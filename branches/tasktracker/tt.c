/*
 * tt.c - Simplified thread information tracker.
 *
 * Copyright (C) 2010-2014  Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
 */

#include "probe.h"
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/binfmts.h>
#include <linux/hash.h>

/* Structure for holding string buffer. */
struct tt_record {
	struct list_head list;
	/*
	 * Pointer to "struct task_struct" for 2.6.28 and earlier,
	 * pointer to "struct cred" for 2.6.29 and later.
	 */
	const void *key;
	struct rcu_head rcu;
	char history[1024 - sizeof(struct list_head)
		     - sizeof(void *) - sizeof(struct rcu_head)];
};

#define TT_RECORD_HASH_BITS 12
#define TT_MAX_RECORD_HASH (1u << TT_RECORD_HASH_BITS)

/* Lock for protecting tt_record_list list. */
static DEFINE_SPINLOCK(tt_record_list_lock);
/* List of "struct tt_record" for "struct cred". */
static struct list_head tt_record_list[TT_MAX_RECORD_HASH];
/* Function pointers originally registered by register_security(). */
static struct security_operations original_security_ops /* = *security_ops; */;

/* Structure for representing YYYY/MM/DD hh/mm/ss. */
struct tt_time {
	u16 year;
	u8 month;
	u8 day;
	u8 hour;
	u8 min;
	u8 sec;
};

/**
 * tt_get_time - Get current time in YYYY/MM/DD hh/mm/ss format.
 *
 * @stamp: Pointer to "struct tt_time".
 *
 * Returns nothing.
 *
 * This function does not handle Y2038 problem.
 */
static void tt_get_time(struct tt_time *stamp)
{
	struct timeval tv;
	static const u16 tt_eom[2][12] = {
		{ 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365 },
		{ 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366 }
	};
	u16 y;
	u8 m;
	bool r;
	time_t time;
	do_gettimeofday(&tv);
	time = tv.tv_sec;
	stamp->sec = time % 60;
	time /= 60;
	stamp->min = time % 60;
	time /= 60;
	stamp->hour = time % 24;
	time /= 24;
	for (y = 1970;; y++) {
		const unsigned short days = (y & 3) ? 365 : 366;
		if (time < days)
			break;
		time -= days;
	}
	r = (y & 3) == 0;
	for (m = 0; m < 11 && time >= tt_eom[r][m]; m++)
		;
	if (m)
		time -= tt_eom[r][m - 1];
	stamp->year = y;
	stamp->month = ++m;
	stamp->day = ++time;
}

/**
 * tt_update_record - Update "struct tt_record" for given credential.
 *
 * @record: Pointer to "struct tt_record". Maybe NULL.
 *
 * Returns nothing.
 */
static void tt_update_record(struct tt_record *record)
{
	char *cp;
	int i;
	struct tt_time stamp;
	if (!record)
		return;
	tt_get_time(&stamp);
	/*
	 * Lockless update because current thread's record is not concurrently
	 * accessible, for "struct cred"->security is not visible from other
	 * threads because this function is called upon only boot up and
	 * successful execve() operation.
	 */
	cp = record->history;
	i = strlen(cp);
	while (i >= sizeof(record->history) - (TASK_COMM_LEN * 4 + 30)) {
		/*
		 * Since this record is not for making security decision,
		 * I don't care by-chance matching "=>" in task's commname.
		 */
		char *cp2 = strstr(cp + 2, "=>");
		if (!cp2)
			return;
		memmove(cp + 1, cp2, strlen(cp2) + 1);
		i = strlen(cp);
	}
	if (!i)
		*cp++ = '"';
	else {
		cp += i - 1;
		*cp++ = '=';
		*cp++ = '>';
	}
	/*
	 * Lockless read because this is current thread and being unexpectedly
	 * modified by other thread is not a fatal problem.
	 */
	for (i = 0; i < TASK_COMM_LEN; i++) {
		const unsigned char c = current->comm[i];
		if (!c)
			break;
		else if (c == '"' || c == '\\' || c < 0x21 || c > 0x7e) {
			*cp++ = '\\';
			*cp++ = (c >> 6) + '0';
			*cp++ = ((c >> 3) & 7)+ '0';
			*cp++ = (c & 7) + '0';
		} else
			*cp++ = c;
	}
	sprintf(cp, "(%04u/%02u/%02u-%02u:%02u:%02u)\"", stamp.year,
		stamp.month, stamp.day, stamp.hour, stamp.min, stamp.sec);
}

/**
 * tt_find_record - Find "struct tt_record" for given credential.
 *
 * @key: Key value.
 *
 * Returns pointer to "struct tt_record" on success, NULL otherwise.
 */
static struct tt_record *tt_find_record(const void *key)
{
	struct tt_record *ptr;
	struct list_head *list = &tt_record_list
		[hash_ptr((void *) key, TT_RECORD_HASH_BITS)];
	rcu_read_lock();
	list_for_each_entry_rcu(ptr, list, list) {
		if (ptr->key != key)
			continue;
		rcu_read_unlock();
		return ptr;
	}
	rcu_read_unlock();
	return NULL;
}

/**
 * tt_add_record - Add "struct tt_record" to list.
 *
 * @ptr: Pointer to "struct tt_record".
 *
 * Returns nothing.
 */
static void tt_add_record(struct tt_record *ptr)
{
	unsigned long flags;
	struct list_head *list = &tt_record_list
		[hash_ptr((void *) ptr->key, TT_RECORD_HASH_BITS)];
	spin_lock_irqsave(&tt_record_list_lock, flags);
	list_add_rcu(&ptr->list, list);
	spin_unlock_irqrestore(&tt_record_list_lock, flags);
}

/**
 * tt_current_record - Get "struct tt_record" for current thread.
 *
 * @key: Key value.
 * @gfp: Memory allocation flags.
 * 
 * Returns pointer to "struct tt_record" for current thread on success, NULL
 * otherwise.
 */
static struct tt_record *tt_current_record(const void *key, gfp_t gfp)
{
	struct tt_record *record = tt_find_record(key);
	if (record)
		return record;
	record = kzalloc(sizeof(*record), gfp);
	if (!record)
		return NULL;
	record->key = key;
	tt_update_record(record);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
	/*
	 * Special handling is needed because "struct cred" might be shared
	 * between multiple threads. We need to allocate history only once for
	 * each "struct cred".
	 */
	{
		unsigned long flags;
		bool duplicated = 0;
		struct tt_record *ptr;
		struct list_head *list = &tt_record_list
			[hash_ptr((void *) key, TT_RECORD_HASH_BITS)];
		spin_lock_irqsave(&tt_record_list_lock, flags);
		rcu_read_lock();
		list_for_each_entry_rcu(ptr, list, list) {
			if (ptr->key != key)
				continue;
			duplicated = 1;
			break;
		}
		rcu_read_unlock();
		if (!duplicated)
			list_add_rcu(&record->list, list);
		spin_unlock_irqrestore(&tt_record_list_lock, flags);
		if (duplicated) {
			kfree(record);
			return ptr;
		}
	}
#else
	tt_add_record(record);
#endif
	return record;
}

/**
 * tt_rcu_free - RCU callback for releasing "struct tt_record".
 *
 * @rcu: Pointer to "struct rcu_head".
 *
 * Returns nothing.
 */
static void tt_rcu_free(struct rcu_head *rcu)
{
	struct tt_record *ptr = container_of(rcu, typeof(*ptr), rcu);
	kfree(ptr);
}

/**
 * tt_del_record - Release "struct tt_record".
 *
 * @ptr: Pointer to "struct tt_record". Maybe NULL.
 *
 * Returns nothing.
 */
static void tt_del_record(struct tt_record *ptr)
{
	unsigned long flags;
	if (!ptr)
		return;
	spin_lock_irqsave(&tt_record_list_lock, flags);
	list_del_rcu(&ptr->list);
	spin_unlock_irqrestore(&tt_record_list_lock, flags);
	call_rcu(&ptr->rcu, tt_rcu_free);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)

/**
 * tt_cred_prepare - Allocate memory for new credentials.
 *
 * @new: Pointer to "struct cred".
 * @old: Pointer to "struct cred".
 * @gfp: Memory allocation flags.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tt_cred_prepare(struct cred *new, const struct cred *old,
			   gfp_t gfp)
{
	int rc;
	struct tt_record *old_record = tt_current_record(old, gfp);
	struct tt_record *new_record = kzalloc(sizeof(*new_record), gfp);
	if (!old_record || !new_record) {
		kfree(new_record);
		return -ENOMEM;
	}
	new_record->key = new;
	strcpy(new_record->history, old_record->history);
	tt_add_record(new_record);
	while (!original_security_ops.cred_prepare);
	rc = original_security_ops.cred_prepare(new, old, gfp);
	if (rc)
		tt_del_record(new_record);
	return rc;
}

/**
 * tt_cred_free - Release memory used by credentials.
 *
 * @cred: Pointer to "struct cred".
 *
 * Returns nothing.
 */
static void tt_cred_free(struct cred *cred)
{
	while (!original_security_ops.cred_free);
	original_security_ops.cred_free(cred);
	tt_del_record(tt_find_record(cred));
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)

/**
 * tt_cred_alloc_blank - Allocate memory for new credentials.
 *
 * @new: Pointer to "struct cred".
 * @gfp: Memory allocation flags.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tt_cred_alloc_blank(struct cred *new, gfp_t gfp)
{
	int rc;
	struct tt_record *record = kzalloc(sizeof(*record), gfp);
	if (!record)
		return -ENOMEM;
	record->key = new;
	tt_add_record(record);
	while (!original_security_ops.cred_alloc_blank);
	rc = original_security_ops.cred_alloc_blank(new, gfp);
	if (rc)
		tt_del_record(record);
	return rc;
}

/**
 * tt_cred_transfer - Transfer "struct tt_record" between credentials.
 *
 * @new: Pointer to "struct cred".
 * @old: Pointer to "struct cred".
 *
 * Returns nothing.
 */
static void tt_cred_transfer(struct cred *new, const struct cred *old)
{
	struct tt_record *new_record;
	struct tt_record *old_record;
	while (!original_security_ops.cred_transfer);
	original_security_ops.cred_transfer(new, old);
	new_record = tt_find_record(new);
	old_record = tt_find_record(old);
	if (new_record && old_record)
		strcpy(new_record->history, old_record->history);
}

#endif

#else

/**
 * tt_task_alloc_security - Allocate memory for new tasks.
 *
 * @p: Pointer to "struct task_struct".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tt_task_alloc_security(struct task_struct *p)
{
	int rc;
	struct tt_record *old = tt_current_record(current, GFP_KERNEL);
	struct tt_record *new = kzalloc(sizeof(*new), GFP_KERNEL);
	if (!old || !new) {
		kfree(new);
		return -ENOMEM;
	}
	new->key = p;
	strcpy(new->history, old->history);
	tt_add_record(new);
	while (!original_security_ops.task_alloc_security);
	rc = original_security_ops.task_alloc_security(p);
	if (rc)
		tt_del_record(new);
	return rc;
}

/**
 * tt_task_free_security - Release memory for "struct task_struct".
 *
 * @p: Pointer to "struct task_struct".
 *
 * Returns nothing.
 */
static void tt_task_free_security(struct task_struct *p)
{
	while (!original_security_ops.task_free_security);
	original_security_ops.task_free_security(p);
	tt_del_record(tt_find_record(p));
}

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)

/**
 * tt_bprm_apply_creds - A hook which is called when do_execve() succeeded.
 *
 * @bprm:   Pointer to "struct linux_binprm".
 * @unsafe: Unsafe flag.
 *
 * Returns nothing.
 */
static void tt_bprm_apply_creds(struct linux_binprm *bprm, int unsafe)
{
	while (!original_security_ops.bprm_apply_creds);
	original_security_ops.bprm_apply_creds(bprm, unsafe);
	tt_update_record(tt_find_record(current));
}

#else

/**
 * tt_bprm_committing_creds - A hook which is called when do_execve() succeeded.
 *
 * @bprm: Pointer to "struct linux_binprm".
 *
 * Returns nothing.
 */
static void tt_bprm_committing_creds(struct linux_binprm *bprm)
{
	while (!original_security_ops.bprm_committing_creds);
	original_security_ops.bprm_committing_creds(bprm);
	tt_update_record(tt_find_record(bprm->cred));
}

#endif

/**
 * tt_task_getsecid - Check whether to audit or not.
 *
 * @p:     Pointer to "struct task_struct".
 * @secid: Pointer to flag.
 */
static void tt_task_getsecid(struct task_struct *p, u32 *secid)
{
	*secid = (p == current);
}

/**
 * tt_secid_to_secctx - Allocate memory used for auditing.
 *
 * @secid:   Bool flag to allocate.
 * @secdata: Pointer to allocate memory.
 * @seclen:  Unused.
 *
 * Returns 0.
 */
static int tt_secid_to_secctx(u32 secid, char **secdata, u32 *seclen)
{
	/*
	 * We don't need to duplicate the string because current thread's
	 * record is updated upon only boot up and successful execve()
	 * operation, even if current thread's record is shared between
	 * multiple threads.
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
	*secdata = tt_find_record(current->real_cred)->history;
#else
	*secdata = tt_find_record(current)->history;
#endif
	return 0;
}

/**
 * tt_update_security_ops - Overwrite original "struct security_operations".
 *
 * @ops: Pointer to "struct security_operations".
 *
 * Returns nothing.
 */
static void __init tt_update_security_ops(struct security_operations *ops)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
	original_security_ops.cred_prepare = ops->cred_prepare;
	original_security_ops.cred_free = ops->cred_free;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	original_security_ops.cred_alloc_blank = ops->cred_alloc_blank;
	original_security_ops.cred_transfer = ops->cred_transfer;
#endif
#else
	original_security_ops.task_alloc_security = ops->task_alloc_security;
	original_security_ops.task_free_security = ops->task_free_security;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
	original_security_ops.bprm_apply_creds = ops->bprm_apply_creds;
#else
	original_security_ops.bprm_committing_creds =
		ops->bprm_committing_creds;
#endif
	smp_mb();
	ops->secid_to_secctx = tt_secid_to_secctx;
	ops->task_getsecid = tt_task_getsecid;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
	ops->cred_prepare = tt_cred_prepare;
	ops->cred_free = tt_cred_free;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	ops->cred_alloc_blank = tt_cred_alloc_blank;
	ops->cred_transfer = tt_cred_transfer;
#endif
#else
	ops->task_alloc_security = tt_task_alloc_security;
	ops->task_free_security = tt_task_free_security;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
	ops->bprm_apply_creds = tt_bprm_apply_creds;
#else
	ops->bprm_committing_creds = tt_bprm_committing_creds;
#endif
}

/**
 * tt_init - Initialize this module.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __init tt_init(void)
{
	int idx;
	struct security_operations *ops = probe_security_ops();
	if (!ops)
		return -EINVAL;
	for (idx = 0; idx < TT_MAX_RECORD_HASH; idx++)
		INIT_LIST_HEAD(&tt_record_list[idx]);
	tt_update_security_ops(ops);
	printk(KERN_INFO "TaskTracker: 0.1   2014/04/15\n");
	return 0;
}

module_init(tt_init);
MODULE_LICENSE("GPL");
