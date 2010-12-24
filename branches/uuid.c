/*
 * uuid.c
 *
 * Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
 *
 * This LSM module isolates processes by comparing session id (which is
 * associated with processes by this module) from LSM hooks which take
 * "struct task_struct *" in their arguments.
 *
 * There are two id named 'id1' and 'id2'.
 * 'id2' cannot be obtained before obtaining 'id1'.
 * Any process is classified as one of three states listed below.
 *
 *   "unrestricted" state holds neither 'id1' nor 'id2'.
 *   "half-restricted" state holds only 'id1'.
 *   "restricted" state holds both 'id1' and 'id2'.
 *
 * Operations (e.g. ptrace()) on objective thread by subjective thread and
 * reopening files via procfs's file descriptors (i.e. /proc/PID/fd/ ) are
 * granted in below rules.
 *
 *           |      Subjective | unrestricted | half restricted | restricted
 * ----------+-----------------+--------------+-----------------+-------------
 * Objective | unrestricted    |  always      | always          | never
 *           | half restricted |  always      | same id1        | same id1
 *           | restricted      |  always      | same id1        | same id1/id2
 *
 * Communication via UNIX domain sockets is granted in below rules.
 * A socket's state is copied from the creator thread's state upon creation.
 *
 *           |           Local | unrestricted | half restricted | restricted
 * ----------+-----------------+--------------+-----------------+-------------
 *    Remote | unrestricted    |  always      | always          | always
 *           | half restricted |  always      | same id1        | same id1
 *           | restricted      |  always      | same id1        | same id1/id2
 *
 * A process is permitted to obtain 'id1' (if not yet obtained one) by
 * opening /proc/uuid1 interface (e.g. doing ": < /proc/uuid1" from bash).
 * If 'id1' was successfully obtained, the process transits from "unrestricted"
 * state to "half restricted" state. Likewise, a process is permitted to obtain
 * 'id2' (if not yet obtained one) by opening /proc/uuid2 interface (e.g. doing
 * ": < /proc/uuid2" from bash). If 'id2' was successfully obtained,
 * the process transits from "half restricted" state to "restricted" state.
 *
 * The 'id1'/'id2' cannot be changed after once obtained and are automatically
 * inherited to child processes created afterward.
 *
 * To compile, put this file on some directory under kernel's source directory
 * (e.g. uuid/ directory) and do "echo 'obj-m := uuid.o' > uuid/Makefile" and
 * do "make -s SUBDIRS=uuid modules modules_install".
 */
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/hash.h>
#include <linux/security.h>
#include <linux/namei.h>
#include <linux/proc_fs.h>
#include <linux/version.h>

#ifndef CONFIG_SECURITY
#error You must choose CONFIG_SECURITY=y for building this module.
#endif
#ifndef CONFIG_KALLSYMS
#error You must choose CONFIG_KALLSYMS=y for building this module.
#endif
#ifndef CONFIG_PROC_FS
#error You must choose CONFIG_PROC_FS=y for building this module.
#endif
#ifndef CONFIG_MODULES
#error You must choose CONFIG_MODULES=y for building this module.
#endif

#ifndef DEFINE_SPINLOCK
#define DEFINE_SPINLOCK(x) spinlock_t x = SPIN_LOCK_UNLOCKED
#endif

#ifndef bool
#define bool _Bool
#endif
#ifndef false
#define false 0
#endif
#ifndef true
#define true 1
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)

/**
 * fatal_signal_pending - Check whether SIGKILL is pending or not.
 *
 * @p: Pointer to "struct task_struct".
 *
 * Returns true if SIGKILL is pending on @p, false otherwise.
 *
 * This is for compatibility with older kernels.
 */
#define fatal_signal_pending(p) (signal_pending(p) &&			\
				 sigismember(&p->pending.signal, SIGKILL))

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 14)

#define gfp_t int

/**
 * kzalloc() - Allocate memory. The memory is set to zero.
 *
 * @size:  Size to allocate.
 * @flags: GFP flags.
 *
 * Returns pointer to allocated memory on success, NULL otherwise.
 *
 * This is for compatibility with older kernels.
 *
 * Since several distributions backported kzalloc(), I define it as a macro
 * rather than an inlined function in order to avoid multiple definition error.
 */
#define kzalloc(size, flags) ({					\
			void *ret = kmalloc((size), (flags));	\
			if (ret)				\
				memset(ret, 0, (size));		\
			ret; })

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 16)
#define mutex semaphore
#define mutex_unlock(mutex) up(mutex)
#define mutex_lock_interruptible(mutex) down_interruptible(mutex)
#define DEFINE_MUTEX(mutexname) DECLARE_MUTEX(mutexname)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)

#define cred task_struct
#define current_cred() (current)
#define __task_cred(task) (task)

#endif

struct uuid_security {
	struct list_head list;
	/* "struct cred" or "struct task_struct" or "struct inode" */
	const void *owner;
	u32 id1;
	u32 id2;
	struct rcu_head rcu;
};

/* Function pointers originally registered by register_security(). */
static struct security_operations original_security_ops /* = *security_ops; */;

#define UUID_SECURITY_HASH_BITS 12
#define UUID_MAX_SECURITY_HASH (1u << UUID_SECURITY_HASH_BITS)
/* List of "struct uuid_security". */
static struct list_head uuid_security_list[UUID_MAX_SECURITY_HASH];
static DEFINE_SPINLOCK(uuid_security_list_lock);

/**
 * uuid_find_security - Find "struct uuid_security" for given object.
 *
 * @owner: Pointer to "struct cred" or "struct task_struct" or "struct inode".
 *
 * Returns pointer to "struct uuid_security" on success, NULL otherwise.
 */
static struct uuid_security *uuid_find_security(const void *owner)
{
	struct uuid_security *ptr;
	struct list_head *list = &uuid_security_list
		[hash_ptr((void *) owner, UUID_SECURITY_HASH_BITS)];
	rcu_read_lock();
	list_for_each_entry_rcu(ptr, list, list) {
		if (ptr->owner != owner)
			continue;
		rcu_read_unlock();
		return ptr;
	}
	rcu_read_unlock();
	return NULL;
}

/**
 * uuid_add_security - Add "struct uuid_security" to list.
 *
 * @ptr: Pointer to "struct uuid_security".
 *
 * Returns nothing.
 */
static void uuid_add_security(struct uuid_security *ptr)
{
	unsigned long flags;
	struct list_head *list = &uuid_security_list
		[hash_ptr((void *) ptr->owner, UUID_SECURITY_HASH_BITS)];
	spin_lock_irqsave(&uuid_security_list_lock, flags);
	list_add_rcu(&ptr->list, list);
	spin_unlock_irqrestore(&uuid_security_list_lock, flags);
}

/**
 * uuid_copy_security - Allocate memory for new credentials.
 *
 * @new: Pointer to "struct cred" or "struct task_struct" or "struct inode".
 * @old: Pointer to "struct cred" or "struct task_struct" or "struct inode".
 * @gfp: Memory allocation flags.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int uuid_copy_security(const void *new, const void *old, gfp_t gfp)
{
	struct uuid_security *old_security = uuid_find_security(old);
	struct uuid_security *new_security;
	if (!old_security)
		return 0;
	new_security = kzalloc(sizeof(*new_security), gfp);
	if (!new_security)
		return -ENOMEM;
	new_security->id1 = old_security->id1;
	new_security->id2 = old_security->id2;
	new_security->owner = new;
	uuid_add_security(new_security);
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)

/**
 * uuid_rcu_free - RCU callback for releasing "struct uuid_security".
 *
 * @rcu: Pointer to "struct rcu_head".
 *
 * Returns nothing.
 */
static void uuid_rcu_free(struct rcu_head *rcu)
{
	struct uuid_security *ptr = container_of(rcu, typeof(*ptr), rcu);
	kfree(ptr);
}

#else

/**
 * uuid_rcu_free - RCU callback for releasing "struct uuid_security".
 *
 * @arg: Pointer to "void".
 *
 * Returns nothing.
 */
static void uuid_rcu_free(void *arg)
{
	kfree(arg);
}

#endif

/**
 * uuid_del_security - Release "struct uuid_security".
 *
 * @ptr: Pointer to "struct uuid_security".
 *
 * Returns nothing.
 */
static void uuid_del_security(struct uuid_security *ptr)
{
	unsigned long flags;
	if (!ptr)
		return;
	spin_lock_irqsave(&uuid_security_list_lock, flags);
	list_del_rcu(&ptr->list);
	spin_unlock_irqrestore(&uuid_security_list_lock, flags);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)
	call_rcu(&ptr->rcu, uuid_rcu_free);
#else
	call_rcu(&ptr->rcu, uuid_rcu_free, ptr);
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)

/**
 * uuid_cred_prepare - Allocate memory for new credentials.
 *
 * @new: Pointer to "struct cred".
 * @old: Pointer to "struct cred".
 * @gfp: Memory allocation flags.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int uuid_cred_prepare(struct cred *new, const struct cred *old,
			     gfp_t gfp)
{
	int rc = uuid_copy_security(new, old, gfp);
	if (rc)
		return rc;
	while (!original_security_ops.cred_prepare);
	rc = original_security_ops.cred_prepare(new, old, gfp);
	if (rc)
		uuid_del_security(uuid_find_security(new));
	return rc;
}

/**
 * uuid_cred_free - Release memory used by credentials.
 *
 * @cred: Pointer to "struct cred".
 *
 * Returns nothing.
 */
static void uuid_cred_free(struct cred *cred)
{
	while (!original_security_ops.cred_free);
	original_security_ops.cred_free(cred);
	uuid_del_security(uuid_find_security(cred));
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)

/**
 * uuid_alloc_security - Allocate memory for new credentials.
 *
 * @cred: Pointer to "struct cred".
 * @gfp:  Memory allocation flags.
 *
 * Returns pointer to "struct uuid_security" on success, NULL otherwise.
 */
static struct uuid_security *uuid_alloc_security(const struct cred *cred,
						 gfp_t gfp)
{
	struct uuid_security *new_security = kzalloc(sizeof(*new_security),
						     gfp);
	if (!new_security)
		return NULL;
	new_security->owner = cred;
	uuid_add_security(new_security);
	return new_security;
}

/**
 * uuid_cred_alloc_blank - Allocate memory for new credentials.
 *
 * @new: Pointer to "struct cred".
 * @gfp: Memory allocation flags.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int uuid_cred_alloc_blank(struct cred *new, gfp_t gfp)
{
	struct uuid_security *ptr = uuid_alloc_security(new, gfp);
	int rc;
	if (!ptr)
		return -ENOMEM;
	while (!original_security_ops.cred_alloc_blank);
	rc = original_security_ops.cred_alloc_blank(new, gfp);
	if (rc)
		uuid_del_security(ptr);
	return rc;
}

/**
 * uuid_cred_transfer - Transfer "struct uuid_security" between credentials.
 *
 * @new: Pointer to "struct cred".
 * @old: Pointer to "struct cred".
 *
 * Returns nothing.
 */
static void uuid_cred_transfer(struct cred *new, const struct cred *old)
{
	struct uuid_security *new_security;
	struct uuid_security *old_security;
	while (!original_security_ops.cred_transfer);
	original_security_ops.cred_transfer(new, old);
	new_security = uuid_find_security(new);
	old_security = uuid_find_security(old);
	if (!new_security || !old_security)
		return;
	new_security->id1 = old_security->id1;
	new_security->id2 = old_security->id2;
}

#endif

#else

/**
 * uuid_task_alloc_security - Allocate memory for new tasks.
 *
 * @p: Pointer to "struct task_struct".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int uuid_task_alloc_security(struct task_struct *p)
{
	int rc = uuid_copy_security(p, current, GFP_KERNEL);
	if (rc)
		return rc;
	while (!original_security_ops.task_alloc_security);
	rc = original_security_ops.task_alloc_security(p);
	if (rc)
		uuid_del_security(uuid_find_security(p));
	return rc;
}

/**
 * uuid_task_free_security - Release memory for "struct task_struct".
 *
 * @p: Pointer to "struct task_struct".
 *
 * Returns nothing.
 */
static void uuid_task_free_security(struct task_struct *p)
{
	while (!original_security_ops.task_free_security);
	original_security_ops.task_free_security(p);
	uuid_del_security(uuid_find_security(p));
}

#endif

static bool uuid_check_task(struct task_struct *task, const char *func)
{
	struct uuid_security *uuid_task;
	struct uuid_security *uuid_current;
	int ret = 0;
	if (task == current)
		return 0;
	rcu_read_lock();
	uuid_current = uuid_find_security(current_cred());
	if (!uuid_current)
		goto ok;
	uuid_task = uuid_find_security(__task_cred(task));
	if (!uuid_current->id2) {
		if (!uuid_task)
			goto ok;
		if (uuid_task->id1 == uuid_current->id1)
			goto ok;
	} else {
		if (uuid_task && uuid_task->id1 == uuid_current->id1 &&
		    (!uuid_task->id2 || uuid_task->id2 == uuid_current->id2))
			goto ok;
	}
        if (uuid_task)
                printk(KERN_INFO "Prevented task(%u,%u) ('%s',pid=%u) from "
		       "accessing task(%u,%u) ('%s',pid=%u) at %s\n",
		       uuid_current->id1, uuid_current->id2, current->comm,
		       current->pid, uuid_task->id1, uuid_task->id2,
		       task->comm, task->pid, func);
	else
                printk(KERN_INFO "Prevented task(%u,%u) ('%s',pid=%u) from "
		       "accessing task ('%s',pid=%u) at %s\n",
		       uuid_current->id1, uuid_current->id2, current->comm,
		       current->pid, task->comm, task->pid, func);
	ret = -EPERM;
ok:
	rcu_read_unlock();
	return ret;
}

#ifdef CONFIG_SECURITY_NETWORK

#include <net/sock.h>

static int uuid_check_socket(struct socket *sock, const char *func)
{
	struct uuid_security *uuid_task;
	struct uuid_security *uuid_current;
	int ret = 0;
	rcu_read_lock();
	uuid_current = uuid_find_security(current_cred());
	if (!uuid_current)
		goto ok;
	uuid_task = uuid_find_security(SOCK_INODE(sock));
	if (!uuid_task)
		goto ok;
	if (uuid_task->id1 == uuid_current->id1 &&
	    (!uuid_task->id2 || !uuid_current->id2 ||
	     uuid_task->id2 == uuid_current->id2))
		goto ok;
	printk(KERN_INFO "Prevented task(%u,%u) ('%s',pid=%u) from accessing "
	       "socket(%u,%u) at %s\n", uuid_current->id1, uuid_current->id2,
	       current->comm, current->pid, uuid_task->id1, uuid_task->id2,
	       func);
	ret = -EPERM;
ok:
	rcu_read_unlock();
	return ret;
}

#endif

static int uuid_check_pipe(struct inode *inode, const char *func)
{
	struct uuid_security *uuid_task;
	struct uuid_security *uuid_current;
	int ret = 0;
	if (!S_ISFIFO(inode->i_mode))
		return 0;
	rcu_read_lock();
	uuid_current = uuid_find_security(current_cred());
	if (!uuid_current)
		goto ok;
	uuid_task = uuid_find_security(inode);
	if (!uuid_task)
		goto ok;
	if (uuid_task->id1 == uuid_current->id1 &&
	    (!uuid_task->id2 || !uuid_current->id2 ||
	     uuid_task->id2 == uuid_current->id2))
		goto ok;
	printk(KERN_INFO "Prevented task(%u,%u) ('%s',pid=%u) from accessing "
	       "pipe(%u,%u) at %s\n", uuid_current->id1, uuid_current->id2,
	       current->comm, current->pid, uuid_task->id1, uuid_task->id2,
	       func);
	ret = -EPERM;
ok:
	rcu_read_unlock();
	return ret;
}



#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)

static int uuid_ptrace_access_check(struct task_struct *child,
				    unsigned int mode)
{
	if (uuid_check_task(child, __func__))
		return -EPERM;
	while (!original_security_ops.ptrace_access_check);
	return original_security_ops.ptrace_access_check(child, mode);
}

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)

static int uuid_ptrace_may_access(struct task_struct *child, unsigned int mode)
{
	if (uuid_check_task(child, __func__))
		return -EPERM;
	while (!original_security_ops.ptrace_may_access);
	return original_security_ops.ptrace_may_access(child, mode);
}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)

static int uuid_ptrace_traceme(struct task_struct *parent)
{
	if (uuid_check_task(parent, __func__))
		return -EPERM;
	while (!original_security_ops.ptrace_traceme);
	return original_security_ops.ptrace_traceme(parent);
}

#else

static inline int uuid_ptrace(struct task_struct *parent,
			      struct task_struct *child)
{
	if (uuid_check_task(parent, __func__))
		return -EPERM;
	if (uuid_check_task(child, __func__))
		return -EPERM;
	while (!original_security_ops.ptrace);
	return original_security_ops.ptrace(parent, child);
}

#endif

static int uuid_capget(struct task_struct *target, kernel_cap_t *effective,
		       kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
	if (uuid_check_task(target, __func__))
		return -EPERM;
	while (!original_security_ops.capget);
	return original_security_ops.capget(target, effective, inheritable,
					    permitted);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)

static int uuid_capable(struct task_struct *tsk, const struct cred *cred,
			int cap, int audit)
{
	if (uuid_check_task(tsk, __func__))
		return -EPERM;
	while (!original_security_ops.capable);
	return original_security_ops.capable(tsk, cred, cap, audit);
}

#else

static int uuid_capset_check(struct task_struct *target,
			     kernel_cap_t *effective,
			     kernel_cap_t *inheritable,
			     kernel_cap_t *permitted)
{
	if (uuid_check_task(target, __func__))
		return -EPERM;
	while (!original_security_ops.capset_check);
	return original_security_ops.capset_check(target, effective,
						  inheritable, permitted);
}

static int uuid_capable(struct task_struct *tsk, int cap)
{
	if (uuid_check_task(tsk, __func__))
		return -EPERM;
	while (!original_security_ops.capable);
	return original_security_ops.capable(tsk, cap);
}

#endif

/*
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)

static int uuid_file_send_sigiotask(struct task_struct *tsk,
				    struct fown_struct *fown, int sig)
{
	if (uuid_check_task(tsk, __func__))
		return -EPERM;
	while (!original_security_ops.file_send_sigiotask);
	return original_security_ops.file_send_sigiotask(tsk, fown, sig);
}

#else

static int uuid_file_send_sigiotask(struct task_struct *tsk,
				    struct fown_struct *fown, int sig,
				    int reason)
{
	if (uuid_check_task(tsk, __func__))
		return -EPERM;
	while (!original_security_ops.file_send_sigiotask);
	return original_security_ops.file_send_sigiotask(tsk, fown, sig,
							 reason);
}

#endif
*/

static int uuid_task_setpgid(struct task_struct *p, pid_t pgid)
{
	if (uuid_check_task(p, __func__))
		return -EPERM;
	while (!original_security_ops.task_setpgid);
	return original_security_ops.task_setpgid(p, pgid);
}

static int uuid_task_getpgid(struct task_struct *p)
{
	if (uuid_check_task(p, __func__))
		return -EPERM;
	while (!original_security_ops.task_getpgid);
	return original_security_ops.task_getpgid(p);
}

static int uuid_task_getsid(struct task_struct *p)
{
	if (uuid_check_task(p, __func__))
		return -EPERM;
	while (!original_security_ops.task_getsid);
	return original_security_ops.task_getsid(p);
}

static int uuid_task_setnice(struct task_struct *p, int nice)
{
	if (uuid_check_task(p, __func__))
		return -EPERM;
	while (!original_security_ops.task_setnice);
	return original_security_ops.task_setnice(p, nice);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)

static int uuid_task_setioprio(struct task_struct *p, int ioprio)
{
	if (uuid_check_task(p, __func__))
		return -EPERM;
	while (!original_security_ops.task_setioprio);
	return original_security_ops.task_setioprio(p, ioprio);
}

static int uuid_task_getioprio(struct task_struct *p)
{
	if (uuid_check_task(p, __func__))
		return -EPERM;
	while (!original_security_ops.task_getioprio);
	return original_security_ops.task_getioprio(p);
}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)

static int uuid_task_setrlimit(struct task_struct *p, unsigned int resource,
			       struct rlimit *new_rlim)
{
	if (uuid_check_task(p, __func__))
		return -EPERM;
	while (!original_security_ops.task_setrlimit);
	return original_security_ops.task_setrlimit(p, resource, new_rlim);
}

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 37)

static int uuid_task_setscheduler(struct task_struct *p, int policy,
				  struct sched_param *lp)
{
	if (uuid_check_task(p, __func__))
		return -EPERM;
	while (!original_security_ops.task_setscheduler);
	return original_security_ops.task_setscheduler(p, policy, lp);
}

#else

static int uuid_task_setscheduler(struct task_struct *p)
{
	if (uuid_check_task(p, __func__))
		return -EPERM;
	while (!original_security_ops.task_setscheduler);
	return original_security_ops.task_setscheduler(p);
}

#endif

static int uuid_task_getscheduler(struct task_struct *p)
{
	if (uuid_check_task(p, __func__))
		return -EPERM;
	while (!original_security_ops.task_getscheduler);
	return original_security_ops.task_getscheduler(p);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)

static int uuid_task_movememory(struct task_struct *p)
{
	if (uuid_check_task(p, __func__))
		return -EPERM;
	while (!original_security_ops.task_movememory);
	return original_security_ops.task_movememory(p);
}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)

static int uuid_task_kill(struct task_struct *p, struct siginfo *info, int sig,
			  u32 secid)
{
	if (uuid_check_task(p, __func__))
		return -EPERM;
	while (!original_security_ops.task_kill);
	return original_security_ops.task_kill(p, info, sig, secid);
}

#else

static int uuid_task_kill(struct task_struct *p, struct siginfo *info, int sig)
{
	if (uuid_check_task(p, __func__))
		return -EPERM;
	while (!original_security_ops.task_kill);
	return original_security_ops.task_kill(p, info, sig);
}

#endif

static int uuid_task_wait(struct task_struct *p)
{
	if (uuid_check_task(p, __func__))
		return -EPERM;
	while (!original_security_ops.task_wait);
	return original_security_ops.task_wait(p);
}

static int uuid_msg_queue_msgrcv(struct msg_queue *msq, struct msg_msg *msg,
				 struct task_struct *target, long type,
				 int mode)
{
	if (uuid_check_task(target, __func__))
		return -EPERM;
	while (!original_security_ops.msg_queue_msgrcv);
	return original_security_ops.msg_queue_msgrcv(msq, msg, target, type,
						      mode);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 21)

static int uuid_getprocattr(struct task_struct *p, char *name, char **value)
{
	if (uuid_check_task(p, __func__))
		return -EPERM;
	while (!original_security_ops.getprocattr);
	return original_security_ops.getprocattr(p, name, value);
}

#else

static int uuid_getprocattr(struct task_struct *p, char *name, void *value,
			    size_t size)
{
	if (uuid_check_task(p, __func__))
		return -EPERM;
	while (!original_security_ops.getprocattr);
	return original_security_ops.getprocattr(p, name, value, size);
}

#endif

static int uuid_setprocattr(struct task_struct *p, char *name, void *value,
			    size_t size)
{
	if (uuid_check_task(p, __func__))
		return -EPERM;
	while (!original_security_ops.setprocattr);
	return original_security_ops.setprocattr(p, name, value, size);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 15) && LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29) && defined(CONFIG_KEYS)

static int uuid_key_permission(key_ref_t key_ref, struct task_struct *context,
			       key_perm_t perm)
{
	if (uuid_check_task(context, __func__))
		return -EPERM;
	while (!original_security_ops.key_permission);
	return original_security_ops.key_permission(key_ref, context, perm);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)

static int uuid_key_alloc(struct key *key, struct task_struct *tsk,
			  unsigned long flags)
{
	if (uuid_check_task(tsk, __func__))
		return -EPERM;
	while (!original_security_ops.key_alloc);
	return original_security_ops.key_alloc(key, tsk, flags);
}

#endif
#endif

/*

static const char *uuid_task_type(void)
{
	struct uuid_security *uuid;
	rcu_read_lock();
	uuid = uuid_find_security(current_cred());
	rcu_read_unlock();
	if (uuid && uuid->id2)
		return "restricted";
	else if (uuid)
		return "half-restricted";
	else
		return "unrestricted";
}

static struct uuid_security *uuid_task_restricted(void)
{
	struct uuid_security *uuid;
	rcu_read_lock();
	uuid = uuid_find_security(current_cred());
	rcu_read_unlock();
	return uuid;
}
*/

static int uuid_inode_alloc_security(struct inode *inode)
{
	int rc;
	if (S_ISSOCK(inode->i_mode) || S_ISFIFO(inode->i_mode)) {
		struct uuid_security *uuid_current;
		rc = uuid_copy_security(inode, current_cred(), GFP_KERNEL);
		if (rc)
			return rc;
		uuid_current = uuid_find_security(current_cred());
		if (uuid_current) {
			struct uuid_security *uuid_task =
				uuid_find_security(inode);
			if (uuid_task)
				printk(KERN_INFO "Allocated %s(%u,%u) by "
				       "task(%u,%u) ('%s',pid=%u) (%p)\n",
				       S_ISSOCK(inode->i_mode) ? "socket" :
				       "pipe", uuid_task->id1, uuid_task->id2,
				       uuid_current->id1, uuid_current->id2,
				       current->comm, current->pid, inode);
			else
				dump_stack();
		}
	}
	while (!original_security_ops.inode_alloc_security);
	rc = original_security_ops.inode_alloc_security(inode);
	if (rc && (S_ISSOCK(inode->i_mode) || S_ISFIFO(inode->i_mode)))
		uuid_del_security(uuid_find_security(inode));
	return rc;
}

static void uuid_inode_free_security(struct inode *inode)
{
	while (!original_security_ops.inode_free_security);
	original_security_ops.inode_free_security(inode);
	if (S_ISSOCK(inode->i_mode) || S_ISFIFO(inode->i_mode))
		uuid_del_security(uuid_find_security(inode));
}

#ifdef CONFIG_SECURITY_NETWORK

static int uuid_unix_stream_connect(struct socket *sock, struct socket *other,
				    struct sock *newsk)
{
	int rc = uuid_check_socket(other, __func__);
	if (rc)
		return rc;
	while (!original_security_ops.unix_stream_connect);
	return original_security_ops.unix_stream_connect(sock, other, newsk);
}

static int uuid_unix_may_send(struct socket *sock, struct socket *other)
{
	int rc = uuid_check_socket(other, __func__);
	if (rc)
		return rc;
	while (!original_security_ops.unix_may_send);
	return original_security_ops.unix_may_send(sock, other);
}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)

/**
 * uuid_dentry_open - Check permission for open().
 *
 * @f:    Pointer to "struct file".
 * @cred: Pointer to "struct cred".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int uuid_dentry_open(struct file *f, const struct cred *cred)
{
	int rc = uuid_check_pipe(f->f_dentry->d_inode, __func__);
	if (rc)
		return rc;
	while (!original_security_ops.dentry_open);
	return original_security_ops.dentry_open(f, cred);
}

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)

/**
 * uuid_dentry_open - Check permission for open().
 *
 * @f: Pointer to "struct file".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int uuid_dentry_open(struct file *f)
{
	int rc = uuid_check_pipe(f->f_dentry->d_inode, __func__);
	if (rc)
		return rc;
	while (!original_security_ops.dentry_open);
	return original_security_ops.dentry_open(f);
}

#else

/**
 * uuid_inode_permission - Check permission for open().
 *
 * @inode: Pointer to "struct inode".
 * @mask:  Open mode.
 * @nd:    Pointer to "struct nameidata".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Note that this hook is called from permission(), and may not be called for
 * open(). Maybe it is better to use security_file_permission().
 */
static int uuid_inode_permission(struct inode *inode, int mask,
				 struct nameidata *nd)
{
	int rc = uuid_check_pipe(inode, __func__);
	if (rc)
		return rc;
	while (!original_security_ops.inode_permission);
	return original_security_ops.inode_permission(inode, mask, nd);
}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)

#include <linux/mount.h>
#include <linux/fs_struct.h>

/**
 * uuid_kernel_read - Wrapper for kernel_read().
 *
 * @file:   Pointer to "struct file".
 * @offset: Starting position.
 * @addr:   Buffer.
 * @count:  Size of @addr.
 *
 * Returns return value from kernel_read().
 */
static int __init uuid_kernel_read(struct file *file, unsigned long offset,
				   char *addr, unsigned long count)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 8)
	/*
	 * I can't use kernel_read() because seq_read() returns -EPIPE
	 * if &pos != &file->f_pos .
	 */
	mm_segment_t old_fs;
	unsigned long pos = file->f_pos;
	int result;
	file->f_pos = offset;
	old_fs = get_fs();
	set_fs(get_ds());
	result = vfs_read(file, (void __user *)addr, count, &file->f_pos);
	set_fs(old_fs);
	file->f_pos = pos;
	return result;
#else
	return kernel_read(file, offset, addr, count);
#endif
}

/**
 * uuid_find_symbol - Find function's address from /proc/kallsyms .
 *
 * @keyline: Function to find.
 *
 * Returns address of specified function on success, NULL otherwise.
 */
static void *__init uuid_find_symbol(const char *keyline)
{
	struct file *file = NULL;
	char *buf;
	unsigned long entry = 0;
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)
		struct file_system_type *fstype = get_fs_type("proc");
		struct vfsmount *mnt = vfs_kern_mount(fstype, 0, "proc", NULL);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)
		struct file_system_type *fstype = NULL;
		struct vfsmount *mnt = do_kern_mount("proc", 0, "proc", NULL);
#else
		struct file_system_type *fstype = get_fs_type("proc");
		struct vfsmount *mnt = kern_mount(fstype);
#endif
		struct dentry *root;
		struct dentry *dentry;
		/*
		 * We embed put_filesystem() here because it is not exported.
		 */
		if (fstype)
			module_put(fstype->owner);
		if (IS_ERR(mnt))
			goto out;
		root = dget(mnt->mnt_root);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 16)
		mutex_lock(&root->d_inode->i_mutex);
		dentry = lookup_one_len("kallsyms", root, 8);
		mutex_unlock(&root->d_inode->i_mutex);
#else
		down(&root->d_inode->i_sem);
		dentry = lookup_one_len("kallsyms", root, 8);
		up(&root->d_inode->i_sem);
#endif
		dput(root);
		if (IS_ERR(dentry))
			mntput(mnt);
		else
			file = dentry_open(dentry, mnt, O_RDONLY
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
					   , current_cred()
#endif
					   );
	}
	if (IS_ERR(file) || !file)
		goto out;
	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (buf) {
		int len;
		int offset = 0;
		while ((len = uuid_kernel_read(file, offset, buf,
					       PAGE_SIZE - 1)) > 0) {
			char *cp;
			buf[len] = '\0';
			cp = strrchr(buf, '\n');
			if (!cp)
				break;
			*(cp + 1) = '\0';
			offset += strlen(buf);
			cp = strstr(buf, keyline);
			if (!cp)
				continue;
			*cp = '\0';
			while (cp > buf && *(cp - 1) != '\n')
				cp--;
			entry = simple_strtoul(cp, NULL, 16);
			break;
		}
		kfree(buf);
	}
	filp_close(file, NULL);
out:
	return (void *) entry;
}

/* Never mark this variable as __initdata . */
static struct security_operations *uuid_security_ops;

/**
 * lsm_addr_calculator - Dummy function which does identical to security_file_alloc() in security/security.c.
 *
 * @file: Pointer to "struct file".
 *
 * Returns return value fromfrom security_file_alloc().
 *
 * Never mark this function as __init in order to make sure that compiler
 * generates identical code for security_file_alloc() and this function.
 */
static int lsm_addr_calculator(struct file *file)
{
	return uuid_security_ops->file_alloc_security(file);
}

/**
 * uuid_find_variable - Find variable's address using dummy.
 *
 * @function: Pointer to dummy function's entry point.
 * @addr:     Address of the variable which is used within @function.
 * @symbol:   Name of symbol to resolve.
 *
 * This trick depends on below assumptions.
 *
 * (1) @addr is found within 128 bytes from @function, even if additional
 *     code (e.g. debug symbols) is added.
 * (2) It is safe to read 128 bytes from @function.
 * (3) @addr != Byte code except @addr.
 */
static void * __init uuid_find_variable(void *function, unsigned long addr,
					const char *symbol)
{
	int i;
	u8 *base;
	u8 *cp = function;
	if (*symbol == ' ')
		base = uuid_find_symbol(symbol);
	else
		base = __symbol_get(symbol);
	if (!base)
		return NULL;
	/* First, assume absolute adressing mode is used. */
	for (i = 0; i < 128; i++) {
		if (*(unsigned long *) cp == addr)
			return base + i;
		cp++;
	}
	/* Next, assume PC-relative addressing mode is used. */
	cp = function;
	for (i = 0; i < 128; i++) {
		if ((unsigned long) (cp + sizeof(int) + *(int *) cp) == addr) {
			static void *cp4ret;
			cp = base + i;
			cp += sizeof(int) + *(int *) cp;
			cp4ret = cp;
			return &cp4ret;
		}
		cp++;
	}
	cp = function;
	for (i = 0; i < 128; i++) {
		if ((unsigned long) (long) (*(int *) cp) == addr) {
			static void *cp4ret;
			cp = base + i;
			cp = (void *) (long) (*(int *) cp);
			cp4ret = cp;
			return &cp4ret;
		}
		cp++;
	}
	return NULL;
}

#endif

/**
 * uuid_find_find_security_ops - Find address of "struct security_operations *security_ops".
 *
 * Returns pointer to "struct security_operations" on success, NULL otherwise.
 */
static struct security_operations * __init uuid_find_security_ops(void)
{
	struct security_operations **ptr;
	struct security_operations *ops;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
	void *cp;
	/* Guess "struct security_operations *security_ops;". */
	cp = uuid_find_variable(lsm_addr_calculator, (unsigned long)
				&uuid_security_ops, " security_file_alloc\n");
	if (!cp) {
		printk(KERN_ERR "Can't resolve security_file_alloc().\n");
		goto out;
	}
	/* This should be "struct security_operations *security_ops;". */
	ptr = *(struct security_operations ***) cp;
#else
	/* This is "struct security_operations *security_ops;". */
	ptr = (struct security_operations **) __symbol_get("security_ops");
#endif
	if (!ptr) {
		printk(KERN_ERR "Can't resolve security_ops structure.\n");
		goto out;
	}
	printk(KERN_INFO "&security_ops=%p\n", ptr);
	ops = *ptr;
	if (!ops) {
		printk(KERN_ERR "No security_operations registered.\n");
		goto out;
	}
	return ops;
out:
	return NULL;
}

/*
 * Why not to copy all operations by "original_security_ops = *ops" ?
 * Because copying byte array is not atomic. Reader checks
 * original_security_ops.op != NULL before doing original_security_ops.op().
 * Thus, modifying original_security_ops.op has to be atomic.
 */
#define swap_security_ops(op)						\
	original_security_ops.op = ops->op; smp_wmb(); ops->op = uuid_##op;

/**
 * uuid_update_security_ops - Overwrite original "struct security_operations".
 *
 * @ops: Pointer to "struct security_operations".
 *
 * Returns nothing.
 */
static void __init uuid_update_security_ops(struct security_operations *ops)
{
	/* Security context allocator. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
	swap_security_ops(cred_prepare);
	swap_security_ops(cred_free);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	swap_security_ops(cred_alloc_blank);
	swap_security_ops(cred_transfer);
#endif
#else
	swap_security_ops(task_alloc_security);
	swap_security_ops(task_free_security);
#endif
	/* Various permission checker. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	swap_security_ops(ptrace_traceme);
	swap_security_ops(ptrace_access_check);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
	swap_security_ops(ptrace_traceme);
	swap_security_ops(ptrace_may_access);
#else
	swap_security_ops(ptrace);
#endif
	swap_security_ops(capget);
	swap_security_ops(capable);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
	swap_security_ops(capset_check);
#endif
	/* swap_security_ops(file_send_sigiotask); */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 15) && LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29) && defined(CONFIG_KEYS)
	swap_security_ops(key_permission);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)
	swap_security_ops(key_alloc);
#endif
#endif
	swap_security_ops(task_setpgid);
	swap_security_ops(task_getpgid);
	swap_security_ops(task_getsid);
	swap_security_ops(task_setnice);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)
	swap_security_ops(task_setioprio);
	swap_security_ops(task_getioprio);
	swap_security_ops(task_movememory);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
	swap_security_ops(task_setrlimit);
#endif
	swap_security_ops(task_setscheduler);
	swap_security_ops(task_getscheduler);
	swap_security_ops(task_kill);
	swap_security_ops(task_wait);
	swap_security_ops(msg_queue_msgrcv);
	swap_security_ops(getprocattr);
	swap_security_ops(setprocattr);
	swap_security_ops(inode_alloc_security);
	swap_security_ops(inode_free_security);
#ifdef CONFIG_SECURITY_NETWORK
	swap_security_ops(unix_may_send);
	swap_security_ops(unix_stream_connect);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
	swap_security_ops(dentry_open);
#else
	swap_security_ops(inode_permission);
#endif
}

#undef swap_security_ops

/**
 * uuid_open - open() for /proc/uuid1 and /proc/uuid2 interface.
 *
 * @inode: Pointer to "struct inode".
 * @file:  Pointer to "struct file".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int uuid_open(struct inode *inode, struct file *file)
{
	static DEFINE_MUTEX(mutex);
	const bool is_id1 = (bool) PDE(inode)->data;
	u32 loop;
	int rc = -ENOMEM;
	const struct cred *cred = current_cred();
	struct uuid_security *ptr;
	struct uuid_security *uuid = is_id1 ?
		kzalloc(sizeof(*uuid), GFP_KERNEL) : NULL;
	if (mutex_lock_interruptible(&mutex)) {
		kfree(uuid);
		return -EINTR;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
	/*
	 * This function must not be called between override_creds() and
	 * revert_creds() because we loose "struct uuid_security" as soon as
	 * the caller calls revert_creds().
	 */
	if (cred != current->real_cred)
		goto out;
#endif
	ptr = uuid_find_security(cred);
	if (is_id1) {
		/*
		 * Reject if "struct uuid_security" was already associated with
		 * "struct cred".
		 */
		if (ptr) {
			rc = -EEXIST;
			goto out;
		}
		if (!uuid)
			goto out;
		uuid->owner = cred;
	} else {
		/*
		 * Reject if "struct uuid_security" was not yet associated with
		 * "struct cred".
		 */
		if (!ptr) {
			rc = -EINVAL;
			goto out;
		}
		/* Reject if id2 was already assigned. */
		if (ptr->id2) {
			rc = -EEXIST;
			goto out;
		}
		uuid = ptr;
	}
	/* Find an unused id. */
	for (loop = 1; loop; loop++) {
		static u32 id[2];
		int idx;
		/* id == 0 is reserved. */
		while (!++id[!is_id1]);
		if (is_id1)
			uuid->id1 = id[0];
		rcu_read_lock();
		for (idx = 0; idx < UUID_MAX_SECURITY_HASH; idx++) {
			struct list_head *list = &uuid_security_list[idx];
			list_for_each_entry_rcu(ptr, list, list) {
				if (ptr->id1 != uuid->id1)
					continue;
				if (!is_id1 && ptr->id2 != id[1])
					continue;
				goto in_use;
			}
		}
in_use:
		rcu_read_unlock();
		if (idx < UUID_MAX_SECURITY_HASH) {
			cond_resched();
			if (fatal_signal_pending(current))
				break;
			continue;
		}
		if (is_id1)
			/*
			 * Associate "struct uuid_security" with "struct cred"
			 * with id2 == 0.
			 */
			uuid_add_security(uuid);
		else
			/* Assign id2 in "struct uuid_security". */
			uuid->id2 = id[1];
		printk(KERN_INFO "Allocated task(%u,%u) ('%s',pid=%u)\n",
		       uuid->id1, uuid->id2, current->comm, current->pid);
		rc = 0;
		uuid = NULL;
		break;
	}
	/* No unused session id was found. */
out:
	mutex_unlock(&mutex);
	if (is_id1)
		kfree(uuid);
	return rc;
}

/* Operations for /proc/uuid1 and /proc/uuid2 interface. */
static
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 17)
const
#endif
struct file_operations uuid_operations = {
	.open    = uuid_open,
};

/**
 * uuid_init - Initialize this module.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __init uuid_init(void)
{
	int idx;
	struct security_operations *ops = uuid_find_security_ops();
	struct proc_dir_entry *entry;
	if (!ops)
		return -EINVAL;
	for (idx = 0; idx < UUID_MAX_SECURITY_HASH; idx++)
		INIT_LIST_HEAD(&uuid_security_list[idx]);
	entry = create_proc_entry("uuid1", 0666, NULL);
	if (!entry)
		return -EINVAL;
	entry->proc_fops = &uuid_operations;
	entry->data = (void *) 1;
	entry = create_proc_entry("uuid2", 0666, NULL);
	if (!entry) {
		remove_proc_entry("uuid1", NULL);
		return -EINVAL;
	}
	entry->proc_fops = &uuid_operations;
	uuid_update_security_ops(ops);
	printk(KERN_INFO "UUID: 0.0.0   2010/12/24\n");
	return 0;
}

module_init(uuid_init);
MODULE_LICENSE("GPL");
