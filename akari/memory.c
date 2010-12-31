/*
 * security/ccsecurity/memory.c
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.8.0+   2010/12/31
 */

#include "internal.h"

/**
 * ccs_warn_oom - Print out of memory warning message.
 *
 * @function: Function's name.
 *
 * Returns nothing.
 */
void ccs_warn_oom(const char *function)
{
	/* Reduce error messages. */
	static pid_t ccs_last_pid;
	const pid_t pid = current->pid;
	if (ccs_last_pid != pid) {
		printk(KERN_WARNING "ERROR: Out of memory at %s.\n",
		       function);
		ccs_last_pid = pid;
	}
	if (!ccs_policy_loaded)
		panic("MAC Initialization failed.\n");
}

/*
 * Lock for protecting ccs_memory_used.
 *
 * I don't use atomic_t because it can handle only 16MB in 2.4 kernels.
 */
static DEFINE_SPINLOCK(ccs_policy_memory_lock);
/* Memoy currently used by policy/audit log/query. */
unsigned int ccs_memory_used[CCS_MAX_MEMORY_STAT];
/* Memory quota for "policy"/"audit log"/"query". */
unsigned int ccs_memory_quota[CCS_MAX_MEMORY_STAT];

/**
 * ccs_memory_ok - Check memory quota.
 *
 * @ptr:  Pointer to allocated memory.
 * @size: Size in byte.
 *
 * Returns true if @ptr is not NULL and quota not exceeded, false otherwise.
 */
bool ccs_memory_ok(const void *ptr, const unsigned int size)
{
	size_t s = ccs_round2(size);
	bool result;
	spin_lock(&ccs_policy_memory_lock);
	ccs_memory_used[CCS_MEMORY_POLICY] += s;
	result = ptr && (!ccs_memory_quota[CCS_MEMORY_POLICY] ||
			 ccs_memory_used[CCS_MEMORY_POLICY] <=
			 ccs_memory_quota[CCS_MEMORY_POLICY]);
	if (!result)
		ccs_memory_used[CCS_MEMORY_POLICY] -= s;
	spin_unlock(&ccs_policy_memory_lock);
	if (result)
		return true;
	ccs_warn_oom(__func__);
	return false;
}

/**
 * ccs_commit_ok - Allocate memory and check memory quota.
 *
 * @data: Data to copy from.
 * @size: Size in byte.
 *
 * Returns pointer to allocated memory on success, NULL otherwise.
 * @data is zero-cleared on success.
 */
void *ccs_commit_ok(void *data, const unsigned int size)
{
	void *ptr = kmalloc(size, CCS_GFP_FLAGS);
	if (ccs_memory_ok(ptr, size)) {
		memmove(ptr, data, size);
		memset(data, 0, size);
		return ptr;
	}
	kfree(ptr);
	return NULL;
}

/**
 * ccs_memory_free - Free memory for elements.
 *
 * @ptr:  Pointer to allocated memory.
 * @size: Size in byte.
 *
 * Returns nothing.
 */
void ccs_memory_free(const void *ptr, size_t size)
{
	size_t s = ccs_round2(size);
	spin_lock(&ccs_policy_memory_lock);
	ccs_memory_used[CCS_MEMORY_POLICY] -= s;
	spin_unlock(&ccs_policy_memory_lock);
	kfree(ptr);
}

/**
 * ccs_get_group - Allocate memory for "struct ccs_path_group"/"struct ccs_number_group"/"struct ccs_address_group".
 *
 * @group_name: The name of address group.
 * @idx:        Index number.
 *
 * Returns pointer to "struct ccs_group" on success, NULL otherwise.
 */
struct ccs_group *ccs_get_group(const char *group_name, const u8 idx)
{
	struct ccs_group e = { };
	struct ccs_group *group = NULL;
	bool found = false;
	if (!ccs_correct_word(group_name) || idx >= CCS_MAX_GROUP)
		return NULL;
	e.group_name = ccs_get_name(group_name);
	if (!e.group_name)
		return NULL;
	if (mutex_lock_interruptible(&ccs_policy_lock))
		goto out;
	list_for_each_entry(group, &ccs_group_list[idx], head.list) {
		if (e.group_name != group->group_name)
			continue;
		atomic_inc(&group->head.users);
		found = true;
		break;
	}
	if (!found) {
		struct ccs_group *entry = ccs_commit_ok(&e, sizeof(e));
		if (entry) {
			INIT_LIST_HEAD(&entry->member_list);
			atomic_set(&entry->head.users, 1);
			list_add_tail_rcu(&entry->head.list,
					  &ccs_group_list[idx]);
			group = entry;
			found = true;
		}
	}
	mutex_unlock(&ccs_policy_lock);
out:
	ccs_put_name(e.group_name);
	return found ? group : NULL;
}

/**
 * ccs_get_ipv6_address - Keep the given IPv6 address on the RAM.
 *
 * @addr: Pointer to "struct in6_addr".
 *
 * Returns pointer to "struct in6_addr" on success, NULL otherwise.
 */
const struct in6_addr *ccs_get_ipv6_address(const struct in6_addr *addr)
{
	struct ccs_ipv6addr *entry;
	struct ccs_ipv6addr *ptr = NULL;
	int error = -ENOMEM;
	if (!addr)
		return NULL;
	entry = kzalloc(sizeof(*entry), CCS_GFP_FLAGS);
	if (mutex_lock_interruptible(&ccs_policy_lock))
		goto out;
	list_for_each_entry(ptr, &ccs_shared_list[CCS_IPV6ADDRESS_LIST],
			    head.list) {
		if (memcmp(&ptr->addr, addr, sizeof(*addr)))
			continue;
		atomic_inc(&ptr->head.users);
		error = 0;
		break;
	}
	if (error && ccs_memory_ok(entry, sizeof(*entry))) {
		ptr = entry;
		ptr->addr = *addr;
		atomic_set(&ptr->head.users, 1);
		list_add_tail(&ptr->head.list,
			      &ccs_shared_list[CCS_IPV6ADDRESS_LIST]);
		entry = NULL;
		error = 0;
	}
	mutex_unlock(&ccs_policy_lock);
out:
	kfree(entry);
	return !error ? &ptr->addr : NULL;
}

/* The list for "struct ccs_name". */
struct list_head ccs_name_list[CCS_MAX_HASH];

/**
 * ccs_get_name - Allocate memory for string data.
 *
 * @name: The string to store into the permernent memory.
 *
 * Returns pointer to "struct ccs_path_info" on success, NULL otherwise.
 */
const struct ccs_path_info *ccs_get_name(const char *name)
{
	struct ccs_name *ptr;
	unsigned int hash;
	int len;
	int allocated_len;
	struct list_head *head;

	if (!name)
		return NULL;
	len = strlen(name) + 1;
	hash = full_name_hash((const unsigned char *) name, len - 1);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0) || defined(RHEL_MAJOR)
	head = &ccs_name_list[hash_long(hash, CCS_HASH_BITS)];
#else
	head = &ccs_name_list[hash % CCS_MAX_HASH];
#endif
	if (mutex_lock_interruptible(&ccs_policy_lock))
		return NULL;
	list_for_each_entry(ptr, head, head.list) {
		if (hash != ptr->entry.hash || strcmp(name, ptr->entry.name))
			continue;
		atomic_inc(&ptr->head.users);
		goto out;
	}
	allocated_len = sizeof(*ptr) + len;
	ptr = kzalloc(allocated_len, CCS_GFP_FLAGS);
	if (ccs_memory_ok(ptr, allocated_len)) {
		ptr->entry.name = ((char *) ptr) + sizeof(*ptr);
		memmove((char *) ptr->entry.name, name, len);
		atomic_set(&ptr->head.users, 1);
		ccs_fill_path_info(&ptr->entry);
		ptr->size = allocated_len;
		list_add_tail(&ptr->head.list, head);
	} else {
		kfree(ptr);
		ptr = NULL;
	}
out:
	mutex_unlock(&ccs_policy_lock);
	return ptr ? &ptr->entry : NULL;
}

#ifdef CONFIG_CCSECURITY_USE_EXTERNAL_TASK_SECURITY

/* Dummy security context for avoiding NULL pointer dereference. */
static struct ccs_security ccs_oom_security = {
	.ccs_domain_info = &ccs_kernel_domain
};

/* Dummy security context for avoiding NULL pointer dereference. */
static struct ccs_security ccs_default_security = {
	.ccs_domain_info = &ccs_kernel_domain
};

/* List of "struct ccs_security". */
struct list_head ccs_task_security_list[CCS_MAX_TASK_SECURITY_HASH];
/* Lock for protecting ccs_task_security_list[]. */
DEFINE_SPINLOCK(ccs_task_security_list_lock);

/**
 * ccs_add_task_security - Add "struct ccs_security" to list.
 *
 * @ptr:  Pointer to "struct ccs_security".
 * @list: Pointer to "struct list_head".
 *
 * Returns nothing.
 */
static void ccs_add_task_security(struct ccs_security *ptr,
				  struct list_head *list)
{
	unsigned long flags;
	spin_lock_irqsave(&ccs_task_security_list_lock, flags);
	list_add_rcu(&ptr->list, list);
	spin_unlock_irqrestore(&ccs_task_security_list_lock, flags);
}

/**
 * __ccs_alloc_task_security - Allocate memory for new tasks.
 *
 * @task: Pointer to "struct task_struct".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_alloc_task_security(const struct task_struct *task)
{
	struct ccs_security *old_security = ccs_current_security();
	struct ccs_security *new_security = kzalloc(sizeof(*new_security),
						    GFP_KERNEL);
	struct list_head *list = &ccs_task_security_list
		[hash_ptr((void *) task, CCS_TASK_SECURITY_HASH_BITS)];
	if (!new_security)
		return -ENOMEM;
	*new_security = *old_security;
	new_security->task = task;
	ccs_add_task_security(new_security, list);
	return 0;
}

#if 0
/**
 * ccs_find_task_security - Find "struct ccs_security" for given task.
 *
 * @task: Pointer to "struct task_struct".
 *
 * Returns pointer to "struct ccs_security" on success, &ccs_oom_security on
 * out of memory, &ccs_default_security otherwise.
 *
 * If @task is current thread and "struct ccs_security" for current thread was
 * not found, I try to allocate it. But if allocation failed, current thread
 * will be killed by SIGKILL. Note that if current->pid == 1, sending SIGKILL
 * won't work.
 */
struct ccs_security *ccs_find_task_security(const struct task_struct *task)
{
	struct ccs_security *ptr;
	struct list_head *list = &ccs_task_security_list
		[hash_ptr((void *) task, CCS_TASK_SECURITY_HASH_BITS)];
	/* Make sure INIT_LIST_HEAD() in ccs_mm_init() takes effect. */
	while (!list->next);
	rcu_read_lock();
	list_for_each_entry_rcu(ptr, list, list) {
		if (ptr->task != task)
			continue;
		rcu_read_unlock();
		return ptr;
	}
	rcu_read_unlock();
	if (task != current)
		return &ccs_default_security;
	/* Use GFP_ATOMIC because caller may have called rcu_read_lock(). */
	ptr = kzalloc(sizeof(*ptr), GFP_ATOMIC);
	if (!ptr) {
		printk(KERN_WARNING "Unable to allocate memory for pid=%u\n",
		       task->pid);
		send_sig(SIGKILL, current, 0);
		return &ccs_oom_security;
	}
	*ptr = ccs_default_security;
	ptr->task = task;
	ccs_add_task_security(ptr, list);
	return ptr;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)

/**
 * ccs_rcu_free - RCU callback for releasing "struct ccs_security".
 *
 * @rcu: Pointer to "struct rcu_head".
 *
 * Returns nothing.
 */
static void ccs_rcu_free(struct rcu_head *rcu)
{
	struct ccs_security *ptr = container_of(rcu, typeof(*ptr), rcu);
	kfree(ptr);
}

#else

/**
 * ccs_rcu_free - RCU callback for releasing "struct ccs_security".
 *
 * @arg: Pointer to "void".
 *
 * Returns nothing.
 */
static void ccs_rcu_free(void *arg)
{
	struct ccs_security *ptr = arg;
	kfree(ptr);
}

#endif

/**
 * __ccs_free_task_security - Release memory associated with "struct task_struct".
 *
 * @task: Pointer to "struct task_struct".
 *
 * Returns nothing.
 */
static void __ccs_free_task_security(const struct task_struct *task)
{
	unsigned long flags;
	struct ccs_security *ptr = ccs_find_task_security(task);
	if (ptr == &ccs_default_security || ptr == &ccs_oom_security)
		return;
	spin_lock_irqsave(&ccs_task_security_list_lock, flags);
	list_del_rcu(&ptr->list);
	spin_unlock_irqrestore(&ccs_task_security_list_lock, flags);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)
	call_rcu(&ptr->rcu, ccs_rcu_free);
#else
	call_rcu(&ptr->rcu, ccs_rcu_free, ptr);
#endif
}

#endif

/**
 * ccs_mm_init - Initialize mm related code.
 *
 * Returns nothing.
 */
void __init ccs_mm_init(void)
{
	int idx;
	for (idx = 0; idx < CCS_MAX_HASH; idx++)
		INIT_LIST_HEAD(&ccs_name_list[idx]);
	for (idx = 0; idx < CCS_MAX_ACL_GROUPS; idx++) {
		INIT_LIST_HEAD(&ccs_acl_group[idx].acl_info_list[0]);
		INIT_LIST_HEAD(&ccs_acl_group[idx].acl_info_list[1]);
	}
	INIT_LIST_HEAD(&ccs_kernel_domain.acl_info_list[0]);
	INIT_LIST_HEAD(&ccs_kernel_domain.acl_info_list[1]);
#ifdef CONFIG_CCSECURITY_USE_EXTERNAL_TASK_SECURITY
	for (idx = 0; idx < CCS_MAX_TASK_SECURITY_HASH; idx++)
		INIT_LIST_HEAD(&ccs_task_security_list[idx]);
#endif
	smp_wmb(); /* Avoid out of order execution. */
#ifdef CONFIG_CCSECURITY_USE_EXTERNAL_TASK_SECURITY
	ccsecurity_ops.alloc_task_security = __ccs_alloc_task_security;
	ccsecurity_ops.free_task_security = __ccs_free_task_security;
#endif
	ccs_kernel_domain.domainname = ccs_get_name(CCS_ROOT_NAME);
	list_add_tail_rcu(&ccs_kernel_domain.list, &ccs_domain_list);
	idx = ccs_read_lock();
	if (ccs_find_domain(CCS_ROOT_NAME) != &ccs_kernel_domain)
		panic("Can't register ccs_kernel_domain");
	{
		/* Load built-in policy. */
		static char ccs_builtin_initializers[] __initdata
			= CONFIG_CCSECURITY_BUILTIN_INITIALIZERS;
		char *cp = ccs_builtin_initializers;
		ccs_normalize_line(cp);
		while (cp && *cp) {
			char *cp2 = strchr(cp, ' ');
			if (cp2)
				*cp2++ = '\0';
			ccs_write_transition_control(cp, false,
				     CCS_TRANSITION_CONTROL_INITIALIZE);
			cp = cp2;
		}
	}
	ccs_read_unlock(idx);
}
