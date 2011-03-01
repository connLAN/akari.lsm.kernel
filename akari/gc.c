/*
 * security/ccsecurity/gc.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.0+   2011/03/01
 */

#include "internal.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)

#ifndef LIST_POISON2
#define LIST_POISON2  ((void *) 0x00200200)
#endif

/**
 * list_del_rcu - Deletes entry from list without re-initialization.
 *
 * @entry: Pointer to "struct list_head".
 *
 * Returns nothing.
 *
 * This is for compatibility with older kernels.
 */
static inline void list_del_rcu(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	entry->prev = LIST_POISON2;
}

#endif

#ifndef list_for_each_entry_safe

/**
 * list_for_each_entry_safe - Iterate over list of given type safe against removal of list entry.
 *
 * @pos:    The "type *" to use as a loop cursor.
 * @n:      Another "type *" to use as temporary storage.
 * @head:   Pointer to "struct list_head".
 * @member: The name of the list_struct within the struct.
 *
 * This is for compatibility with older kernels.
 */
#define list_for_each_entry_safe(pos, n, head, member)                  \
	for (pos = list_entry((head)->next, typeof(*pos), member),      \
		     n = list_entry(pos->member.next, typeof(*pos), member); \
	     &pos->member != (head);					\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))

#endif

/* Size of an element. */
static const u8 ccs_element_size[CCS_MAX_POLICY] = {
	[CCS_ID_RESERVEDPORT] = sizeof(struct ccs_reserved),
	[CCS_ID_GROUP] = sizeof(struct ccs_group),
	[CCS_ID_ADDRESS_GROUP] = sizeof(struct ccs_address_group),
	[CCS_ID_PATH_GROUP] = sizeof(struct ccs_path_group),
	[CCS_ID_NUMBER_GROUP] = sizeof(struct ccs_number_group),
	[CCS_ID_AGGREGATOR] = sizeof(struct ccs_aggregator),
	[CCS_ID_TRANSITION_CONTROL] = sizeof(struct ccs_transition_control),
	[CCS_ID_MANAGER] = sizeof(struct ccs_manager),
	[CCS_ID_IPV6_ADDRESS] = sizeof(struct ccs_ipv6addr),
	/* [CCS_ID_CONDITION] = "struct ccs_condition"->size, */
	/* [CCS_ID_NAME] = "struct ccs_name"->size, */
	/* [CCS_ID_ACL] = ccs_acl_size["struct ccs_acl_info"->type], */
	[CCS_ID_DOMAIN] = sizeof(struct ccs_domain_info),
};

/* Size of a domain ACL element. */
static const u8 ccs_acl_size[] = {
	[CCS_TYPE_PATH_ACL] = sizeof(struct ccs_path_acl),
	[CCS_TYPE_PATH2_ACL] = sizeof(struct ccs_path2_acl),
	[CCS_TYPE_PATH_NUMBER_ACL] = sizeof(struct ccs_path_number_acl),
	[CCS_TYPE_MKDEV_ACL] = sizeof(struct ccs_mkdev_acl),
	[CCS_TYPE_MOUNT_ACL] = sizeof(struct ccs_mount_acl),
	[CCS_TYPE_INET_ACL] = sizeof(struct ccs_inet_acl),
	[CCS_TYPE_UNIX_ACL] = sizeof(struct ccs_unix_acl),
	[CCS_TYPE_ENV_ACL] = sizeof(struct ccs_env_acl),
	[CCS_TYPE_CAPABILITY_ACL] = sizeof(struct ccs_capability_acl),
	[CCS_TYPE_SIGNAL_ACL] = sizeof(struct ccs_signal_acl),
	[CCS_TYPE_AUTO_EXECUTE_HANDLER] = sizeof(struct ccs_handler_acl),
	[CCS_TYPE_DENIED_EXECUTE_HANDLER] = sizeof(struct ccs_handler_acl),
	[CCS_TYPE_AUTO_TASK_ACL] = sizeof(struct ccs_task_acl),
	[CCS_TYPE_MANUAL_TASK_ACL] = sizeof(struct ccs_task_acl),
};

/* The list for "struct ccs_io_buffer". */
static LIST_HEAD(ccs_io_buffer_list);
/* Lock for protecting ccs_io_buffer_list. */
static DEFINE_SPINLOCK(ccs_io_buffer_list_lock);

/**
 * ccs_struct_used_by_io_buffer - Check whether the list element is used by /proc/ccs/ users or not.
 *
 * @element: Pointer to "struct list_head".
 *
 * Returns true if @element is used by /proc/ccs/ users, false otherwise.
 */
static bool ccs_struct_used_by_io_buffer(const struct list_head *element)
{
	struct ccs_io_buffer *head;
	bool in_use = false;
	spin_lock(&ccs_io_buffer_list_lock);
	list_for_each_entry(head, &ccs_io_buffer_list, list) {
		head->users++;
		spin_unlock(&ccs_io_buffer_list_lock);
		if (mutex_lock_interruptible(&head->io_sem)) {
			in_use = true;
			goto out;
		}
		if (head->r.domain == element || head->r.group == element ||
		    head->r.acl == element || &head->w.domain->list == element)
			in_use = true;
		mutex_unlock(&head->io_sem);
out:
		spin_lock(&ccs_io_buffer_list_lock);
		head->users--;
		if (in_use)
			break;
	}
	spin_unlock(&ccs_io_buffer_list_lock);
	return in_use;
}

/**
 * ccs_name_used_by_io_buffer - Check whether the string is used by /proc/ccs/ users or not.
 *
 * @string: String to check.
 * @size:   Memory allocated for @string .
 *
 * Returns true if @string is used by /proc/ccs/ users, false otherwise.
 */
static bool ccs_name_used_by_io_buffer(const char *string, const size_t size)
{
	struct ccs_io_buffer *head;
	bool in_use = false;
	spin_lock(&ccs_io_buffer_list_lock);
	list_for_each_entry(head, &ccs_io_buffer_list, list) {
		int i;
		head->users++;
		spin_unlock(&ccs_io_buffer_list_lock);
		if (mutex_lock_interruptible(&head->io_sem)) {
			in_use = true;
			goto out;
		}
		for (i = 0; i < CCS_MAX_IO_READ_QUEUE; i++) {
			const char *w = head->r.w[i];
			if (w < string || w > string + size)
				continue;
			in_use = true;
			break;
		}
		mutex_unlock(&head->io_sem);
out:
		spin_lock(&ccs_io_buffer_list_lock);
		head->users--;
		if (in_use)
			break;
	}
	spin_unlock(&ccs_io_buffer_list_lock);
	return in_use;
}

/* Structure for garbage collection. */
struct ccs_gc {
	struct list_head list;
	enum ccs_policy_id type;
	size_t size;
	struct list_head *element;
};
/* List of entries to be deleted. */
static LIST_HEAD(ccs_gc_list);
/* Length of ccs_gc_list. */
static int ccs_gc_list_len;

/**
 * ccs_add_to_gc - Add an entry to to be deleted list.
 *
 * @type:    One of values in "enum ccs_policy_id".
 * @element: Pointer to "struct list_head".
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_policy_lock mutex.
 *
 * Adding an entry needs kmalloc(). Thus, if we try to add thousands of
 * entries at once, it will take too long time. Thus, do not add more than 128
 * entries per a scan. But to be able to handle worst case where all entries
 * are in-use, we accept one more entry per a scan.
 *
 * If we use singly linked list using "struct list_head"->prev (which is
 * LIST_POISON2), we can avoid kmalloc().
 */
static bool ccs_add_to_gc(const enum ccs_policy_id type,
			  struct list_head *element)
{
	struct ccs_gc *entry = kzalloc(sizeof(*entry), CCS_GFP_FLAGS);
	if (!entry)
		return false;
	entry->type = type;
	if (type == CCS_ID_ACL)
		entry->size =
			ccs_acl_size[container_of(element,
						  typeof(struct ccs_acl_info),
						  list)->type];
	else if (type == CCS_ID_NAME)
		entry->size =
 			container_of(element, typeof(struct ccs_name),
				     head.list)->size;
	else if (type == CCS_ID_CONDITION)
		entry->size =
			container_of(element, typeof(struct ccs_condition),
				     head.list)->size;
	else
		entry->size = ccs_element_size[type];
	entry->element = element;
	list_add(&entry->list, &ccs_gc_list);
	list_del_rcu(element);
	return ccs_gc_list_len++ < 128;
}

/**
 * ccs_element_linked_by_gc - Validate next element of an entry.
 *
 * @element: Pointer to an element.
 * @size:    Size of @element in byte.
 *
 * Returns true if @element is linked by other elements in the garbage
 * collector's queue, false otherwise.
 */
static bool ccs_element_linked_by_gc(const u8 *element, const size_t size)
{
	struct ccs_gc *p;
	list_for_each_entry(p, &ccs_gc_list, list) {
		const u8 *ptr = (const u8 *) p->element->next;
		if (ptr < element || element + size < ptr)
			continue;
		return true;
	}
	return false;
}

/**
 * ccs_del_transition_control - Delete members in "struct ccs_transition_control".
 *
 * @element: Pointer to "struct list_head".
 *
 * Returns nothing.
 */
static inline void ccs_del_transition_control(struct list_head *element)
{
	struct ccs_transition_control *ptr =
		container_of(element, typeof(*ptr), head.list);
	ccs_put_name(ptr->domainname);
	ccs_put_name(ptr->program);
}

/**
 * ccs_del_aggregator - Delete members in "struct ccs_aggregator".
 *
 * @element: Pointer to "struct list_head".
 *
 * Returns nothing.
 */
static inline void ccs_del_aggregator(struct list_head *element)
{
	struct ccs_aggregator *ptr =
		container_of(element, typeof(*ptr), head.list);
	ccs_put_name(ptr->original_name);
	ccs_put_name(ptr->aggregated_name);
}

/**
 * ccs_del_manager - Delete members in "struct ccs_manager".
 *
 * @element: Pointer to "struct list_head".
 *
 * Returns nothing.
 */
static inline void ccs_del_manager(struct list_head *element)
{
	struct ccs_manager *ptr =
		container_of(element, typeof(*ptr), head.list);
	ccs_put_name(ptr->manager);
}

/* For compatibility with older kernels. */
#ifndef for_each_process
#define for_each_process for_each_task
#endif

/**
 * ccs_domain_used_by_task - Check whether the given pointer is referenced by a task.
 *
 * @domain: Pointer to "struct ccs_domain_info".
 *
 * Returns true if @domain is in use, false otherwise.
 */
static bool ccs_domain_used_by_task(struct ccs_domain_info *domain)
{
	bool in_use = false;
	/*
	 * Don't delete this domain if somebody is doing execve().
	 *
	 * Since ccs_finish_execve() first reverts ccs_domain_info and then
	 * updates ccs_flags, we need smp_rmb() to make sure that GC first
	 * checks ccs_flags and then checks ccs_domain_info.
	 */
#ifdef CONFIG_CCSECURITY_USE_EXTERNAL_TASK_SECURITY
	int idx;
	rcu_read_lock();
	for (idx = 0; idx < CCS_MAX_TASK_SECURITY_HASH; idx++) {
		struct ccs_security *ptr;
		struct list_head *list = &ccs_task_security_list[idx];
		list_for_each_entry_rcu(ptr, list, list) {
			if (!(ptr->ccs_flags & CCS_TASK_IS_IN_EXECVE)) {
				smp_rmb(); /* Avoid out of order execution. */
				if (ptr->ccs_domain_info != domain)
					continue;
			}
			in_use = true;
			goto out;
		}
	}
	in_use = ccs_used_by_cred(domain);
out:
	rcu_read_unlock();
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0)
	struct task_struct *g;
	struct task_struct *t;
	ccs_tasklist_lock();
	do_each_thread(g, t) {
		if (!(t->ccs_flags & CCS_TASK_IS_IN_EXECVE)) {
			smp_rmb(); /* Avoid out of order execution. */
			if (t->ccs_domain_info != domain)
				continue;
		}
		in_use = true;
		goto out;
	} while_each_thread(g, t);
out:
	ccs_tasklist_unlock();
#else
	struct task_struct *p;
	ccs_tasklist_lock();
	for_each_process(p) {
		if (!(p->ccs_flags & CCS_TASK_IS_IN_EXECVE)) {
			smp_rmb(); /* Avoid out of order execution. */
			if (p->ccs_domain_info != domain)
				continue;
		}
		in_use = true;
		break;
	}
	ccs_tasklist_unlock();
#endif
	return in_use;
}

/**
 * ccs_del_acl - Delete members in "struct ccs_acl_info".
 *
 * @element: Pointer to "struct list_head".
 *
 * Returns nothing.
 */
static void ccs_del_acl(struct list_head *element)
{
	struct ccs_acl_info *acl = container_of(element, typeof(*acl), list);
	ccs_put_condition(acl->cond);
	switch (acl->type) {
	case CCS_TYPE_PATH_ACL:
		{
			struct ccs_path_acl *entry =
				container_of(acl, typeof(*entry), head);
			ccs_put_name_union(&entry->name);
		}
		break;
	case CCS_TYPE_PATH2_ACL:
		{
			struct ccs_path2_acl *entry =
				container_of(acl, typeof(*entry), head);
			ccs_put_name_union(&entry->name1);
			ccs_put_name_union(&entry->name2);
		}
		break;
	case CCS_TYPE_PATH_NUMBER_ACL:
		{
			struct ccs_path_number_acl *entry =
				container_of(acl, typeof(*entry), head);
			ccs_put_name_union(&entry->name);
			ccs_put_number_union(&entry->number);
		}
		break;
	case CCS_TYPE_MKDEV_ACL:
		{
			struct ccs_mkdev_acl *entry =
				container_of(acl, typeof(*entry), head);
			ccs_put_name_union(&entry->name);
			ccs_put_number_union(&entry->mode);
			ccs_put_number_union(&entry->major);
			ccs_put_number_union(&entry->minor);
		}
		break;
	case CCS_TYPE_MOUNT_ACL:
		{
			struct ccs_mount_acl *entry =
				container_of(acl, typeof(*entry), head);
			ccs_put_name_union(&entry->dev_name);
			ccs_put_name_union(&entry->dir_name);
			ccs_put_name_union(&entry->fs_type);
			ccs_put_number_union(&entry->flags);
		}
		break;
	case CCS_TYPE_INET_ACL:
		{
			struct ccs_inet_acl *entry =
				container_of(acl, typeof(*entry), head);
			switch (entry->address_type) {
			case CCS_IP_ADDRESS_TYPE_ADDRESS_GROUP:
				ccs_put_group(entry->address.group);
				break;
			case CCS_IP_ADDRESS_TYPE_IPv6:
				ccs_put_ipv6_address(entry->address.ipv6.min);
				ccs_put_ipv6_address(entry->address.ipv6.max);
				break;
			}
			ccs_put_number_union(&entry->port);
		}
		break;
	case CCS_TYPE_UNIX_ACL:
		{
			struct ccs_unix_acl *entry =
				container_of(acl, typeof(*entry), head);
			ccs_put_name_union(&entry->name);
		}
		break;
	case CCS_TYPE_ENV_ACL:
		{
			struct ccs_env_acl *entry =
				container_of(acl, typeof(*entry), head);
			ccs_put_name(entry->env);
		}
		break;
	case CCS_TYPE_CAPABILITY_ACL:
		{
			/* Nothing to do. */
		}
		break;
	case CCS_TYPE_SIGNAL_ACL:
		{
			struct ccs_signal_acl *entry =
				container_of(acl, typeof(*entry), head);
			ccs_put_name(entry->domainname);
		}
		break;
	case CCS_TYPE_AUTO_EXECUTE_HANDLER:
	case CCS_TYPE_DENIED_EXECUTE_HANDLER:
		{
			struct ccs_handler_acl *entry =
				container_of(acl, typeof(*entry), head);
			ccs_put_name(entry->handler);
		}
		break;
	case CCS_TYPE_AUTO_TASK_ACL:
	case CCS_TYPE_MANUAL_TASK_ACL:
		{
			struct ccs_task_acl *entry =
				container_of(acl, typeof(*entry), head);
			ccs_put_name(entry->domainname);
		}
		break;
	}
}

/**
 * ccs_del_domain - Delete members in "struct ccs_domain_info".
 *
 * @element: Pointer to "struct list_head".
 *
 * Returns nothing.
 */
static inline void ccs_del_domain(struct list_head *element)
{
	struct ccs_domain_info *domain =
		container_of(element, typeof(*domain), list);
	struct ccs_acl_info *acl;
	struct ccs_acl_info *tmp;
	u8 i;
	/*
	 * Since this domain is referenced from none of "struct ccs_io_buffer"
	 * ccs_gc_list, "struct task_struct", we can delete elements without
	 * checking for is_deleted flag.
	 */
	for (i = 0; i < 2; i++) {
		list_for_each_entry_safe(acl, tmp, &domain->acl_info_list[i],
					 list) {
			ccs_del_acl(&acl->list);
			ccs_memory_free(acl, ccs_acl_size[acl->type]);
		}
	}
	ccs_put_name(domain->domainname);
}

/**
 * ccs_del_path_group - Delete members in "struct ccs_path_group".
 *
 * @element: Pointer to "struct list_head".
 *
 * Returns nothing.
 */
static inline void ccs_del_path_group(struct list_head *element)
{
	struct ccs_path_group *member =
		container_of(element, typeof(*member), head.list);
	ccs_put_name(member->member_name);
}

/**
 * ccs_del_group - Delete "struct ccs_group".
 *
 * @element: Pointer to "struct list_head".
 *
 * Returns nothing.
 */
static inline void ccs_del_group(struct list_head *element)
{
	struct ccs_group *group =
		container_of(element, typeof(*group), head.list);
	ccs_put_name(group->group_name);
}

/**
 * ccs_del_address_group - Delete members in "struct ccs_address_group".
 *
 * @element: Pointer to "struct list_head".
 *
 * Returns nothing.
 */
static inline void ccs_del_address_group(struct list_head *element)
{
	struct ccs_address_group *member =
		container_of(element, typeof(*member), head.list);
	if (member->is_ipv6) {
		ccs_put_ipv6_address(member->min.ipv6);
		ccs_put_ipv6_address(member->max.ipv6);
	}
}

/**
 * ccs_del_number_group - Delete members in "struct ccs_number_group".
 *
 * @element: Pointer to "struct list_head".
 *
 * Returns nothing.
 */
static inline void ccs_del_number_group(struct list_head *element)
{
	/* Nothing to do. */
}

/**
 * ccs_del_reservedport - Delete members in "struct ccs_reserved".
 *
 * @element: Pointer to "struct list_head".
 *
 * Returns nothing.
 */
static inline void ccs_del_reservedport(struct list_head *element)
{
	/* Nothing to do. */
}

/**
 * ccs_del_ipv6_address - Delete members in "struct ccs_ipv6addr".
 *
 * @element: Pointer to "struct list_head".
 *
 * Returns nothing.
 */
static inline void ccs_del_ipv6_address(struct list_head *element)
{
	/* Nothing to do. */
}

/**
 * ccs_del_condition - Delete members in "struct ccs_condition".
 *
 * @element: Pointer to "struct list_head".
 *
 * Returns nothing.
 */
void ccs_del_condition(struct list_head *element)
{
	struct ccs_condition *cond = container_of(element, typeof(*cond),
						  head.list);
	const u16 condc = cond->condc;
	const u16 numbers_count = cond->numbers_count;
	const u16 names_count = cond->names_count;
	const u16 argc = cond->argc;
	const u16 envc = cond->envc;
	unsigned int i;
	const struct ccs_condition_element *condp
		= (const struct ccs_condition_element *) (cond + 1);
	struct ccs_number_union *numbers_p
		= (struct ccs_number_union *) (condp + condc);
	struct ccs_name_union *names_p
		= (struct ccs_name_union *) (numbers_p + numbers_count);
	const struct ccs_argv *argv
		= (const struct ccs_argv *) (names_p + names_count);
	const struct ccs_envp *envp
		= (const struct ccs_envp *) (argv + argc);
	for (i = 0; i < numbers_count; i++)
		ccs_put_number_union(numbers_p++);
	for (i = 0; i < names_count; i++)
		ccs_put_name_union(names_p++);
	for (i = 0; i < argc; argv++, i++)
		ccs_put_name(argv->value);
	for (i = 0; i < envc; envp++, i++) {
		ccs_put_name(envp->name);
		ccs_put_name(envp->value);
	}
	ccs_put_name(cond->transit);
}

/**
 * ccs_del_name - Delete members in "struct ccs_name".
 *
 * @element: Pointer to "struct list_head".
 *
 * Returns nothing.
 */
static inline void ccs_del_name(struct list_head *element)
{
	/* Nothing to do. */
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 19)

/*
 * Lock for syscall users.
 *
 * This lock is held for only protecting single SRCU section.
 */
struct srcu_struct ccs_ss;

#else

/*
 * Lock for syscall users.
 *
 * This lock is used for protecting single SRCU section for 2.6.18 and
 * earlier kernels because they don't have SRCU support.
 */
static struct {
	int counter_idx; /* Currently active index (0 or 1). */
	int counter[2];  /* Current users. Protected by ccs_counter_lock. */
} ccs_counter;
/* Lock for protecting ccs_counter. */
static DEFINE_SPINLOCK(ccs_counter_lock);

/**
 * ccs_lock - Alternative for srcu_read_lock().
 *
 * Returns index number which has to be passed to ccs_unlock().
 */
int ccs_lock(void)
{
	int idx;
	spin_lock(&ccs_counter_lock);
	idx = ccs_counter.counter_idx;
	ccs_counter.counter[idx]++;
	spin_unlock(&ccs_counter_lock);
	return idx;
}

/**
 * ccs_unlock - Alternative for srcu_read_unlock().
 *
 * @idx: Index number returned by ccs_lock().
 *
 * Returns nothing.
 */
void ccs_unlock(const int idx)
{
	spin_lock(&ccs_counter_lock);
	ccs_counter.counter[idx]--;
	spin_unlock(&ccs_counter_lock);
}

/**
 * ccs_synchronize_counter - Alternative for synchronize_srcu().
 *
 * Returns nothing.
 */
static void ccs_synchronize_counter(void)
{
	int idx;
	int v;
	/*
	 * Change currently active counter's index. Make it visible to other
	 * threads by doing it with ccs_counter_lock held.
	 * This function is called by garbage collector thread, and the garbage
	 * collector thread is exclusive. Therefore, it is guaranteed that
	 * SRCU grace period has expired when returning from this function.
	 */
	spin_lock(&ccs_counter_lock);
	idx = ccs_counter.counter_idx;
	ccs_counter.counter_idx ^= 1;
	v = ccs_counter.counter[idx];
	spin_unlock(&ccs_counter_lock);
	/* Wait for previously active counter to become 0. */
	while (v) {
		ssleep(1);
		spin_lock(&ccs_counter_lock);
		v = ccs_counter.counter[idx];
		spin_unlock(&ccs_counter_lock);
	}
}

#endif

/**
 * ccs_collect_member - Delete elements with "struct ccs_acl_head".
 *
 * @id:          One of values in "enum ccs_policy_id".
 * @member_list: Pointer to "struct list_head".
 *
 * Returns true if some elements are deleted, false otherwise.
 */
static bool ccs_collect_member(const enum ccs_policy_id id,
			       struct list_head *member_list)
{
	struct ccs_acl_head *member;
	list_for_each_entry(member, member_list, list) {
		if (!member->is_deleted)
			continue;
		if (!ccs_add_to_gc(id, &member->list))
			return false;
	}
	return true;
}

/**
 * ccs_collect_acl - Delete elements in "struct ccs_domain_info".
 *
 * @domain: Pointer to "struct ccs_domain_info".
 *
 * Returns true if some elements are deleted, false otherwise.
 */
static bool ccs_collect_acl(struct ccs_domain_info *domain)
{
	struct ccs_acl_info *acl;
	u8 i;
	for (i = 0; i < 2; i++) {
		list_for_each_entry(acl, &domain->acl_info_list[i], list) {
			if (!acl->is_deleted)
				continue;
			if (!ccs_add_to_gc(CCS_ID_ACL, &acl->list))
				return false;
		}
	}
	return true;
}

/**
 * ccs_collect_entry - Scan lists for deleted elements.
 *
 * Returns nothing.
 */
static void ccs_collect_entry(void)
{
	int i;
	enum ccs_policy_id id;
	int idx;
	if (mutex_lock_interruptible(&ccs_policy_lock))
		return;
	idx = ccs_read_lock();
	for (id = 0; id < CCS_MAX_POLICY; id++)
		if (!ccs_collect_member(id, &ccs_policy_list[id]))
			goto unlock;
	for (i = 0; i < CCS_MAX_ACL_GROUPS; i++)
		if (!ccs_collect_acl(&ccs_acl_group[i]))
			goto unlock;
	{
		struct ccs_domain_info *domain;
		list_for_each_entry(domain, &ccs_domain_list, list) {
			if (!ccs_collect_acl(domain))
				goto unlock;
			if (!domain->is_deleted ||
			    ccs_domain_used_by_task(domain))
				continue;
			if (!ccs_add_to_gc(CCS_ID_DOMAIN, &domain->list))
				goto unlock;
		}
	}
	for (i = 0; i < CCS_MAX_GROUP; i++) {
		struct list_head *list = &ccs_group_list[i];
		struct ccs_group *group;
		switch (i) {
		case 0:
			id = CCS_ID_PATH_GROUP;
			break;
		case 1:
			id = CCS_ID_NUMBER_GROUP;
			break;
		default:
			id = CCS_ID_ADDRESS_GROUP;
			break;
		}
		list_for_each_entry(group, list, head.list) {
			if (!ccs_collect_member(id, &group->member_list))
				goto unlock;
			if (!list_empty(&group->member_list) ||
			    atomic_read(&group->head.users))
				continue;
			if (!ccs_add_to_gc(CCS_ID_GROUP, &group->head.list))
				goto unlock;
		}
	}
	for (i = 0; i < CCS_MAX_LIST + CCS_MAX_HASH; i++) {
		struct list_head *list = i < CCS_MAX_LIST ?
			&ccs_shared_list[i] : &ccs_name_list[i - CCS_MAX_LIST];
		struct ccs_shared_acl_head *ptr;
		switch (i) {
		case 0:
			id = CCS_ID_CONDITION;
			break;
		case 1:
			id = CCS_ID_IPV6_ADDRESS;
			break;
		default:
			id = CCS_ID_NAME;
			break;
		}
		list_for_each_entry(ptr, list, list) {
			if (atomic_read(&ptr->users))
				continue;
			if (!ccs_add_to_gc(id, &ptr->list))
				goto unlock;
		}
	}
unlock:
	ccs_read_unlock(idx);
	mutex_unlock(&ccs_policy_lock);
}

/**
 * ccs_kfree_entry - Delete entries in ccs_gc_list.
 *
 * Returns true if some entries were kfree()d, false otherwise.
 */
static bool ccs_kfree_entry(void)
{
	struct ccs_gc *p;
	struct ccs_gc *tmp;
	bool result = false;
	list_for_each_entry_safe(p, tmp, &ccs_gc_list, list) {
		struct list_head * const element = p->element;
		/*
		 * list_del_rcu() in ccs_add_to_gc() guarantees that the list
		 * element became no longer reachable from the list which the
		 * element was originally on (e.g. ccs_domain_list). Also,
		 * synchronize_srcu() in ccs_gc_thread() guarantees that the
		 * list element became no longer referenced by syscall users.
		 *
		 * However, there are three users which may still be using the
		 * list element. We need to defer until all of these users
		 * forget the list element.
		 *
		 * Firstly, defer until "struct ccs_io_buffer"->r.{domain,
		 * group,acl} and "struct ccs_io_buffer"->w.domain forget the
		 * list element.
		 */
		if (ccs_struct_used_by_io_buffer(element))
			continue;
		/*
		 * Secondly, defer until all other elements in the ccs_gc_list
		 * list forget the list element.
		 */
		if (ccs_element_linked_by_gc((const u8 *) element, p->size))
			continue;
		switch (p->type) {
		case CCS_ID_TRANSITION_CONTROL:
			ccs_del_transition_control(element);
			break;
		case CCS_ID_MANAGER:
			ccs_del_manager(element);
			break;
		case CCS_ID_AGGREGATOR:
			ccs_del_aggregator(element);
			break;
		case CCS_ID_GROUP:
			ccs_del_group(element);
			break;
		case CCS_ID_PATH_GROUP:
			ccs_del_path_group(element);
			break;
		case CCS_ID_ADDRESS_GROUP:
			ccs_del_address_group(element);
			break;
		case CCS_ID_NUMBER_GROUP:
			ccs_del_number_group(element);
			break;
		case CCS_ID_RESERVEDPORT:
			ccs_del_reservedport(element);
			break;
		case CCS_ID_IPV6_ADDRESS:
			ccs_del_ipv6_address(element);
			break;
		case CCS_ID_CONDITION:
			ccs_del_condition(element);
			break;
		case CCS_ID_NAME:
			/*
			 * Thirdly, defer until all "struct ccs_io_buffer"
			 * ->r.w[] forget the list element.
			 */
			if (ccs_name_used_by_io_buffer(
			    container_of(element, typeof(struct ccs_name),
					 head.list)->entry.name, p->size))
				continue;
			ccs_del_name(element);
			break;
		case CCS_ID_ACL:
			ccs_del_acl(element);
			break;
		case CCS_ID_DOMAIN:
			/*
			 * Thirdly, defer until all "struct task_struct" forget
			 * the list element.
			 */
			if (ccs_domain_used_by_task(
			    container_of(element,
					 typeof(struct ccs_domain_info),
					 list)))
				continue;
			ccs_del_domain(element);
			break;
		case CCS_MAX_POLICY:
			break;
		}
		ccs_memory_free(element, p->size);
		list_del(&p->list);
		kfree(p);
		ccs_gc_list_len--;
		result = true;
	}
	return result;
}

/**
 * ccs_gc_thread - Garbage collector thread function.
 *
 * @unused: Unused.
 *
 * In case OOM-killer choose this thread for termination, we create this thread
 * as a short live thread whenever /proc/ccs/ interface was close()d.
 *
 * Returns 0.
 */
static int ccs_gc_thread(void *unused)
{
	/* Garbage collector thread is exclusive. */
	static DEFINE_MUTEX(ccs_gc_mutex);
	if (!mutex_trylock(&ccs_gc_mutex))
		goto out;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
	daemonize("GC for CCS");
#else
	daemonize();
	reparent_to_init();
#if defined(TASK_DEAD)
	{
		struct task_struct *task = current;
		spin_lock_irq(&task->sighand->siglock);
		siginitsetinv(&task->blocked, 0);
		recalc_sigpending();
		spin_unlock_irq(&task->sighand->siglock);
	}
#else
	{
		struct task_struct *task = current;
		spin_lock_irq(&task->sigmask_lock);
		siginitsetinv(&task->blocked, 0);
		recalc_sigpending(task);
		spin_unlock_irq(&task->sigmask_lock);
	}
#endif
	snprintf(current->comm, sizeof(current->comm) - 1, "GC for CCS");
#endif
	do {
		ccs_collect_entry();
		if (list_empty(&ccs_gc_list))
			break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 19)
		synchronize_srcu(&ccs_ss);
#else
		ccs_synchronize_counter();
#endif
	} while (ccs_kfree_entry());
	mutex_unlock(&ccs_gc_mutex);
out:
	/* This acts as do_exit(0). */
	return 0;
}

/**
 * ccs_notify_gc - Register/unregister /proc/ccs/ users.
 *
 * @head:        Pointer to "struct ccs_io_buffer".
 * @is_register: True if register, false if unregister.
 *
 * Returns nothing.
 */
void ccs_notify_gc(struct ccs_io_buffer *head, const bool is_register)
{
	bool is_write = false;
	spin_lock(&ccs_io_buffer_list_lock);
	if (is_register) {
		head->users = 1;
		list_add(&head->list, &ccs_io_buffer_list);
	} else {
		is_write = head->write_buf != NULL;
		if (!--head->users) {
			list_del(&head->list);
			kfree(head->read_buf);
			kfree(head->write_buf);
			kfree(head);
		}
	}
	spin_unlock(&ccs_io_buffer_list_lock);
	if (is_write) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 6)
		struct task_struct *task = kthread_create(ccs_gc_thread, NULL,
							  "GC for CCS");
		if (!IS_ERR(task))
			wake_up_process(task);
#else
		kernel_thread(ccs_gc_thread, NULL, 0);
#endif
	}
}
