/*
 * security/ccsecurity/memory.c
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.8.0-pre   2010/10/22
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include "internal.h"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0) || defined(RHEL_MAJOR)
#include <linux/hash.h>
#endif

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
 * Lock for protecting ccs_memory_used .
 *
 * I don't use atomic_t because it can handle only 16MB in 2.4 kernels.
 */
static DEFINE_SPINLOCK(ccs_policy_memory_lock);
/* Memoy currently used by policy/audit log/query . */
unsigned int ccs_memory_used[CCS_MAX_MEMORY_STAT];
/* Memory quota for policy/audit log/query . */
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

/**
 * ccs_mm_init - Initialize mm related code.
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
