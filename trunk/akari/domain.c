/*
 * security/ccsecurity/domain.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.2-pre   2011/06/06
 */

#include "internal.h"

/* The initial domain. */
struct ccs_domain_info ccs_kernel_domain;

/* The list for "struct ccs_domain_info". */
LIST_HEAD(ccs_domain_list);

/* List of "struct ccs_condition" and "struct ccs_ipv6addr". */
struct list_head ccs_shared_list[CCS_MAX_LIST];

/**
 * ccs_update_policy - Update an entry for exception policy.
 *
 * @new_entry:       Pointer to "struct ccs_acl_info".
 * @size:            Size of @new_entry in bytes.
 * @param:           Pointer to "struct ccs_acl_param".
 * @check_duplicate: Callback function to find duplicated entry.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
int ccs_update_policy(struct ccs_acl_head *new_entry, const int size,
		      struct ccs_acl_param *param,
		      bool (*check_duplicate) (const struct ccs_acl_head *,
					       const struct ccs_acl_head *))
{
	int error = param->is_delete ? -ENOENT : -ENOMEM;
	struct ccs_acl_head *entry;
	struct list_head *list = param->list;
	if (mutex_lock_interruptible(&ccs_policy_lock))
		return -ENOMEM;
	list_for_each_entry_srcu(entry, list, list, &ccs_ss) {
		if (!check_duplicate(entry, new_entry))
			continue;
		entry->is_deleted = param->is_delete;
		error = 0;
		break;
	}
	if (error && !param->is_delete) {
		entry = ccs_commit_ok(new_entry, size);
		if (entry) {
			list_add_tail_rcu(&entry->list, list);
			error = 0;
		}
	}
	mutex_unlock(&ccs_policy_lock);
	return error;
}

/**
 * ccs_same_acl_head - Check for duplicated "struct ccs_acl_info" entry.
 *
 * @a: Pointer to "struct ccs_acl_info".
 * @b: Pointer to "struct ccs_acl_info".
 *
 * Returns true if @a == @b, false otherwise.
 */
static inline bool ccs_same_acl_head(const struct ccs_acl_info *a,
				     const struct ccs_acl_info *b)
{
	return a->type == b->type && a->cond == b->cond;
}

/**
 * ccs_update_domain - Update an entry for domain policy.
 *
 * @new_entry:       Pointer to "struct ccs_acl_info".
 * @size:            Size of @new_entry in bytes.
 * @param:           Pointer to "struct ccs_acl_param".
 * @check_duplicate: Callback function to find duplicated entry.
 * @merge_duplicate: Callback function to merge duplicated entry. Maybe NULL.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
int ccs_update_domain(struct ccs_acl_info *new_entry, const int size,
		      struct ccs_acl_param *param,
		      bool (*check_duplicate) (const struct ccs_acl_info *,
					       const struct ccs_acl_info *),
		      bool (*merge_duplicate) (struct ccs_acl_info *,
					       struct ccs_acl_info *,
					       const bool))
{
	const bool is_delete = param->is_delete;
	int error = is_delete ? -ENOENT : -ENOMEM;
	struct ccs_acl_info *entry;
	const u8 type = new_entry->type;
	struct list_head * const list = &param->list
		[type == CCS_TYPE_AUTO_EXECUTE_HANDLER ||
		 type == CCS_TYPE_DENIED_EXECUTE_HANDLER ||
		 type == CCS_TYPE_AUTO_TASK_ACL];
	if (param->data[0]) {
		new_entry->cond = ccs_get_condition(param);
		if (!new_entry->cond)
			return -EINVAL;
	}
	if (mutex_lock_interruptible(&ccs_policy_lock))
		goto out;
	list_for_each_entry_srcu(entry, list, list, &ccs_ss) {
		if (!ccs_same_acl_head(entry, new_entry) ||
		    !check_duplicate(entry, new_entry))
			continue;
		if (merge_duplicate)
			entry->is_deleted = merge_duplicate(entry, new_entry,
							    is_delete);
		else
			entry->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (error && !is_delete) {
		entry = ccs_commit_ok(new_entry, size);
		if (entry) {
			list_add_tail_rcu(&entry->list, list);
			error = 0;
		}
	}
	mutex_unlock(&ccs_policy_lock);
out:
	ccs_put_condition(new_entry->cond);
	return error;
}

/**
 * ccs_check_acl - Do permission check.
 *
 * @r:           Pointer to "struct ccs_request_info".
 * @check_entry: Callback function to check type specific parameters.
 *               Maybe NULL.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
void ccs_check_acl(struct ccs_request_info *r,
		   bool (*check_entry) (struct ccs_request_info *,
					const struct ccs_acl_info *))
{
	const struct ccs_domain_info *domain = ccs_current_domain();
	struct ccs_acl_info *ptr;
	bool retried = false;
	const u8 i = !check_entry;
	const struct list_head *list = &domain->acl_info_list[i];
retry:
	list_for_each_entry_srcu(ptr, list, list, &ccs_ss) {
		if (ptr->is_deleted)
			continue;
		if (ptr->type != r->param_type)
			continue;
		if (check_entry && !check_entry(r, ptr))
			continue;
		if (!ccs_condition(r, ptr->cond))
			continue;
		r->matched_acl = ptr;
		r->granted = true;
		return;
	}
	if (!retried) {
		retried = true;
		list = &r->ns->acl_group[domain->group][i];
		goto retry;
	}
	r->granted = false;
}

/**
 * ccs_same_transition_control - Check for duplicated "struct ccs_transition_control" entry.
 *
 * @a: Pointer to "struct ccs_acl_head".
 * @b: Pointer to "struct ccs_acl_head".
 *
 * Returns true if @a == @b, false otherwise.
 */
static bool ccs_same_transition_control(const struct ccs_acl_head *a,
					const struct ccs_acl_head *b)
{
	const struct ccs_transition_control *p1 = container_of(a, typeof(*p1),
							       head);
	const struct ccs_transition_control *p2 = container_of(b, typeof(*p2),
							       head);
	return p1->type == p2->type && p1->is_last_name == p2->is_last_name
		&& p1->domainname == p2->domainname
		&& p1->program == p2->program;
}

/**
 * ccs_write_transition_control - Write "struct ccs_transition_control" list.
 *
 * @param: Pointer to "struct ccs_acl_param".
 * @type:  Type of this entry.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_transition_control(struct ccs_acl_param *param, const u8 type)
{
	struct ccs_transition_control e = { .type = type };
	int error = param->is_delete ? -ENOENT : -ENOMEM;
	char *program = param->data;
	char *domainname = strstr(program, " from ");
	if (domainname) {
		*domainname = '\0';
		domainname += 6;
	} else if (type == CCS_TRANSITION_CONTROL_NO_KEEP ||
		   type == CCS_TRANSITION_CONTROL_KEEP) {
		domainname = program;
		program = NULL;
	}
	if (program && strcmp(program, "any")) {
		if (!ccs_correct_path(program))
			return -EINVAL;
		e.program = ccs_get_name(program);
		if (!e.program)
			goto out;
	}
	if (domainname && strcmp(domainname, "any")) {
		if (!ccs_correct_domain(domainname)) {
			if (!ccs_correct_path(domainname))
				goto out;
			e.is_last_name = true;
		}
		e.domainname = ccs_get_name(domainname);
		if (!e.domainname)
			goto out;
	}
	param->list = &param->ns->policy_list[CCS_ID_TRANSITION_CONTROL];
	error = ccs_update_policy(&e.head, sizeof(e), param,
				  ccs_same_transition_control);
out:
	ccs_put_name(e.domainname);
	ccs_put_name(e.program);
	return error;
}

/**
 * ccs_last_word - Get last component of a domainname.
 *
 * @name: Domainname to check.
 *
 * Returns the last word of @name.
 */
static const char *ccs_last_word(const char *name)
{
	const char *cp = strrchr(name, ' ');
	if (cp)
		return cp + 1;
	return name;
}

/**
 * ccs_scan_transition - Try to find specific domain transition type.
 *
 * @list:       Pointer to "struct list_head".
 * @domainname: The name of current domain.
 * @program:    The name of requested program.
 * @last:       The last component of @domainname.
 * @type:       One of values in "enum ccs_transition_type".
 *
 * Returns true if found one, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static inline bool ccs_scan_transition(const struct list_head *list,
				       const struct ccs_path_info *domainname,
				       const struct ccs_path_info *program,
				       const char *last_name,
				       const enum ccs_transition_type type)
{
	const struct ccs_transition_control *ptr;
	list_for_each_entry_srcu(ptr, list, head.list, &ccs_ss) {
		if (ptr->head.is_deleted || ptr->type != type)
			continue;
		if (ptr->domainname) {
			if (!ptr->is_last_name) {
				if (ptr->domainname != domainname)
					continue;
			} else {
				/*
				 * Use direct strcmp() since this is
				 * unlikely used.
				 */
				if (strcmp(ptr->domainname->name, last_name))
					continue;
			}
		}
		if (ptr->program && ccs_pathcmp(ptr->program, program))
			continue;
		return true;
	}
	return false;
}

/**
 * ccs_transition_type - Get domain transition type.
 *
 * @ns:         Pointer to "struct ccs_policy_namespace".
 * @domainname: The name of current domain.
 * @program:    The name of requested program.
 *
 * Returns CCS_TRANSITION_CONTROL_TRANSIT if executing @program causes domain
 * transition across namespaces, CCS_TRANSITION_CONTROL_INITIALIZE if executing
 * @program reinitializes domain transition within that namespace,
 * CCS_TRANSITION_CONTROL_KEEP if executing @program stays at @domainname ,
 * others otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static enum ccs_transition_type ccs_transition_type
(const struct ccs_policy_namespace *ns, const struct ccs_path_info *domainname,
 const struct ccs_path_info *program)
{
	const char *last_name = ccs_last_word(domainname->name);
	enum ccs_transition_type type = CCS_TRANSITION_CONTROL_NO_RESET;
	while (type < CCS_MAX_TRANSITION_TYPE) {
		const struct list_head * const list =
			&ns->policy_list[CCS_ID_TRANSITION_CONTROL];
		if (!ccs_scan_transition(list, domainname, program, last_name,
					 type)) {
			type++;
			continue;
		}
		if (type != CCS_TRANSITION_CONTROL_NO_RESET &&
		    type != CCS_TRANSITION_CONTROL_NO_INITIALIZE)
			break;
		/*
		 * Do not check for reset_domain if no_reset_domain matched.
		 * Do not check for initialize_domain if no_initialize_domain
		 * matched.
		 */
		type++;
		type++;
	}
	return type;
}

/**
 * ccs_same_aggregator - Check for duplicated "struct ccs_aggregator" entry.
 *
 * @a: Pointer to "struct ccs_acl_head".
 * @b: Pointer to "struct ccs_acl_head".
 *
 * Returns true if @a == @b, false otherwise.
 */
static bool ccs_same_aggregator(const struct ccs_acl_head *a,
				const struct ccs_acl_head *b)
{
	const struct ccs_aggregator *p1 = container_of(a, typeof(*p1), head);
	const struct ccs_aggregator *p2 = container_of(b, typeof(*p2), head);
	return p1->original_name == p2->original_name &&
		p1->aggregated_name == p2->aggregated_name;
}

/**
 * ccs_write_aggregator - Write "struct ccs_aggregator" list.
 *
 * @param: Pointer to "struct ccs_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_aggregator(struct ccs_acl_param *param)
{
	struct ccs_aggregator e = { };
	int error = param->is_delete ? -ENOENT : -ENOMEM;
	const char *original_name = ccs_read_token(param);
	const char *aggregated_name = ccs_read_token(param);
	if (!ccs_correct_word(original_name) ||
	    !ccs_correct_path(aggregated_name))
		return -EINVAL;
	e.original_name = ccs_get_name(original_name);
	e.aggregated_name = ccs_get_name(aggregated_name);
	if (!e.original_name || !e.aggregated_name ||
	    e.aggregated_name->is_patterned) /* No patterns allowed. */
		goto out;
	param->list = &param->ns->policy_list[CCS_ID_AGGREGATOR];
	error = ccs_update_policy(&e.head, sizeof(e), param,
				  ccs_same_aggregator);
out:
	ccs_put_name(e.original_name);
	ccs_put_name(e.aggregated_name);
	return error;
}

/* Domain create handler. */

/**
 * ccs_find_namespace - Find specified namespace.
 *
 * @name: Name of namespace to find.
 * @len:  Length of @name.
 *
 * Returns pointer to "struct ccs_policy_namespace" if found, NULL otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static struct ccs_policy_namespace *ccs_find_namespace(const char *name,
						       const unsigned int len)
{
	struct ccs_policy_namespace *ns;
	list_for_each_entry_srcu(ns, &ccs_namespace_list, namespace_list,
				 &ccs_ss) {
		if (strncmp(name, ns->name, len) ||
		    (name[len] && name[len] != ' '))
			continue;
		return ns;
	}
	return NULL;
}


/**
 * ccs_assign_namespace - Create a new namespace.
 *
 * @domainname: Name of namespace to create.
 *
 * Returns pointer to "struct ccs_policy_namespace" on success, NULL otherwise.
 *
 * Caller holds ccs_read_lock().
 */
struct ccs_policy_namespace *ccs_assign_namespace(const char *domainname)
{
	struct ccs_policy_namespace *ptr;
	struct ccs_policy_namespace *entry;
	const char *cp = domainname;
	unsigned int len = 0;
	while (*cp && *cp++ != ' ')
		len++;
	ptr = ccs_find_namespace(domainname, len);
	if (ptr)
		return ptr;
	if (len >= CCS_EXEC_TMPSIZE - 10 || !ccs_domain_def(domainname))
		return NULL;
	entry = kzalloc(sizeof(*entry) + len + 1, CCS_GFP_FLAGS);
	if (!entry)
		return NULL;
	if (mutex_lock_interruptible(&ccs_policy_lock))
		goto out;
	ptr = ccs_find_namespace(domainname, len);
	if (!ptr && ccs_memory_ok(entry, sizeof(*entry) + len + 1)) {
		char *name = (char *) (entry + 1);
		ptr = entry;
		memmove(name, domainname, len);
		name[len] = '\0';
		entry->name = name;
		ccs_init_policy_namespace(entry);
		entry = NULL;
	}
	mutex_unlock(&ccs_policy_lock);
out:
	kfree(entry);
	return ptr;
}

/**
 * ccs_namespace_jump - Check for namespace jump.
 *
 * @domainname: Name of domain.
 *
 * Returns true if namespace differs, false otherwise.
 */
static bool ccs_namespace_jump(const char *domainname)
{
	const char *namespace = ccs_current_namespace()->name;
	const int len = strlen(namespace);
	return strncmp(domainname, namespace, len) ||
		(domainname[len] && domainname[len] != ' ');
}

/**
 * ccs_assign_domain - Create a domain or a namespace.
 *
 * @domainname: The name of domain.
 * @transit:    True if transit to domain found or created.
 *
 * Returns pointer to "struct ccs_domain_info" on success, NULL otherwise.
 *
 * Caller holds ccs_read_lock().
 */
struct ccs_domain_info *ccs_assign_domain(const char *domainname,
					  const bool transit)
{
	struct ccs_security *security = ccs_current_security();
	struct ccs_domain_info e = { };
	struct ccs_domain_info *entry = ccs_find_domain(domainname);
	bool created = false;
	if (entry) {
		if (transit) {
			/*
			 * Since namespace is created at runtime, profiles may
			 * not be created by the moment the process transits to
			 * that domain. Do not perform domain transition if
			 * profile for that domain is not yet created.
			 */
			if (!entry->ns->profile_ptr[entry->profile])
				return NULL;
			security->ccs_domain_info = entry;
		}
		return entry;
	}
	/* Requested domain does not exist. */
	/* Don't create requested domain if domainname is invalid. */
	if (strlen(domainname) >= CCS_EXEC_TMPSIZE - 10 ||
	    !ccs_correct_domain(domainname))
		return NULL;
	/*
	 * Since definition of profiles and acl_groups may differ across
	 * namespaces, do not inherit "use_profile" and "use_group" settings
	 * by automatically creating requested domain upon domain transition.
	 */
	if (transit && ccs_namespace_jump(domainname))
		return NULL;
	e.ns = ccs_assign_namespace(domainname);
	if (!e.ns)
		return NULL;
	/*
	 * "use_profile" and "use_group" settings for automatically created
	 * domains are inherited from current domain. These are 0 for manually
	 * created domains.
	 */
	if (transit) {
		const struct ccs_domain_info *domain =
			security->ccs_domain_info;
		e.profile = domain->profile;
		e.group = domain->group;
	}
	e.domainname = ccs_get_name(domainname);
	if (!e.domainname)
		return NULL;
	if (mutex_lock_interruptible(&ccs_policy_lock))
		goto out;
	entry = ccs_find_domain(domainname);
	if (!entry) {
		entry = ccs_commit_ok(&e, sizeof(e));
		if (entry) {
			INIT_LIST_HEAD(&entry->acl_info_list[0]);
			INIT_LIST_HEAD(&entry->acl_info_list[1]);
			list_add_tail_rcu(&entry->list, &ccs_domain_list);
			created = true;
		}
	}
	mutex_unlock(&ccs_policy_lock);
out:
	ccs_put_name(e.domainname);
	if (entry && transit) {
		security->ccs_domain_info = entry;
		if (created) {
			struct ccs_request_info r;
			ccs_init_request_info(&r, CCS_MAC_FILE_EXECUTE);
			r.granted = false;
			ccs_write_log(&r, "use_profile %u\n", entry->profile);
			ccs_write_log(&r, "use_group %u\n", entry->group);
			ccs_update_stat(CCS_STAT_POLICY_UPDATES);
		}
	}
	return entry;
}

/**
 * ccs_find_next_domain - Find a domain.
 *
 * @ee: Pointer to "struct ccs_execve".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_find_next_domain(struct ccs_execve *ee)
{
	struct ccs_request_info *r = &ee->r;
	const struct ccs_path_info *handler = ee->handler;
	struct ccs_domain_info *domain = NULL;
	struct ccs_domain_info * const old_domain = ccs_current_domain();
	struct linux_binprm *bprm = ee->bprm;
	struct ccs_security *task = ccs_current_security();
	struct ccs_path_info rn = { }; /* real name */
	int retval;
	bool need_kfree = false;
	bool reject_on_transition_failure = false;
retry:
	r->matched_acl = NULL;
	if (need_kfree) {
		kfree(rn.name);
		need_kfree = false;
	}

	/* Get symlink's pathname of program. */
	retval = ccs_symlink_path(bprm->filename, &rn);
	if (retval < 0)
		goto out;
	need_kfree = true;

	if (handler) {
		if (ccs_pathcmp(&rn, handler)) {
			/* Failed to verify execute handler. */
			static u8 counter = 20;
			if (counter) {
				counter--;
				printk(KERN_WARNING "Failed to verify: %s\n",
				       handler->name);
			}
			goto out;
		}
	} else {
		struct ccs_aggregator *ptr;
		struct list_head *list =
			&r->ns->policy_list[CCS_ID_AGGREGATOR];
		/* Check 'aggregator' directive. */
		list_for_each_entry_srcu(ptr, list, head.list, &ccs_ss) {
			if (ptr->head.is_deleted ||
			    !ccs_path_matches_pattern(&rn, ptr->original_name))
				continue;
			kfree(rn.name);
			need_kfree = false;
			/* This is OK because it is read only. */
			rn = *ptr->aggregated_name;
			break;
		}

		/* Check execute permission. */
		retval = ccs_path_permission(r, CCS_TYPE_EXECUTE, &rn);
		if (retval == CCS_RETRY_REQUEST)
			goto retry;
		if (retval < 0)
			goto out;
		/*
		 * To be able to specify domainnames with wildcards, use the
		 * pathname specified in the policy (which may contain
		 * wildcard) rather than the pathname passed to execve()
		 * (which never contains wildcard).
		 */
		if (r->param.path.matched_path) {
			if (need_kfree)
				kfree(rn.name);
			need_kfree = false;
			/* This is OK because it is read only. */
			rn = *r->param.path.matched_path;
		}
	}

	/* Calculate domain to transit to. */
	switch (ccs_transition_type(r->ns, old_domain->domainname, &rn)) {
	case CCS_TRANSITION_CONTROL_RESET:
		/* Transit to the root of specified namespace. */
		snprintf(ee->tmp, CCS_EXEC_TMPSIZE - 1, "<%s>", rn.name);
		/*
		 * Make do_execve() fail if domain transition across namespaces
		 * has failed.
		 */
		reject_on_transition_failure = true;
		break;
	case CCS_TRANSITION_CONTROL_INITIALIZE:
		/* Transit to the child of current namespace's root. */
		snprintf(ee->tmp, CCS_EXEC_TMPSIZE - 1, "%s %s", r->ns->name,
			 rn.name);
		break;
	case CCS_TRANSITION_CONTROL_KEEP:
		/* Keep current domain. */
		domain = old_domain;
		break;
	default:
		if (old_domain == &ccs_kernel_domain && !ccs_policy_loaded) {
			/*
			 * Needn't to transit from kernel domain before
			 * starting /sbin/init. But transit from kernel domain
			 * if executing initializers because they might start
			 * before /sbin/init.
			 */
			domain = old_domain;
		} else {
			/* Normal domain transition. */
			snprintf(ee->tmp, CCS_EXEC_TMPSIZE - 1, "%s %s",
				 old_domain->domainname->name, rn.name);
		}
		break;
	}
	/*
	 * Tell GC that I started execve().
	 * Also, tell open_exec() to check read permission.
	 */
	task->ccs_flags |= CCS_TASK_IS_IN_EXECVE;
	/*
	 * Make task->ccs_flags visible to GC before changing
	 * task->ccs_domain_info.
	 */
	smp_wmb();
	/*
	 * Proceed to the next domain in order to allow reaching via PID.
	 * It will be reverted if execve() failed. Reverting is not good.
	 * But it is better than being unable to reach via PID in interactive
	 * enforcing mode.
	 */
	if (!domain)
		domain = ccs_assign_domain(ee->tmp, true);
	if (domain)
		retval = 0;
	else if (reject_on_transition_failure) {
		printk(KERN_WARNING
		       "ERROR: Domain '%s' not ready.\n", ee->tmp);
		retval = -ENOMEM;
	} else if (r->mode == CCS_CONFIG_ENFORCING)
		retval = -ENOMEM;
	else {
		retval = 0;
		if (!old_domain->flags[CCS_DIF_TRANSITION_FAILED]) {
			old_domain->flags[CCS_DIF_TRANSITION_FAILED] = true;
			r->granted = false;
			ccs_write_log(r, "%s",
				      ccs_dif[CCS_DIF_TRANSITION_FAILED]);
			printk(KERN_WARNING
			       "ERROR: Domain '%s' not defined.\n", ee->tmp);
		}
	}
out:
	if (need_kfree)
		kfree(rn.name);
	return retval;
}

/**
 * ccs_environ - Check permission for environment variable names.
 *
 * @ee: Pointer to "struct ccs_execve".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_environ(struct ccs_execve *ee)
{
	struct ccs_request_info *r = &ee->r;
	struct linux_binprm *bprm = ee->bprm;
	/* env_page->data is allocated by ccs_dump_page(). */
	struct ccs_page_dump env_page = { };
	char *arg_ptr; /* Size is CCS_EXEC_TMPSIZE bytes */
	int arg_len = 0;
	unsigned long pos = bprm->p;
	int offset = pos % PAGE_SIZE;
	int argv_count = bprm->argc;
	int envp_count = bprm->envc;
	/* printk(KERN_DEBUG "start %d %d\n", argv_count, envp_count); */
	int error = -ENOMEM;
	ee->r.type = CCS_MAC_ENVIRON;
	ee->r.profile = ccs_current_domain()->profile;
	ee->r.mode = ccs_get_mode(ee->r.profile, CCS_MAC_ENVIRON);
	if (!r->mode || !envp_count)
		return 0;
	arg_ptr = kzalloc(CCS_EXEC_TMPSIZE, CCS_GFP_FLAGS);
	if (!arg_ptr)
		goto out;
	while (error == -ENOMEM) {
		if (!ccs_dump_page(bprm, pos, &env_page))
			goto out;
		pos += PAGE_SIZE - offset;
		/* Read. */
		while (argv_count && offset < PAGE_SIZE) {
			if (!env_page.data[offset++])
				argv_count--;
		}
		if (argv_count) {
			offset = 0;
			continue;
		}
		while (offset < PAGE_SIZE) {
			const unsigned char c = env_page.data[offset++];
			if (c && arg_len < CCS_EXEC_TMPSIZE - 10) {
				if (c == '=') {
					arg_ptr[arg_len++] = '\0';
				} else if (c == '\\') {
					arg_ptr[arg_len++] = '\\';
					arg_ptr[arg_len++] = '\\';
				} else if (c > ' ' && c < 127) {
					arg_ptr[arg_len++] = c;
				} else {
					arg_ptr[arg_len++] = '\\';
					arg_ptr[arg_len++] = (c >> 6) + '0';
					arg_ptr[arg_len++]
						= ((c >> 3) & 7) + '0';
					arg_ptr[arg_len++] = (c & 7) + '0';
				}
			} else {
				arg_ptr[arg_len] = '\0';
			}
			if (c)
				continue;
			if (ccs_env_perm(r, arg_ptr)) {
				error = -EPERM;
				break;
			}
			if (!--envp_count) {
				error = 0;
				break;
			}
			arg_len = 0;
		}
		offset = 0;
	}
out:
	if (r->mode != 3)
		error = 0;
	kfree(env_page.data);
	kfree(arg_ptr);
	return error;
}

/**
 * ccs_unescape - Unescape escaped string.
 *
 * @dest: String to unescape.
 *
 * Returns nothing.
 */
static void ccs_unescape(unsigned char *dest)
{
	unsigned char *src = dest;
	unsigned char c;
	unsigned char d;
	unsigned char e;
	while (1) {
		c = *src++;
		if (!c)
			break;
		if (c != '\\') {
			*dest++ = c;
			continue;
		}
		c = *src++;
		if (c == '\\') {
			*dest++ = c;
			continue;
		}
		if (c < '0' || c > '3')
			break;
		d = *src++;
		if (d < '0' || d > '7')
			break;
		e = *src++;
		if (e < '0' || e > '7')
			break;
		*dest++ = ((c - '0') << 6) + ((d - '0') << 3) + (e - '0');
	}
	*dest = '\0';
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)

/**
 * ccs_copy_argv - Wrapper for copy_strings_kernel().
 *
 * @arg:  String to copy.
 * @bprm: Pointer to "struct linux_binprm".
 *
 * Returns return value of copy_strings_kernel().
 */
static int ccs_copy_argv(const char *arg, struct linux_binprm *bprm)
{
	const int ret = copy_strings_kernel(1, &arg, bprm);
	if (ret >= 0)
		bprm->argc++;
	return ret;
}

#else

/**
 * ccs_copy_argv - Wrapper for copy_strings_kernel().
 *
 * @arg:  String to copy.
 * @bprm: Pointer to "struct linux_binprm".
 *
 * Returns return value of copy_strings_kernel().
 */
static int ccs_copy_argv(char *arg, struct linux_binprm *bprm)
{
	const int ret = copy_strings_kernel(1, &arg, bprm);
	if (ret >= 0)
		bprm->argc++;
	return ret;
}

#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 35)

/**
 * get_fs_root - Get reference on root directory.
 *
 * @fs:   Pointer to "struct fs_struct".
 * @root: Pointer to "struct path".
 *
 * Returns nothing.
 *
 * This is for compatibility with older kernels.
 */
static inline void get_fs_root(struct fs_struct *fs, struct path *root)
{
	read_lock(&fs->lock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
	*root = fs->root;
	path_get(root);
#else
	root->dentry = dget(fs->root);
	root->mnt = mntget(fs->rootmnt);
#endif
	read_unlock(&fs->lock);
}

#endif

/**
 * ccs_try_alt_exec - Try to start execute handler.
 *
 * @ee: Pointer to "struct ccs_execve".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_try_alt_exec(struct ccs_execve *ee)
{
	/*
	 * Contents of modified bprm.
	 * The envp[] in original bprm is moved to argv[] so that
	 * the alternatively executed program won't be affected by
	 * some dangerous environment variables like LD_PRELOAD.
	 *
	 * modified bprm->argc
	 *    = original bprm->argc + original bprm->envc + 7
	 * modified bprm->envc
	 *    = 0
	 *
	 * modified bprm->argv[0]
	 *    = the program's name specified by *_execute_handler
	 * modified bprm->argv[1]
	 *    = ccs_current_domain()->domainname->name
	 * modified bprm->argv[2]
	 *    = the current process's name
	 * modified bprm->argv[3]
	 *    = the current process's information (e.g. uid/gid).
	 * modified bprm->argv[4]
	 *    = original bprm->filename
	 * modified bprm->argv[5]
	 *    = original bprm->argc in string expression
	 * modified bprm->argv[6]
	 *    = original bprm->envc in string expression
	 * modified bprm->argv[7]
	 *    = original bprm->argv[0]
	 *  ...
	 * modified bprm->argv[bprm->argc + 6]
	 *     = original bprm->argv[bprm->argc - 1]
	 * modified bprm->argv[bprm->argc + 7]
	 *     = original bprm->envp[0]
	 *  ...
	 * modified bprm->argv[bprm->envc + bprm->argc + 6]
	 *     = original bprm->envp[bprm->envc - 1]
	 */
	struct linux_binprm *bprm = ee->bprm;
	struct file *filp;
	int retval;
	const int original_argc = bprm->argc;
	const int original_envc = bprm->envc;

	/* Close the requested program's dentry. */
	ee->obj.path1.dentry = NULL;
	ee->obj.path1.mnt = NULL;
	ee->obj.validate_done = false;
	allow_write_access(bprm->file);
	fput(bprm->file);
	bprm->file = NULL;

	/* Invalidate page dump cache. */
	ee->dump.page = NULL;

	/* Move envp[] to argv[] */
	bprm->argc += bprm->envc;
	bprm->envc = 0;

	/* Set argv[6] */
	{
		snprintf(ee->tmp, CCS_EXEC_TMPSIZE - 1, "%d", original_envc);
		retval = ccs_copy_argv(ee->tmp, bprm);
		if (retval < 0)
			goto out;
	}

	/* Set argv[5] */
	{
		snprintf(ee->tmp, CCS_EXEC_TMPSIZE - 1, "%d", original_argc);
		retval = ccs_copy_argv(ee->tmp, bprm);
		if (retval < 0)
			goto out;
	}

	/* Set argv[4] */
	{
		retval = ccs_copy_argv(bprm->filename, bprm);
		if (retval < 0)
			goto out;
	}

	/* Set argv[3] */
	{
		snprintf(ee->tmp, CCS_EXEC_TMPSIZE - 1,
			 "pid=%d uid=%d gid=%d euid=%d egid=%d suid=%d "
			 "sgid=%d fsuid=%d fsgid=%d", ccs_sys_getpid(),
			 current_uid(), current_gid(), current_euid(),
			 current_egid(), current_suid(), current_sgid(),
			 current_fsuid(), current_fsgid());
		retval = ccs_copy_argv(ee->tmp, bprm);
		if (retval < 0)
			goto out;
	}

	/* Set argv[2] */
	{
		char *exe = (char *) ccs_get_exe();
		if (exe) {
			retval = ccs_copy_argv(exe, bprm);
			kfree(exe);
		} else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
			retval = ccs_copy_argv("<unknown>", bprm);
#else
			snprintf(ee->tmp, CCS_EXEC_TMPSIZE - 1, "<unknown>");
			retval = ccs_copy_argv(ee->tmp, bprm);
#endif
		}
		if (retval < 0)
			goto out;
	}

	/* Set argv[1] */
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
		retval = ccs_copy_argv(ccs_current_domain()->domainname->name,
				       bprm);
#else
		snprintf(ee->tmp, CCS_EXEC_TMPSIZE - 1, "%s",
			 ccs_current_domain()->domainname->name);
		retval = ccs_copy_argv(ee->tmp, bprm);
#endif
		if (retval < 0)
			goto out;
	}

	/* Set argv[0] */
	{
		struct path root;
		char *cp;
		int root_len;
		int handler_len;
		get_fs_root(current->fs, &root);
		cp = ccs_realpath_from_path(&root);
		path_put(&root);
		if (!cp) {
			retval = -ENOMEM;
			goto out;
		}
		root_len = strlen(cp);
		retval = strncmp(ee->handler->name, cp, root_len);
		root_len--;
		kfree(cp);
		if (retval) {
			retval = -ENOENT;
			goto out;
		}
		handler_len = ee->handler->total_len + 1;
		cp = kmalloc(handler_len, CCS_GFP_FLAGS);
		if (!cp) {
			retval = -ENOMEM;
			goto out;
		}
		/* ee->handler_path is released by ccs_finish_execve(). */
		ee->handler_path = cp;
		/* Adjust root directory for open_exec(). */
		memmove(cp, ee->handler->name + root_len,
			handler_len - root_len);
		ccs_unescape(cp);
		retval = -ENOENT;
		if (*cp != '/')
			goto out;
		retval = ccs_copy_argv(cp, bprm);
		if (retval < 0)
			goto out;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 23)
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 24)
	bprm->argv_len = bprm->exec - bprm->p;
#endif
#endif

	/*
	 * OK, now restart the process with execute handler program's dentry.
	 */
	filp = open_exec(ee->handler_path);
	if (IS_ERR(filp)) {
		retval = PTR_ERR(filp);
		goto out;
	}
	ee->obj.path1.dentry = filp->f_dentry;
	ee->obj.path1.mnt = filp->f_vfsmnt;
	bprm->file = filp;
	bprm->filename = ee->handler_path;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
	bprm->interp = bprm->filename;
#endif
	retval = prepare_binprm(bprm);
	if (retval < 0)
		goto out;
	ee->r.dont_sleep_on_enforce_error = true;
	retval = ccs_find_next_domain(ee);
	ee->r.dont_sleep_on_enforce_error = false;
out:
	return retval;
}

/**
 * ccs_find_execute_handler - Find an execute handler.
 *
 * @ee:   Pointer to "struct ccs_execve".
 * @type: Type of execute handler.
 *
 * Returns true if found, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static bool ccs_find_execute_handler(struct ccs_execve *ee, const u8 type)
{
	struct ccs_request_info *r = &ee->r;
	/*
	 * To avoid infinite execute handler loop, don't use execute handler
	 * if the current process is marked as execute handler.
	 */
	if (ccs_current_flags() & CCS_TASK_IS_EXECUTE_HANDLER)
		return false;
	r->param_type = type;
	ccs_check_acl(r, NULL);
	if (!r->granted)
		return false;
	ee->handler = container_of(r->matched_acl, struct ccs_handler_acl,
				   head)->handler;
	return true;
}

#ifdef CONFIG_MMU
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 23)
#define CCS_BPRM_MMU
#elif defined(RHEL_MAJOR) && RHEL_MAJOR == 5
#define CCS_BPRM_MMU
#elif defined(AX_MAJOR) && AX_MAJOR == 3
#define CCS_BPRM_MMU
#endif
#endif

/**
 * ccs_dump_page - Dump a page to buffer.
 *
 * @bprm: Pointer to "struct linux_binprm".
 * @pos:  Location to dump.
 * @dump: Poiner to "struct ccs_page_dump".
 *
 * Returns true on success, false otherwise.
 */
bool ccs_dump_page(struct linux_binprm *bprm, unsigned long pos,
		   struct ccs_page_dump *dump)
{
	struct page *page;
	/* dump->data is released by ccs_finish_execve(). */
	if (!dump->data) {
		dump->data = kzalloc(PAGE_SIZE, CCS_GFP_FLAGS);
		if (!dump->data)
			return false;
	}
	/* Same with get_arg_page(bprm, pos, 0) in fs/exec.c */
#ifdef CCS_BPRM_MMU
	if (get_user_pages(current, bprm->mm, pos, 1, 0, 1, &page, NULL) <= 0)
		return false;
#else
	page = bprm->page[pos / PAGE_SIZE];
#endif
	if (page != dump->page) {
		const unsigned int offset = pos % PAGE_SIZE;
		/*
		 * Maybe kmap()/kunmap() should be used here.
		 * But remove_arg_zero() uses kmap_atomic()/kunmap_atomic().
		 * So do I.
		 */
		char *kaddr = kmap_atomic(page, KM_USER0);
		dump->page = page;
		memcpy(dump->data + offset, kaddr + offset,
		       PAGE_SIZE - offset);
		kunmap_atomic(kaddr, KM_USER0);
	}
	/* Same with put_arg_page(page) in fs/exec.c */
#ifdef CCS_BPRM_MMU
	put_page(page);
#endif
	return true;
}

/**
 * ccs_start_execve - Prepare for execve() operation.
 *
 * @bprm: Pointer to "struct linux_binprm".
 * @eep:  Pointer to "struct ccs_execve *".
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_start_execve(struct linux_binprm *bprm, struct ccs_execve **eep)
{
	int retval;
	struct ccs_security *task = ccs_current_security();
	struct ccs_execve *ee;
	*eep = NULL;
	ee = kzalloc(sizeof(*ee), CCS_GFP_FLAGS);
	if (!ee)
		return -ENOMEM;
	ee->tmp = kzalloc(CCS_EXEC_TMPSIZE, CCS_GFP_FLAGS);
	if (!ee->tmp) {
		kfree(ee);
		return -ENOMEM;
	}
	ee->reader_idx = ccs_read_lock();
	/* ee->dump->data is allocated by ccs_dump_page(). */
	ee->previous_domain = task->ccs_domain_info;
	/* Clear manager flag. */
	task->ccs_flags &= ~CCS_TASK_IS_MANAGER;
	*eep = ee;
	ccs_init_request_info(&ee->r, CCS_MAC_FILE_EXECUTE);
	ee->r.ee = ee;
	ee->bprm = bprm;
	ee->r.obj = &ee->obj;
	ee->obj.path1.dentry = bprm->file->f_dentry;
	ee->obj.path1.mnt = bprm->file->f_vfsmnt;
	/*
	 * No need to call ccs_environ() for execute handler because envp[] is
	 * moved to argv[].
	 */
	if (ccs_find_execute_handler(ee, CCS_TYPE_AUTO_EXECUTE_HANDLER))
		return ccs_try_alt_exec(ee);
	retval = ccs_find_next_domain(ee);
	if (retval == -EPERM) {
		if (ccs_find_execute_handler(ee,
					     CCS_TYPE_DENIED_EXECUTE_HANDLER))
			return ccs_try_alt_exec(ee);
	}
	if (!retval)
		retval = ccs_environ(ee);
	return retval;
}

/**
 * ccs_finish_execve - Clean up execve() operation.
 *
 * @retval: Return code of an execve() operation.
 * @ee:     Pointer to "struct ccs_execve".
 *
 * Returns nothing.
 *
 * Caller holds ccs_read_lock().
 */
void ccs_finish_execve(int retval, struct ccs_execve *ee)
{
	struct ccs_security *task = ccs_current_security();
	if (!ee)
		return;
	if (retval < 0) {
		task->ccs_domain_info = ee->previous_domain;
		/*
		 * Make task->ccs_domain_info visible to GC before changing
		 * task->ccs_flags.
		 */
		smp_wmb();
	} else {
		/* Mark the current process as execute handler. */
		if (ee->handler)
			task->ccs_flags |= CCS_TASK_IS_EXECUTE_HANDLER;
		/* Mark the current process as normal process. */
		else
			task->ccs_flags &= ~CCS_TASK_IS_EXECUTE_HANDLER;
	}
	/* Tell GC that I finished execve(). */
	task->ccs_flags &= ~CCS_TASK_IS_IN_EXECVE;
	ccs_read_unlock(ee->reader_idx);
	kfree(ee->handler_path);
	kfree(ee->tmp);
	kfree(ee->dump.data);
	kfree(ee);
}

/**
 * __ccs_search_binary_handler - Main routine for do_execve().
 *
 * @bprm: Pointer to "struct linux_binprm".
 * @regs: Pointer to "struct pt_regs".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Performs permission checks for do_execve() and domain transition.
 * Domain transition by "struct ccs_domain_transition_control" and
 * "auto_domain_transition=" parameter of "struct ccs_condition" are reverted
 * if do_execve() failed.
 * Garbage collector does not remove "struct ccs_domain_info" from
 * ccs_domain_list nor kfree("struct ccs_domain_info") if the current thread is
 * marked as CCS_TASK_IS_IN_EXECVE.
 */
static int __ccs_search_binary_handler(struct linux_binprm *bprm,
				       struct pt_regs *regs)
{
	struct ccs_execve *ee;
	int retval;
#ifndef CONFIG_CCSECURITY_OMIT_USERSPACE_LOADER
	if (!ccs_policy_loaded)
		ccsecurity_exports.load_policy(bprm->filename);
#endif
	retval = ccs_start_execve(bprm, &ee);
	if (!retval)
		retval = search_binary_handler(bprm, regs);
	ccs_finish_execve(retval, ee);
	return retval;
}

/**
 * ccs_domain_init - Register program execution hook.
 *
 * Returns nothing.
 */
void __init ccs_domain_init(void)
{
	ccsecurity_ops.search_binary_handler = __ccs_search_binary_handler;
}
