/*
 * security/ccsecurity/environ.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.2   2011/06/20
 */

#include "internal.h"

/**
 * ccs_check_env_acl - Check permission for environment variable's name.
 *
 * @r:   Pointer to "struct ccs_request_info".
 * @ptr: Pointer to "struct ccs_acl_info".
 *
 * Returns true if granted, false otherwise.
 */
static bool ccs_check_env_acl(struct ccs_request_info *r,
			      const struct ccs_acl_info *ptr)
{
	const struct ccs_env_acl *acl = container_of(ptr, typeof(*acl), head);
	return ccs_path_matches_pattern(r->param.environ.name, acl->env);
}

/**
 * ccs_audit_env_log - Audit environment variable name log.
 *
 * @r: Pointer to "struct ccs_request_info".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_env_log(struct ccs_request_info *r)
{
	return ccs_supervisor(r, "misc env %s\n", r->param.environ.name->name);
}

/**
 * ccs_env_perm - Check permission for environment variable's name.
 *
 * @r:   Pointer to "struct ccs_request_info".
 * @env: The name of environment variable.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
int ccs_env_perm(struct ccs_request_info *r, const char *env)
{
	struct ccs_path_info environ;
	int error;
	if (!env || !*env)
		return 0;
	environ.name = env;
	ccs_fill_path_info(&environ);
	r->param_type = CCS_TYPE_ENV_ACL;
	r->param.environ.name = &environ;
	do {
		ccs_check_acl(r, ccs_check_env_acl);
		error = ccs_audit_env_log(r);
	} while (error == CCS_RETRY_REQUEST);
	return error;
}

/**
 * ccs_same_env_acl - Check for duplicated "struct ccs_env_acl" entry.
 *
 * @a: Pointer to "struct ccs_acl_info".
 * @b: Pointer to "struct ccs_acl_info".
 *
 * Returns true if @a == @b, false otherwise.
 */
static bool ccs_same_env_acl(const struct ccs_acl_info *a,
			     const struct ccs_acl_info *b)
{
	const struct ccs_env_acl *p1 = container_of(a, typeof(*p1), head);
	const struct ccs_env_acl *p2 = container_of(b, typeof(*p2), head);
	return p1->env == p2->env;
}

/**
 * ccs_write_env - Write "struct ccs_env_acl" list.
 *
 * @param: Pointer to "struct ccs_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_write_env(struct ccs_acl_param *param)
{
	struct ccs_env_acl e = { .head.type = CCS_TYPE_ENV_ACL };
	int error = -ENOMEM;
	const char *data = ccs_read_token(param);
	if (!ccs_correct_word(data) || strchr(data, '='))
		return -EINVAL;
	e.env = ccs_get_name(data);
	if (!e.env)
		return error;
	error = ccs_update_domain(&e.head, sizeof(e), param,
				  ccs_same_env_acl, NULL);
	ccs_put_name(e.env);
	return error;
}

/**
 * ccs_write_misc - Update environment variable list.
 *
 * @param: Pointer to "struct ccs_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_misc(struct ccs_acl_param *param)
{
	if (ccs_str_starts(&param->data, "env "))
		return ccs_write_env(param);
	return -EINVAL;
}
