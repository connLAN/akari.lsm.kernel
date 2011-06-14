/*
 * security/ccsecurity/network.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.2-rc   2011/06/14
 */

#include "internal.h"

/* Structure for holding inet domain socket's address. */
struct ccs_inet_addr_info {
	u16 port;           /* In network byte order. */
	const u32 *address; /* In network byte order. */
	bool is_ipv6;
};

/* Structure for holding unix domain socket's address. */
struct ccs_unix_addr_info {
	u8 *addr; /* This may not be '\0' terminated string. */
	unsigned int addr_len;
};

/* Structure for holding socket address. */
struct ccs_addr_info {
	u8 protocol;
	u8 operation;
	struct ccs_inet_addr_info inet;
	struct ccs_unix_addr_info unix0;
};

/* String table for socket's protocols. */
const char * const ccs_proto_keyword[CCS_SOCK_MAX] = {
	[SOCK_STREAM]    = "stream",
	[SOCK_DGRAM]     = "dgram",
	[SOCK_RAW]       = "raw",
	[SOCK_SEQPACKET] = "seqpacket",
	[0] = " ", /* Dummy for avoiding NULL pointer dereference. */
	[4] = " ", /* Dummy for avoiding NULL pointer dereference. */
};

/**
 * ccs_parse_ipaddr_union - Parse an IP address.
 *
 * @param: Pointer to "struct ccs_acl_param".
 * @ptr:   Pointer to "struct ccs_ipaddr_union".
 *
 * Returns true on success, false otherwise.
 */
bool ccs_parse_ipaddr_union(struct ccs_acl_param *param,
			    struct ccs_ipaddr_union *ptr)
{
	u16 * const min = ptr->ip[0].s6_addr16;
	u16 * const max = ptr->ip[1].s6_addr16;
	char *address = ccs_read_token(param);
	int count = sscanf(address, "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx"
			   "-%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx",
			   &min[0], &min[1], &min[2], &min[3],
			   &min[4], &min[5], &min[6], &min[7],
			   &max[0], &max[1], &max[2], &max[3],
			   &max[4], &max[5], &max[6], &max[7]);
	if (count == 8 || count == 16) {
		u8 i;
		if (count == 8)
			memmove(max, min, sizeof(u16) * 8);
		for (i = 0; i < 8; i++) {
			min[i] = htons(min[i]);
			max[i] = htons(max[i]);
		}
		ptr->is_ipv6 = true;
		return true;
	}
	count = sscanf(address, "%hu.%hu.%hu.%hu-%hu.%hu.%hu.%hu",
		       &min[0], &min[1], &min[2], &min[3],
		       &max[0], &max[1], &max[2], &max[3]);
	if (count == 4 || count == 8) {
		/* use host byte order to allow u32 comparison.*/
		ptr->ip[0].s6_addr32[0] =
			(((u8) min[0]) << 24) + (((u8) min[1]) << 16)
			+ (((u8) min[2]) << 8) + (u8) min[3];
		if (count == 4)
			ptr->ip[1].s6_addr32[0] = ptr->ip[0].s6_addr32[0];
		else
			ptr->ip[1].s6_addr32[0] =
				(((u8) max[0]) << 24) + (((u8) max[1]) << 16)
				+ (((u8) max[2]) << 8) + (u8) max[3];
		ptr->is_ipv6 = false;
		return true;
	}
	return false;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
#if defined(__LITTLE_ENDIAN)
#define HIPQUAD(addr)				\
	((unsigned char *)&addr)[3],		\
		((unsigned char *)&addr)[2],	\
		((unsigned char *)&addr)[1],	\
		((unsigned char *)&addr)[0]
#elif defined(__BIG_ENDIAN)
#define HIPQUAD(addr)				\
	((unsigned char *)&addr)[0],		\
		((unsigned char *)&addr)[1],	\
		((unsigned char *)&addr)[2],	\
		((unsigned char *)&addr)[3]
#else
#error "Please fix asm/byteorder.h"
#endif /* __LITTLE_ENDIAN */
#endif

/**
 * ccs_print_ipv4 - Print an IPv4 address.
 *
 * @buffer:     Buffer to write to.
 * @buffer_len: Size of @buffer.
 * @min_ip:     Min address in host byte order.
 * @max_ip:     Max address in host byte order.
 *
 * Returns nothing.
 */
static void ccs_print_ipv4(char *buffer, const unsigned int buffer_len,
			   const u32 min_ip, const u32 max_ip)
{
	memset(buffer, 0, buffer_len);
	snprintf(buffer, buffer_len - 1, "%u.%u.%u.%u%c%u.%u.%u.%u",
		 HIPQUAD(min_ip), min_ip == max_ip ? '\0' : '-',
		 HIPQUAD(max_ip));
}

#if !defined(NIP6)

#define NIP6(addr)							\
	ntohs((addr).s6_addr16[0]), ntohs((addr).s6_addr16[1]),		\
		ntohs((addr).s6_addr16[2]), ntohs((addr).s6_addr16[3]), \
		ntohs((addr).s6_addr16[4]), ntohs((addr).s6_addr16[5]), \
		ntohs((addr).s6_addr16[6]), ntohs((addr).s6_addr16[7])

#endif

/**
 * ccs_print_ipv6 - Print an IPv6 address.
 *
 * @buffer:     Buffer to write to.
 * @buffer_len: Size of @buffer.
 * @min_ip:     Pointer to "struct in6_addr".
 * @max_ip:     Pointer to "struct in6_addr".
 *
 * Returns nothing.
 */
static void ccs_print_ipv6(char *buffer, const unsigned int buffer_len,
			   const struct in6_addr *min_ip,
			   const struct in6_addr *max_ip)
{
	memset(buffer, 0, buffer_len);
	snprintf(buffer, buffer_len - 1,
		 "%x:%x:%x:%x:%x:%x:%x:%x%c%x:%x:%x:%x:%x:%x:%x:%x",
		 NIP6(*min_ip), !memcmp(min_ip, max_ip, 16) ? '\0' : '-',
		 NIP6(*max_ip));
}

/**
 * ccs_print_ip - Print an IP address.
 *
 * @buf:  Buffer to write to.
 * @size: Size of @buf.
 * @ptr:  Pointer to "struct ipaddr_union".
 *
 * Returns nothing.
 */
void ccs_print_ip(char *buf, const unsigned int size,
		  const struct ccs_ipaddr_union *ptr)
{
	if (ptr->is_ipv6)
		ccs_print_ipv6(buf, size, &ptr->ip[0], &ptr->ip[1]);
	else
		ccs_print_ipv4(buf, size, ptr->ip[0].s6_addr32[0],
			       ptr->ip[1].s6_addr32[0]);
}

/*
 * Mapping table from "enum ccs_network_acl_index" to "enum ccs_mac_index" for
 * inet domain socket.
 */
static const u8 ccs_inet2mac[CCS_SOCK_MAX][CCS_MAX_NETWORK_OPERATION] = {
	[SOCK_STREAM] = {
		[CCS_NETWORK_BIND]    = CCS_MAC_NETWORK_INET_STREAM_BIND,
		[CCS_NETWORK_LISTEN]  = CCS_MAC_NETWORK_INET_STREAM_LISTEN,
		[CCS_NETWORK_CONNECT] = CCS_MAC_NETWORK_INET_STREAM_CONNECT,
		[CCS_NETWORK_ACCEPT]  = CCS_MAC_NETWORK_INET_STREAM_ACCEPT,
	},
	[SOCK_DGRAM] = {
		[CCS_NETWORK_BIND]    = CCS_MAC_NETWORK_INET_DGRAM_BIND,
		[CCS_NETWORK_SEND]    = CCS_MAC_NETWORK_INET_DGRAM_SEND,
		[CCS_NETWORK_RECV]    = CCS_MAC_NETWORK_INET_DGRAM_RECV,
	},
	[SOCK_RAW]    = {
		[CCS_NETWORK_BIND]    = CCS_MAC_NETWORK_INET_RAW_BIND,
		[CCS_NETWORK_SEND]    = CCS_MAC_NETWORK_INET_RAW_SEND,
		[CCS_NETWORK_RECV]    = CCS_MAC_NETWORK_INET_RAW_RECV,
	},
};

/*
 * Mapping table from "enum ccs_network_acl_index" to "enum ccs_mac_index" for
 * unix domain socket.
 */
static const u8 ccs_unix2mac[CCS_SOCK_MAX][CCS_MAX_NETWORK_OPERATION] = {
	[SOCK_STREAM] = {
		[CCS_NETWORK_BIND]    = CCS_MAC_NETWORK_UNIX_STREAM_BIND,
		[CCS_NETWORK_LISTEN]  = CCS_MAC_NETWORK_UNIX_STREAM_LISTEN,
		[CCS_NETWORK_CONNECT] = CCS_MAC_NETWORK_UNIX_STREAM_CONNECT,
		[CCS_NETWORK_ACCEPT]  = CCS_MAC_NETWORK_UNIX_STREAM_ACCEPT,
	},
	[SOCK_DGRAM] = {
		[CCS_NETWORK_BIND]    = CCS_MAC_NETWORK_UNIX_DGRAM_BIND,
		[CCS_NETWORK_SEND]    = CCS_MAC_NETWORK_UNIX_DGRAM_SEND,
		[CCS_NETWORK_RECV]    = CCS_MAC_NETWORK_UNIX_DGRAM_RECV,
	},
	[SOCK_SEQPACKET] = {
		[CCS_NETWORK_BIND]    = CCS_MAC_NETWORK_UNIX_SEQPACKET_BIND,
		[CCS_NETWORK_LISTEN]  = CCS_MAC_NETWORK_UNIX_SEQPACKET_LISTEN,
		[CCS_NETWORK_CONNECT] = CCS_MAC_NETWORK_UNIX_SEQPACKET_CONNECT,
		[CCS_NETWORK_ACCEPT]  = CCS_MAC_NETWORK_UNIX_SEQPACKET_ACCEPT,
	},
};

/**
 * ccs_same_inet_acl - Check for duplicated "struct ccs_inet_acl" entry.
 *
 * @a: Pointer to "struct ccs_acl_info".
 * @b: Pointer to "struct ccs_acl_info".
 *
 * Returns true if @a == @b except permission bits, false otherwise.
 */
static bool ccs_same_inet_acl(const struct ccs_acl_info *a,
			      const struct ccs_acl_info *b)
{
	const struct ccs_inet_acl *p1 = container_of(a, typeof(*p1), head);
	const struct ccs_inet_acl *p2 = container_of(b, typeof(*p2), head);
	return p1->protocol == p2->protocol &&
		ccs_same_ipaddr_union(&p1->address, &p2->address) &&
		ccs_same_number_union(&p1->port, &p2->port);
}

/**
 * ccs_same_unix_acl - Check for duplicated "struct ccs_unix_acl" entry.
 *
 * @a: Pointer to "struct ccs_acl_info".
 * @b: Pointer to "struct ccs_acl_info".
 *
 * Returns true if @a == @b except permission bits, false otherwise.
 */
static bool ccs_same_unix_acl(const struct ccs_acl_info *a,
			      const struct ccs_acl_info *b)
{
	const struct ccs_unix_acl *p1 = container_of(a, typeof(*p1), head);
	const struct ccs_unix_acl *p2 = container_of(b, typeof(*p2), head);
	return p1->protocol == p2->protocol &&
		ccs_same_name_union(&p1->name, &p2->name);
}

/**
 * ccs_merge_inet_acl - Merge duplicated "struct ccs_inet_acl" entry.
 *
 * @a:         Pointer to "struct ccs_acl_info".
 * @b:         Pointer to "struct ccs_acl_info".
 * @is_delete: True for @a &= ~@b, false for @a |= @b.
 *
 * Returns true if @a is empty, false otherwise.
 */
static bool ccs_merge_inet_acl(struct ccs_acl_info *a, struct ccs_acl_info *b,
			       const bool is_delete)
{
	u8 * const a_perm = &container_of(a, struct ccs_inet_acl, head)->perm;
	u8 perm = *a_perm;
	const u8 b_perm = container_of(b, struct ccs_inet_acl, head)->perm;
	if (is_delete)
		perm &= ~b_perm;
	else
		perm |= b_perm;
	*a_perm = perm;
	return !perm;
}

/**
 * ccs_merge_unix_acl - Merge duplicated "struct ccs_unix_acl" entry.
 *
 * @a:         Pointer to "struct ccs_acl_info".
 * @b:         Pointer to "struct ccs_acl_info".
 * @is_delete: True for @a &= ~@b, false for @a |= @b.
 *
 * Returns true if @a is empty, false otherwise.
 */
static bool ccs_merge_unix_acl(struct ccs_acl_info *a, struct ccs_acl_info *b,
			       const bool is_delete)
{
	u8 * const a_perm = &container_of(a, struct ccs_unix_acl, head)->perm;
	u8 perm = *a_perm;
	const u8 b_perm = container_of(b, struct ccs_unix_acl, head)->perm;
	if (is_delete)
		perm &= ~b_perm;
	else
		perm |= b_perm;
	*a_perm = perm;
	return !perm;
}

/**
 * ccs_write_inet_network - Write "struct ccs_inet_acl" list.
 *
 * @param: Pointer to "struct ccs_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
int ccs_write_inet_network(struct ccs_acl_param *param)
{
	struct ccs_inet_acl e = { .head.type = CCS_TYPE_INET_ACL };
	int error = -EINVAL;
	u8 type;
	const char *protocol = ccs_read_token(param);
	const char *operation = ccs_read_token(param);
	for (e.protocol = 0; e.protocol < CCS_SOCK_MAX; e.protocol++)
		if (!strcmp(protocol, ccs_proto_keyword[e.protocol]))
			break;
	for (type = 0; type < CCS_MAX_NETWORK_OPERATION; type++)
		if (ccs_permstr(operation, ccs_socket_keyword[type]))
			e.perm |= 1 << type;
	if (e.protocol == CCS_SOCK_MAX || !e.perm)
		return -EINVAL;
	if (param->data[0] == '@') {
		param->data++;
		e.address.group = ccs_get_group(param, CCS_ADDRESS_GROUP);
		if (!e.address.group)
			return -ENOMEM;
	} else {
		if (!ccs_parse_ipaddr_union(param, &e.address))
			goto out;
	}
	if (!ccs_parse_number_union(param, &e.port) ||
	    e.port.values[1] > 65535)
		goto out;
	error = ccs_update_domain(&e.head, sizeof(e), param, ccs_same_inet_acl,
				  ccs_merge_inet_acl);
out:
	ccs_put_group(e.address.group);
	ccs_put_number_union(&e.port);
	return error;
}

/**
 * ccs_write_unix_network - Write "struct ccs_unix_acl" list.
 *
 * @param: Pointer to "struct ccs_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_unix_network(struct ccs_acl_param *param)
{
	struct ccs_unix_acl e = { .head.type = CCS_TYPE_UNIX_ACL };
	int error;
	u8 type;
	const char *protocol = ccs_read_token(param);
	const char *operation = ccs_read_token(param);
	for (e.protocol = 0; e.protocol < CCS_SOCK_MAX; e.protocol++)
		if (!strcmp(protocol, ccs_proto_keyword[e.protocol]))
			break;
	for (type = 0; type < CCS_MAX_NETWORK_OPERATION; type++)
		if (ccs_permstr(operation, ccs_socket_keyword[type]))
			e.perm |= 1 << type;
	if (e.protocol == CCS_SOCK_MAX || !e.perm)
		return -EINVAL;
	if (!ccs_parse_name_union(param, &e.name))
		return -EINVAL;
	error = ccs_update_domain(&e.head, sizeof(e), param, ccs_same_unix_acl,
				  ccs_merge_unix_acl);
	ccs_put_name_union(&e.name);
	return error;
}

#ifndef CONFIG_NET

/**
 * ccs_network_init - Dummy initialize function for CONFIG_NET=n case.
 *
 * Returns nothing.
 */
void __init ccs_network_init(void)
{
}

#else

/**
 * ccs_audit_net_log - Audit network log.
 *
 * @r:         Pointer to "struct ccs_request_info".
 * @family:    Name of socket family ("inet" or "unix").
 * @protocol:  Name of protocol in @family.
 * @operation: Name of socket operation.
 * @address:   Name of address.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_net_log(struct ccs_request_info *r, const char *family,
			     const u8 protocol, const u8 operation,
			     const char *address)
{
	return ccs_supervisor(r, "network %s %s %s %s\n", family,
			      ccs_proto_keyword[protocol],
			      ccs_socket_keyword[operation], address);
}

/**
 * ccs_audit_inet_log - Audit INET network log.
 *
 * @r: Pointer to "struct ccs_request_info".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_inet_log(struct ccs_request_info *r)
{
	char buf[128];
	int len;
	const u32 *address = r->param.inet_network.address;
	if (r->param.inet_network.is_ipv6)
		ccs_print_ipv6(buf, sizeof(buf), (const struct in6_addr *)
			       address, (const struct in6_addr *) address);
	else
		ccs_print_ipv4(buf, sizeof(buf), r->param.inet_network.ip,
			       r->param.inet_network.ip);
	len = strlen(buf);
	snprintf(buf + len, sizeof(buf) - len, " %u",
		 r->param.inet_network.port);
	return ccs_audit_net_log(r, "inet", r->param.inet_network.protocol,
				 r->param.inet_network.operation, buf);
}

/**
 * ccs_audit_unix_log - Audit UNIX network log.
 *
 * @r: Pointer to "struct ccs_request_info".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_unix_log(struct ccs_request_info *r)
{
	return ccs_audit_net_log(r, "unix", r->param.unix_network.protocol,
				 r->param.unix_network.operation,
				 r->param.unix_network.address->name);
}

/**
 * ccs_check_inet_acl - Check permission for inet domain socket operation.
 *
 * @r:   Pointer to "struct ccs_request_info".
 * @ptr: Pointer to "struct ccs_acl_info".
 *
 * Returns true if granted, false otherwise.
 */
static bool ccs_check_inet_acl(struct ccs_request_info *r,
			       const struct ccs_acl_info *ptr)
{
	const struct ccs_inet_acl *acl = container_of(ptr, typeof(*acl), head);
	if (!(acl->perm & (1 << r->param.inet_network.operation)) ||
	    !ccs_compare_number_union(r->param.inet_network.port, &acl->port))
		return false;
	if (acl->address.group)
		return ccs_address_matches_group(r->param.inet_network.is_ipv6,
						 r->param.inet_network.address,
						 acl->address.group);
	else if (acl->address.is_ipv6)
		return r->param.inet_network.is_ipv6 &&
			memcmp(&acl->address.ip[0],
			       r->param.inet_network.address, 16) <= 0 &&
			memcmp(r->param.inet_network.address,
			       &acl->address.ip[1], 16) <= 0;
	else
		return !r->param.inet_network.is_ipv6 &&
			acl->address.ip[0].s6_addr32[0] <=
			r->param.inet_network.ip &&
			r->param.inet_network.ip <=
			acl->address.ip[1].s6_addr32[0];
}

/**
 * ccs_check_unix_acl - Check permission for unix domain socket operation.
 *
 * @r:   Pointer to "struct ccs_request_info".
 * @ptr: Pointer to "struct ccs_acl_info".
 *
 * Returns true if granted, false otherwise.
 */
static bool ccs_check_unix_acl(struct ccs_request_info *r,
			       const struct ccs_acl_info *ptr)
{
	const struct ccs_unix_acl *acl = container_of(ptr, typeof(*acl), head);
	return (acl->perm & (1 << r->param.unix_network.operation)) &&
		ccs_compare_name_union(r->param.unix_network.address,
				       &acl->name);
}

/**
 * ccs_inet_entry - Check permission for INET network operation.
 *
 * @address: Pointer to "struct ccs_addr_info".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inet_entry(const struct ccs_addr_info *address)
{
	const int idx = ccs_read_lock();
	struct ccs_request_info r;
	int error = 0;
	const u8 type = ccs_inet2mac[address->protocol][address->operation];
	if (type && ccs_init_request_info(&r, type) != CCS_CONFIG_DISABLED) {
		r.param_type = CCS_TYPE_INET_ACL;
		r.param.inet_network.protocol = address->protocol;
		r.param.inet_network.operation = address->operation;
		r.param.inet_network.is_ipv6 = address->inet.is_ipv6;
		r.param.inet_network.address = address->inet.address;
		r.param.inet_network.port = ntohs(address->inet.port);
		/*
		 * Use host byte order to allow u32 comparison than memcmp().
		 */
		r.param.inet_network.ip = ntohl(*address->inet.address);
		r.dont_sleep_on_enforce_error =
			address->operation == CCS_NETWORK_ACCEPT ||
			address->operation == CCS_NETWORK_RECV;
		do {
			ccs_check_acl(&r, ccs_check_inet_acl);
			error = ccs_audit_inet_log(&r);
		} while (error == CCS_RETRY_REQUEST);
	}
	ccs_read_unlock(idx);
	return error;
}

/**
 * ccs_check_inet_address - Check permission for inet domain socket's operation.
 *
 * @addr:     Pointer to "struct sockaddr".
 * @addr_len: Size of @addr.
 * @port:     Port number.
 * @address:  Pointer to "struct ccs_addr_info".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_check_inet_address(const struct sockaddr *addr,
				  const unsigned int addr_len, const u16 port,
				  struct ccs_addr_info *address)
{
	struct ccs_inet_addr_info *i = &address->inet;
	switch (addr->sa_family) {
	case AF_INET6:
		if (addr_len < SIN6_LEN_RFC2133)
			goto skip;
		i->is_ipv6 = true;
		i->address = (u32 *)
			((struct sockaddr_in6 *) addr)->sin6_addr.s6_addr;
		i->port = ((struct sockaddr_in6 *) addr)->sin6_port;
		break;
	case AF_INET:
		if (addr_len < sizeof(struct sockaddr_in))
			goto skip;
		i->is_ipv6 = false;
		i->address = (u32 *) &((struct sockaddr_in *) addr)->sin_addr;
		i->port = ((struct sockaddr_in *) addr)->sin_port;
		break;
	default:
		goto skip;
	}
	if (address->protocol == SOCK_RAW)
		i->port = htons(port);
	return ccs_inet_entry(address);
skip:
	return 0;
}

/**
 * ccs_unix_entry - Check permission for UNIX network operation.
 *
 * @address: Pointer to "struct ccs_addr_info".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_unix_entry(const struct ccs_addr_info *address)
{
	const int idx = ccs_read_lock();
	struct ccs_request_info r;
	int error = 0;
	const u8 type = ccs_unix2mac[address->protocol][address->operation];
	if (type && ccs_init_request_info(&r, type) != CCS_CONFIG_DISABLED) {
		char *buf = address->unix0.addr;
		int len = address->unix0.addr_len - sizeof(sa_family_t);
		if (len <= 0) {
			buf = "anonymous";
			len = 9;
		} else if (buf[0]) {
			len = strnlen(buf, len);
		}
		buf = ccs_encode2(buf, len);
		if (buf) {
			struct ccs_path_info addr;
			addr.name = buf;
			ccs_fill_path_info(&addr);
			r.param_type = CCS_TYPE_UNIX_ACL;
			r.param.unix_network.protocol = address->protocol;
			r.param.unix_network.operation = address->operation;
			r.param.unix_network.address = &addr;
			r.dont_sleep_on_enforce_error =
				address->operation == CCS_NETWORK_ACCEPT ||
				address->operation == CCS_NETWORK_RECV;
			do {
				ccs_check_acl(&r, ccs_check_unix_acl);
				error = ccs_audit_unix_log(&r);
			} while (error == CCS_RETRY_REQUEST);
			kfree(buf);
		} else
			error = -ENOMEM;
	}
	ccs_read_unlock(idx);
	return error;
}

/**
 * ccs_check_unix_address - Check permission for unix domain socket's operation.
 *
 * @addr:     Pointer to "struct sockaddr".
 * @addr_len: Size of @addr.
 * @address:  Pointer to "struct ccs_addr_info".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_check_unix_address(struct sockaddr *addr,
				  const unsigned int addr_len,
				  struct ccs_addr_info *address)
{
	struct ccs_unix_addr_info *u = &address->unix0;
	if (addr->sa_family != AF_UNIX)
		return 0;
	u->addr = ((struct sockaddr_un *) addr)->sun_path;
	u->addr_len = addr_len;
	return ccs_unix_entry(address);
}

/**
 * ccs_kernel_service - Check whether I'm kernel service or not.
 *
 * Returns true if I'm kernel service, false otherwise.
 */
static bool ccs_kernel_service(void)
{
	/* Nothing to do if I am a kernel service. */
	return segment_eq(get_fs(), KERNEL_DS);
}

/**
 * ccs_sock_family - Get socket's family.
 *
 * @sk: Pointer to "struct sock".
 *
 * Returns one of PF_INET, PF_INET6, PF_UNIX or 0.
 */
static u8 ccs_sock_family(struct sock *sk)
{
	u8 family;
	if (ccs_kernel_service())
		return 0;
	family = sk->sk_family;
	switch (family) {
	case PF_INET:
	case PF_INET6:
	case PF_UNIX:
		return family;
	default:
		return 0;
	}
}

/**
 * __ccs_socket_create_permission - Check permission for creating a socket.
 *
 * @family:   Protocol family.
 * @type:     Unused.
 * @protocol: Unused.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_socket_create_permission(int family, int type, int protocol)
{
	if (ccs_kernel_service())
		return 0;
	if (family == PF_PACKET && !ccs_capable(CCS_USE_PACKET_SOCKET))
		return -EPERM;
	if (family == PF_ROUTE && !ccs_capable(CCS_USE_ROUTE_SOCKET))
		return -EPERM;
	return 0;
}

/**
 * __ccs_socket_listen_permission - Check permission for listening a socket.
 *
 * @sock: Pointer to "struct socket".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_socket_listen_permission(struct socket *sock)
{
	struct ccs_addr_info address;
	const u8 family = ccs_sock_family(sock->sk);
	const unsigned int type = sock->type;
	struct sockaddr_storage addr;
	int addr_len;
	if (!family || (type != SOCK_STREAM && type != SOCK_SEQPACKET))
		return 0;
	{
		const int error = sock->ops->getname(sock, (struct sockaddr *)
						     &addr, &addr_len, 0);
		if (error)
			return error;
	}
	address.protocol = type;
	address.operation = CCS_NETWORK_LISTEN;
	if (family == PF_UNIX)
		return ccs_check_unix_address((struct sockaddr *) &addr,
					      addr_len, &address);
	return ccs_check_inet_address((struct sockaddr *) &addr, addr_len, 0,
				      &address);
}

/**
 * __ccs_socket_connect_permission - Check permission for setting the remote address of a socket.
 *
 * @sock:     Pointer to "struct socket".
 * @addr:     Pointer to "struct sockaddr".
 * @addr_len: Size of @addr.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_socket_connect_permission(struct socket *sock,
					   struct sockaddr *addr, int addr_len)
{
	struct ccs_addr_info address;
	const u8 family = ccs_sock_family(sock->sk);
	const unsigned int type = sock->type;
	if (!family)
		return 0;
	address.protocol = type;
	switch (type) {
	case SOCK_DGRAM:
	case SOCK_RAW:
		address.operation = CCS_NETWORK_SEND;
		break;
	case SOCK_STREAM:
	case SOCK_SEQPACKET:
		address.operation = CCS_NETWORK_CONNECT;
		break;
	default:
		return 0;
	}
	if (family == PF_UNIX)
		return ccs_check_unix_address(addr, addr_len, &address);
	return ccs_check_inet_address(addr, addr_len, sock->sk->sk_protocol,
				      &address);
}

/**
 * __ccs_socket_bind_permission - Check permission for setting the local address of a socket.
 *
 * @sock:     Pointer to "struct socket".
 * @addr:     Pointer to "struct sockaddr".
 * @addr_len: Size of @addr.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_socket_bind_permission(struct socket *sock,
					struct sockaddr *addr, int addr_len)
{
	struct ccs_addr_info address;
	const u8 family = ccs_sock_family(sock->sk);
	const unsigned int type = sock->type;
	if (!family)
		return 0;
	switch (type) {
	case SOCK_STREAM:
	case SOCK_DGRAM:
	case SOCK_RAW:
	case SOCK_SEQPACKET:
		address.protocol = type;
		address.operation = CCS_NETWORK_BIND;
		break;
	default:
		return 0;
	}
	if (family == PF_UNIX)
		return ccs_check_unix_address(addr, addr_len, &address);
	return ccs_check_inet_address(addr, addr_len, sock->sk->sk_protocol,
				      &address);
}

/**
 * __ccs_socket_sendmsg_permission - Check permission for sending a datagram.
 *
 * @sock: Pointer to "struct socket".
 * @msg:  Pointer to "struct msghdr".
 * @size: Unused.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_socket_sendmsg_permission(struct socket *sock,
					   struct msghdr *msg, int size)
{
	struct ccs_addr_info address;
	const u8 family = ccs_sock_family(sock->sk);
	const unsigned int type = sock->type;
	if (!msg->msg_name || !family ||
	    (type != SOCK_DGRAM && type != SOCK_RAW))
		return 0;
	address.protocol = type;
	address.operation = CCS_NETWORK_SEND;
	if (family == PF_UNIX)
		return ccs_check_unix_address((struct sockaddr *)
					      msg->msg_name, msg->msg_namelen,
					      &address);
	return ccs_check_inet_address((struct sockaddr *) msg->msg_name,
				      msg->msg_namelen, sock->sk->sk_protocol,
				      &address);
}

/**
 * __ccs_socket_post_accept_permission - Check permission for accepting a socket.
 *
 * @sock:    Pointer to "struct socket".
 * @newsock: Pointer to "struct socket".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_socket_post_accept_permission(struct socket *sock,
					       struct socket *newsock)
{
	struct ccs_addr_info address;
	const u8 family = ccs_sock_family(sock->sk);
	const unsigned int type = sock->type;
	struct sockaddr_storage addr;
	int addr_len;
	if (!family || (type != SOCK_STREAM && type != SOCK_SEQPACKET))
		return 0;
	{
		const int error = newsock->ops->getname(newsock,
							(struct sockaddr *)
							&addr, &addr_len, 2);
		if (error)
			return error;
	}
	address.protocol = type;
	address.operation = CCS_NETWORK_ACCEPT;
	if (family == PF_UNIX)
		return ccs_check_unix_address((struct sockaddr *) &addr,
					      addr_len, &address);
	return ccs_check_inet_address((struct sockaddr *) &addr, addr_len, 0,
				      &address);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 22)
#if !defined(RHEL_MAJOR) || RHEL_MAJOR != 5
#if !defined(AX_MAJOR) || AX_MAJOR != 3

/**
 * ip_hdr - Get "struct iphdr".
 *
 * @skb: Pointer to "struct sk_buff".
 *
 * Returns pointer to "struct iphdr".
 *
 * This is for compatibility with older kernels.
 */
static inline struct iphdr *ip_hdr(const struct sk_buff *skb)
{
	return skb->nh.iph;
}

/**
 * udp_hdr - Get "struct udphdr".
 *
 * @skb: Pointer to "struct sk_buff".
 *
 * Returns pointer to "struct udphdr".
 *
 * This is for compatibility with older kernels.
 */
static inline struct udphdr *udp_hdr(const struct sk_buff *skb)
{
	return skb->h.uh;
}

/**
 * ipv6_hdr - Get "struct ipv6hdr".
 *
 * @skb: Pointer to "struct sk_buff".
 *
 * Returns pointer to "struct ipv6hdr".
 *
 * This is for compatibility with older kernels.
 */
static inline struct ipv6hdr *ipv6_hdr(const struct sk_buff *skb)
{
	return skb->nh.ipv6h;
}

#endif
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)

/**
 * skb_kill_datagram - Kill a datagram forcibly.
 *
 * @sk:    Pointer to "struct sock".
 * @skb:   Pointer to "struct sk_buff".
 * @flags: Flags passed to skb_recv_datagram().
 *
 * Returns nothing.
 */
static inline void skb_kill_datagram(struct sock *sk, struct sk_buff *skb,
				     int flags)
{
	/* Clear queue. */
	if (flags & MSG_PEEK) {
		int clear = 0;
		spin_lock_irq(&sk->receive_queue.lock);
		if (skb == skb_peek(&sk->receive_queue)) {
			__skb_unlink(skb, &sk->receive_queue);
			clear = 1;
		}
		spin_unlock_irq(&sk->receive_queue.lock);
		if (clear)
			kfree_skb(skb);
	}
	skb_free_datagram(sk, skb);
}

#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 12)

/**
 * skb_kill_datagram - Kill a datagram forcibly.
 *
 * @sk:    Pointer to "struct sock".
 * @skb:   Pointer to "struct sk_buff".
 * @flags: Flags passed to skb_recv_datagram().
 *
 * Returns nothing.
 */
static inline void skb_kill_datagram(struct sock *sk, struct sk_buff *skb,
				     int flags)
{
	/* Clear queue. */
	if (flags & MSG_PEEK) {
		int clear = 0;
		spin_lock_irq(&sk->sk_receive_queue.lock);
		if (skb == skb_peek(&sk->sk_receive_queue)) {
			__skb_unlink(skb, &sk->sk_receive_queue);
			clear = 1;
		}
		spin_unlock_irq(&sk->sk_receive_queue.lock);
		if (clear)
			kfree_skb(skb);
	}
	skb_free_datagram(sk, skb);
}

#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 16)

/**
 * skb_kill_datagram - Kill a datagram forcibly.
 *
 * @sk:    Pointer to "struct sock".
 * @skb:   Pointer to "struct sk_buff".
 * @flags: Flags passed to skb_recv_datagram().
 *
 * Returns nothing.
 */
static inline void skb_kill_datagram(struct sock *sk, struct sk_buff *skb,
				     int flags)
{
	/* Clear queue. */
	if (flags & MSG_PEEK) {
		int clear = 0;
		spin_lock_bh(&sk->sk_receive_queue.lock);
		if (skb == skb_peek(&sk->sk_receive_queue)) {
			__skb_unlink(skb, &sk->sk_receive_queue);
			clear = 1;
		}
		spin_unlock_bh(&sk->sk_receive_queue.lock);
		if (clear)
			kfree_skb(skb);
	}
	skb_free_datagram(sk, skb);
}

#endif

/**
 * __ccs_socket_post_recvmsg_permission - Check permission for receiving a datagram.
 *
 * @sk:    Pointer to "struct sock".
 * @skb:   Pointer to "struct sk_buff".
 * @flags: Flags passed to skb_recv_datagram().
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_socket_post_recvmsg_permission(struct sock *sk,
						struct sk_buff *skb, int flags)
{
	struct ccs_addr_info address;
	const u8 family = ccs_sock_family(sk);
	const unsigned int type = sk->sk_type;
	struct sockaddr_storage addr;
	if (!family)
		return 0;
	switch (type) {
	case SOCK_DGRAM:
	case SOCK_RAW:
		address.protocol = type;
		break;
	default:
		return 0;
	}
	address.operation = CCS_NETWORK_RECV;
	switch (family) {
	case PF_INET6:
		{
			struct in6_addr *sin6 = (struct in6_addr *) &addr;
			address.inet.is_ipv6 = true;
			if (type == SOCK_DGRAM &&
			    skb->protocol == htons(ETH_P_IP))
				ipv6_addr_set(sin6, 0, 0, htonl(0xffff),
					      ip_hdr(skb)->saddr);
			else
				ipv6_addr_copy(sin6, &ipv6_hdr(skb)->saddr);
			break;
		}
	case PF_INET:
		{
			struct in_addr *sin4 = (struct in_addr *) &addr;
			address.inet.is_ipv6 = false;
			sin4->s_addr = ip_hdr(skb)->saddr;
			break;
		}
	default: /* == PF_UNIX */
		{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
			struct unix_address *u = unix_sk(skb->sk)->addr;
#else
			struct unix_address *u =
				skb->sk->protinfo.af_unix.addr;
#endif
			unsigned int addr_len;
			if (u && u->len <= sizeof(addr)) {
				addr_len = u->len;
				memcpy(&addr, u->name, addr_len);
			} else {
				addr_len = 0;
				addr.ss_family = AF_UNIX;
			}
			if (ccs_check_unix_address((struct sockaddr *) &addr,
						   addr_len, &address))
				goto out;
			return 0;
		}
	}
	address.inet.address = (u32 *) &addr;
	if (type == SOCK_DGRAM)
		address.inet.port = udp_hdr(skb)->source;
	else
		address.inet.port = htons(sk->sk_protocol);
	if (ccs_inet_entry(&address))
		goto out;
	return 0;
out:
	/*
	 * Remove from queue if MSG_PEEK is used so that
	 * the head message from unwanted source in receive queue will not
	 * prevent the caller from picking up next message from wanted source
	 * when the caller is using MSG_PEEK flag for picking up.
	 */
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 35)
		bool slow = false;
		if (type == SOCK_DGRAM && family != PF_UNIX)
			slow = lock_sock_fast(sk);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
		if (type == SOCK_DGRAM && family != PF_UNIX)
			lock_sock(sk);
#endif
		skb_kill_datagram(sk, skb, flags);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 35)
		if (type == SOCK_DGRAM && family != PF_UNIX)
			unlock_sock_fast(sk, slow);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
		if (type == SOCK_DGRAM && family != PF_UNIX)
			release_sock(sk);
#endif
	}
	return -EPERM;
}

/**
 * ccs_network_init - Register network related hooks.
 *
 * Returns nothing.
 */
void __init ccs_network_init(void)
{
	ccsecurity_ops.socket_create_permission =
		__ccs_socket_create_permission;
	ccsecurity_ops.socket_listen_permission =
		__ccs_socket_listen_permission;
	ccsecurity_ops.socket_connect_permission =
		__ccs_socket_connect_permission;
	ccsecurity_ops.socket_bind_permission = __ccs_socket_bind_permission;
	ccsecurity_ops.socket_post_accept_permission =
		__ccs_socket_post_accept_permission;
	ccsecurity_ops.socket_sendmsg_permission =
		__ccs_socket_sendmsg_permission;
	ccsecurity_ops.socket_post_recvmsg_permission =
		__ccs_socket_post_recvmsg_permission;
}

#endif
