/*
 * security/ccsecurity/network.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.2+   2011/09/03
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 19) && defined(CONFIG_NET)
#define ccs_in4_pton in4_pton
#define ccs_in6_pton in6_pton
#else
/*
 * Routines for parsing IPv4 or IPv6 address.
 * These are copied from lib/hexdump.c net/core/utils.c .
 */
#include <linux/ctype.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35)
static int hex_to_bin(char ch)
{
	if ((ch >= '0') && (ch <= '9'))
		return ch - '0';
	ch = tolower(ch);
	if ((ch >= 'a') && (ch <= 'f'))
		return ch - 'a' + 10;
	return -1;
}
#endif

#define IN6PTON_XDIGIT		0x00010000
#define IN6PTON_DIGIT		0x00020000
#define IN6PTON_COLON_MASK	0x00700000
#define IN6PTON_COLON_1		0x00100000	/* single : requested */
#define IN6PTON_COLON_2		0x00200000	/* second : requested */
#define IN6PTON_COLON_1_2	0x00400000	/* :: requested */
#define IN6PTON_DOT		0x00800000	/* . */
#define IN6PTON_DELIM		0x10000000
#define IN6PTON_NULL		0x20000000	/* first/tail */
#define IN6PTON_UNKNOWN		0x40000000

static inline int xdigit2bin(char c, int delim)
{
	int val;

	if (c == delim || c == '\0')
		return IN6PTON_DELIM;
	if (c == ':')
		return IN6PTON_COLON_MASK;
	if (c == '.')
		return IN6PTON_DOT;

	val = hex_to_bin(c);
	if (val >= 0)
		return val | IN6PTON_XDIGIT | (val < 10 ? IN6PTON_DIGIT : 0);

	if (delim == -1)
		return IN6PTON_DELIM;
	return IN6PTON_UNKNOWN;
}

static int ccs_in4_pton(const char *src, int srclen, u8 *dst, int delim,
			const char **end)
{
	const char *s;
	u8 *d;
	u8 dbuf[4];
	int ret = 0;
	int i;
	int w = 0;

	if (srclen < 0)
		srclen = strlen(src);
	s = src;
	d = dbuf;
	i = 0;
	while(1) {
		int c;
		c = xdigit2bin(srclen > 0 ? *s : '\0', delim);
		if (!(c & (IN6PTON_DIGIT | IN6PTON_DOT | IN6PTON_DELIM |
			   IN6PTON_COLON_MASK))) {
			goto out;
		}
		if (c & (IN6PTON_DOT | IN6PTON_DELIM | IN6PTON_COLON_MASK)) {
			if (w == 0)
				goto out;
			*d++ = w & 0xff;
			w = 0;
			i++;
			if (c & (IN6PTON_DELIM | IN6PTON_COLON_MASK)) {
				if (i != 4)
					goto out;
				break;
			}
			goto cont;
		}
		w = (w * 10) + c;
		if ((w & 0xffff) > 255) {
			goto out;
		}
cont:
		if (i >= 4)
			goto out;
		s++;
		srclen--;
	}
	ret = 1;
	memcpy(dst, dbuf, sizeof(dbuf));
out:
	if (end)
		*end = s;
	return ret;
}

static int ccs_in6_pton(const char *src, int srclen, u8 *dst, int delim,
			const char **end)
{
	const char *s, *tok = NULL;
	u8 *d, *dc = NULL;
	u8 dbuf[16];
	int ret = 0;
	int i;
	int state = IN6PTON_COLON_1_2 | IN6PTON_XDIGIT | IN6PTON_NULL;
	int w = 0;

	memset(dbuf, 0, sizeof(dbuf));

	s = src;
	d = dbuf;
	if (srclen < 0)
		srclen = strlen(src);

	while (1) {
		int c;

		c = xdigit2bin(srclen > 0 ? *s : '\0', delim);
		if (!(c & state))
			goto out;
		if (c & (IN6PTON_DELIM | IN6PTON_COLON_MASK)) {
			/* process one 16-bit word */
			if (!(state & IN6PTON_NULL)) {
				*d++ = (w >> 8) & 0xff;
				*d++ = w & 0xff;
			}
			w = 0;
			if (c & IN6PTON_DELIM) {
				/* We've processed last word */
				break;
			}
			/*
			 * COLON_1 => XDIGIT
			 * COLON_2 => XDIGIT|DELIM
			 * COLON_1_2 => COLON_2
			 */
			switch (state & IN6PTON_COLON_MASK) {
			case IN6PTON_COLON_2:
				dc = d;
				state = IN6PTON_XDIGIT | IN6PTON_DELIM;
				if (dc - dbuf >= sizeof(dbuf))
					state |= IN6PTON_NULL;
				break;
			case IN6PTON_COLON_1|IN6PTON_COLON_1_2:
				state = IN6PTON_XDIGIT | IN6PTON_COLON_2;
				break;
			case IN6PTON_COLON_1:
				state = IN6PTON_XDIGIT;
				break;
			case IN6PTON_COLON_1_2:
				state = IN6PTON_COLON_2;
				break;
			default:
				state = 0;
			}
			tok = s + 1;
			goto cont;
		}

		if (c & IN6PTON_DOT) {
			ret = ccs_in4_pton(tok ? tok : s, srclen +
					   (int)(s - tok), d, delim, &s);
			if (ret > 0) {
				d += 4;
				break;
			}
			goto out;
		}

		w = (w << 4) | (0xff & c);
		state = IN6PTON_COLON_1 | IN6PTON_DELIM;
		if (!(w & 0xf000)) {
			state |= IN6PTON_XDIGIT;
		}
		if (!dc && d + 2 < dbuf + sizeof(dbuf)) {
			state |= IN6PTON_COLON_1_2;
			state &= ~IN6PTON_DELIM;
		}
		if (d + 2 >= dbuf + sizeof(dbuf)) {
			state &= ~(IN6PTON_COLON_1|IN6PTON_COLON_1_2);
		}
cont:
		if ((dc && d + 4 < dbuf + sizeof(dbuf)) ||
		    d + 4 == dbuf + sizeof(dbuf)) {
			state |= IN6PTON_DOT;
		}
		if (d >= dbuf + sizeof(dbuf)) {
			state &= ~(IN6PTON_XDIGIT|IN6PTON_COLON_MASK);
		}
		s++;
		srclen--;
	}

	i = 15; d--;

	if (dc) {
		while(d >= dc)
			dst[i--] = *d--;
		while(i >= dc - dbuf)
			dst[i--] = 0;
		while(i >= 0)
			dst[i--] = *d--;
	} else
		memcpy(dst, dbuf, sizeof(dbuf));

	ret = 1;
out:
	if (end)
		*end = s;
	return ret;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32)

/*
 * Routines for printing IPv4 or IPv6 address.
 * These are copied from include/linux/kernel.h include/net/ipv6.h
 * include/net/addrconf.h lib/hexdump.c lib/vsprintf.c and simplified.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
static const char hex_asc[] = "0123456789abcdef";
#define hex_asc_lo(x)   hex_asc[((x) & 0x0f)]
#define hex_asc_hi(x)   hex_asc[((x) & 0xf0) >> 4]

static inline char *pack_hex_byte(char *buf, u8 byte)
{
	*buf++ = hex_asc_hi(byte);
	*buf++ = hex_asc_lo(byte);
	return buf;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
static inline int ipv6_addr_v4mapped(const struct in6_addr *a)
{
	return (a->s6_addr32[0] | a->s6_addr32[1] |
		(a->s6_addr32[2] ^ htonl(0x0000ffff))) == 0;
}
#endif

static inline int ipv6_addr_is_isatap(const struct in6_addr *addr)
{
	return (addr->s6_addr32[2] | htonl(0x02000000)) == htonl(0x02005EFE);
}

static char *ip4_string(char *p, const u8 *addr)
{
	/*
	 * Since this function is called outside vsnprintf(), I can use
	 * sprintf() here.
	 */
	return p +
		sprintf(p, "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
}

static char *ip6_compressed_string(char *p, const char *addr)
{
	int i, j, range;
	unsigned char zerolength[8];
	int longest = 1;
	int colonpos = -1;
	u16 word;
	u8 hi, lo;
	bool needcolon = false;
	bool useIPv4;
	struct in6_addr in6;

	memcpy(&in6, addr, sizeof(struct in6_addr));

	useIPv4 = ipv6_addr_v4mapped(&in6) || ipv6_addr_is_isatap(&in6);

	memset(zerolength, 0, sizeof(zerolength));

	if (useIPv4)
		range = 6;
	else
		range = 8;

	/* find position of longest 0 run */
	for (i = 0; i < range; i++) {
		for (j = i; j < range; j++) {
			if (in6.s6_addr16[j] != 0)
				break;
			zerolength[i]++;
		}
	}
	for (i = 0; i < range; i++) {
		if (zerolength[i] > longest) {
			longest = zerolength[i];
			colonpos = i;
		}
	}
	if (longest == 1)		/* don't compress a single 0 */
		colonpos = -1;

	/* emit address */
	for (i = 0; i < range; i++) {
		if (i == colonpos) {
			if (needcolon || i == 0)
				*p++ = ':';
			*p++ = ':';
			needcolon = false;
			i += longest - 1;
			continue;
		}
		if (needcolon) {
			*p++ = ':';
			needcolon = false;
		}
		/* hex u16 without leading 0s */
		word = ntohs(in6.s6_addr16[i]);
		hi = word >> 8;
		lo = word & 0xff;
		if (hi) {
			if (hi > 0x0f)
				p = pack_hex_byte(p, hi);
			else
				*p++ = hex_asc_lo(hi);
			p = pack_hex_byte(p, lo);
		}
		else if (lo > 0x0f)
			p = pack_hex_byte(p, lo);
		else
			*p++ = hex_asc_lo(lo);
		needcolon = true;
	}

	if (useIPv4) {
		if (needcolon)
			*p++ = ':';
		p = ip4_string(p, &in6.s6_addr[12]);
	}
	*p = '\0';

	return p;
}
#endif

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
	u8 * const min = ptr->ip[0].in6_u.u6_addr8;
	u8 * const max = ptr->ip[1].in6_u.u6_addr8;
	char *address = ccs_read_token(param);
	const char *end;
	if (!strchr(address, ':') &&
	    ccs_in4_pton(address, -1, min, '-', &end) > 0) {
		ptr->is_ipv6 = false;
		if (!*end)
			ptr->ip[1].s6_addr32[0] = ptr->ip[0].s6_addr32[0];
		else if (*end++ != '-' ||
			 ccs_in4_pton(end, -1, max, '\0', &end) <= 0 || *end)
			return false;
		return true;
	}
	if (ccs_in6_pton(address, -1, min, '-', &end) > 0) {
		ptr->is_ipv6 = true;
		if (!*end)
			memmove(max, min, sizeof(u16) * 8);
		else if (*end++ != '-' ||
			 ccs_in6_pton(end, -1, max, '\0', &end) <= 0 || *end)
			return false;
		return true;
	}
	return false;
}

/**
 * ccs_print_ipv4 - Print an IPv4 address.
 *
 * @buffer:     Buffer to write to.
 * @buffer_len: Size of @buffer.
 * @min_ip:     Pointer to "u32 in network byte order".
 * @max_ip:     Pointer to "u32 in network byte order".
 *
 * Returns nothing.
 */
static void ccs_print_ipv4(char *buffer, const unsigned int buffer_len,
			   const u32 *min_ip, const u32 *max_ip)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	snprintf(buffer, buffer_len, "%pI4%c%pI4", min_ip,
		 *min_ip == *max_ip ? '\0' : '-', max_ip);
#else
	char min_addr[sizeof("255.255.255.255")];
	char max_addr[sizeof("255.255.255.255")];
	ip4_string(min_addr, (const u8 *) min_ip);
	ip4_string(max_addr, (const u8 *) max_ip);
	snprintf(buffer, buffer_len, "%s%c%s", min_addr,
		 *min_ip == *max_ip ? '\0' : '-', max_addr);
#endif
}

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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	snprintf(buffer, buffer_len, "%pI6c%c%pI6c", min_ip,
		 !memcmp(min_ip, max_ip, 16) ? '\0' : '-', max_ip);
#else
	char min_addr[sizeof("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:255.255.255.255")];
	char max_addr[sizeof("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:255.255.255.255")];
	ip6_compressed_string(min_addr, (const u8 *) min_ip);
	ip6_compressed_string(max_addr, (const u8 *) max_ip);
	snprintf(buffer, buffer_len, "%s%c%s", min_addr,
		 !memcmp(min_ip, max_ip, 16) ? '\0' : '-', max_addr);
#endif
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
		ccs_print_ipv4(buf, size, &ptr->ip[0].s6_addr32[0],
			       &ptr->ip[1].s6_addr32[0]);
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
		ccs_print_ipv4(buf, sizeof(buf), address, address);
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
	const u8 size = r->param.inet_network.is_ipv6 ? 16 : 4;
	if (!(acl->perm & (1 << r->param.inet_network.operation)) ||
	    !ccs_compare_number_union(r->param.inet_network.port, &acl->port))
		return false;
	if (acl->address.group)
		return ccs_address_matches_group(r->param.inet_network.is_ipv6,
						 r->param.inet_network.address,
						 acl->address.group);
	return acl->address.is_ipv6 == r->param.inet_network.is_ipv6 &&
		memcmp(&acl->address.ip[0],
		       r->param.inet_network.address, size) <= 0 &&
		memcmp(r->param.inet_network.address,
		       &acl->address.ip[1], size) <= 0;
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
