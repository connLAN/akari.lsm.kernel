/*
 * security/ccsecurity/internal.h
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.8.0-pre   2010/10/05
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#ifndef _SECURITY_CCSECURITY_INTERNAL_H
#define _SECURITY_CCSECURITY_INTERNAL_H

#include <linux/string.h>
#include <linux/mm.h>
#include <linux/utime.h>
#include <linux/file.h>
#include <linux/smp_lock.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/binfmts.h>
#include <asm/uaccess.h>
#include <stdarg.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/in6.h>
#ifndef CONFIG_CCSECURITY
#define CONFIG_CCSECURITY
#define CONFIG_CCSECURITY_MAX_GRANT_LOG    1024
#define CONFIG_CCSECURITY_MAX_REJECT_LOG   1024
#define CONFIG_CCSECURITY_MAX_ACCEPT_ENTRY 2048
#define CONFIG_CCSECURITY_DEFAULT_LOADER "/sbin/ccs-init"
#define CONFIG_CCSECURITY_ALTERNATIVE_TRIGGER "/sbin/ccs-start"
#define CONFIG_CCSECURITY_BUILTIN_INITIALIZERS ""
#endif
#include "ccsecurity.h"
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
#include <linux/fs.h>
#endif
#include <linux/dcache.h>
#include "compat.h"

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
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 3)
#error This version is not supported because I cannot resolve vfsmount_lock .
#endif

struct dentry;
struct vfsmount;
struct in6_addr;

/**
 * list_for_each_cookie - iterate over a list with cookie.
 * @pos:        the &struct list_head to use as a loop cursor.
 * @head:       the head for your list.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 34)
#define list_for_each_cookie(pos, head)			\
	if (!pos)					\
		pos = rcu_dereference((head)->next);	\
	for ( ; pos != (head); pos = rcu_dereference(pos->next))
#else
#define list_for_each_cookie(pos, head)				\
	if (!pos)						\
		pos = srcu_dereference((head)->next, &ccs_ss);	\
	for ( ; pos != (head); pos = srcu_dereference(pos->next, &ccs_ss))
#endif

enum ccs_policy_stat_type {
	/* Do not change this order. */
	CCS_STAT_POLICY_UPDATES,
	CCS_STAT_POLICY_LEARNING,   /* == CCS_CONFIG_LEARNING */
	CCS_STAT_POLICY_PERMISSIVE, /* == CCS_CONFIG_PERMISSIVE */
	CCS_STAT_POLICY_ENFORCING,  /* == CCS_CONFIG_ENFORCING */
	CCS_MAX_POLICY_STAT
};

enum ccs_pref_index {
	CCS_PREF_MAX_GRANT_LOG,
	CCS_PREF_MAX_REJECT_LOG,
	CCS_PREF_MAX_LEARNING_ENTRY,
	CCS_PREF_ENFORCING_PENALTY,
	CCS_MAX_PREF,
};

enum ccs_memory_stat_type {
	CCS_MEMORY_POLICY,
	CCS_MEMORY_AUDIT,
	CCS_MEMORY_QUERY,
	CCS_MAX_MEMORY_STAT,
};

enum ccs_transition_type {
	/* Do not change this order, */
	CCS_TRANSITION_CONTROL_NO_INITIALIZE,
	CCS_TRANSITION_CONTROL_INITIALIZE,
	CCS_TRANSITION_CONTROL_NO_KEEP,
	CCS_TRANSITION_CONTROL_KEEP,
	CCS_MAX_TRANSITION_TYPE
};

/* Index numbers for Access Controls. */
enum ccs_acl_entry_type_index {
	CCS_TYPE_PATH_ACL,
	CCS_TYPE_PATH2_ACL,
	CCS_TYPE_PATH_NUMBER_ACL,
	CCS_TYPE_MKDEV_ACL,
	CCS_TYPE_MOUNT_ACL,
	CCS_TYPE_ENV_ACL,
	CCS_TYPE_CAPABILITY_ACL,
	CCS_TYPE_INET_ACL,
	CCS_TYPE_UNIX_ACL,
	CCS_TYPE_SIGNAL_ACL,
	CCS_TYPE_AUTO_EXECUTE_HANDLER,
	CCS_TYPE_DENIED_EXECUTE_HANDLER,
	CCS_TYPE_AUTO_TASK_ACL,
	CCS_TYPE_MANUAL_TASK_ACL,
};

enum ccs_path_acl_index {
	CCS_TYPE_EXECUTE,
	CCS_TYPE_READ,
	CCS_TYPE_WRITE,
	CCS_TYPE_APPEND,
	CCS_TYPE_UNLINK,
	CCS_TYPE_RMDIR,
	CCS_TYPE_TRUNCATE,
	CCS_TYPE_SYMLINK,
	CCS_TYPE_CHROOT,
	CCS_TYPE_UMOUNT,
	//CCS_TYPE_TRANSIT,
	CCS_MAX_PATH_OPERATION
};

enum ccs_mkdev_acl_index {
	CCS_TYPE_MKBLOCK,
	CCS_TYPE_MKCHAR,
	CCS_MAX_MKDEV_OPERATION
};

enum ccs_path2_acl_index {
	CCS_TYPE_LINK,
	CCS_TYPE_RENAME,
	CCS_TYPE_PIVOT_ROOT,
	CCS_MAX_PATH2_OPERATION
};

enum ccs_path_number_acl_index {
	CCS_TYPE_CREATE,
	CCS_TYPE_MKDIR,
	CCS_TYPE_MKFIFO,
	CCS_TYPE_MKSOCK,
	CCS_TYPE_IOCTL,
	CCS_TYPE_CHMOD,
	CCS_TYPE_CHOWN,
	CCS_TYPE_CHGRP,
	CCS_MAX_PATH_NUMBER_OPERATION
};

enum ccs_network_acl_index {
	CCS_NETWORK_BIND,    /* bind() operation. */
	CCS_NETWORK_LISTEN,  /* listen() operation. */
	CCS_NETWORK_CONNECT, /* connect() operation. */
	CCS_NETWORK_ACCEPT,  /* accept() operation. */
	CCS_NETWORK_SEND,    /* send() operation. */
	CCS_NETWORK_RECV,    /* recv() operation. */
	CCS_MAX_NETWORK_OPERATION
};

enum ccs_ip_address_type {
	CCS_IP_ADDRESS_TYPE_ADDRESS_GROUP,
	CCS_IP_ADDRESS_TYPE_IPv4,
	CCS_IP_ADDRESS_TYPE_IPv6
};

/* Indexes for /proc/ccs/ interfaces. */
enum ccs_proc_interface_index {
	CCS_DOMAINPOLICY,
	CCS_EXCEPTIONPOLICY,
	CCS_DOMAIN_STATUS,
	CCS_PROCESS_STATUS,
	CCS_MEMINFO,
	CCS_GRANTLOG,
	CCS_REJECTLOG,
	CCS_VERSION,
	CCS_PROFILE,
	CCS_QUERY,
	CCS_MANAGER,
	CCS_EXECUTE_HANDLER
};

enum ccs_mac_index {
	CCS_MAC_FILE_EXECUTE,
	CCS_MAC_FILE_OPEN,
	CCS_MAC_FILE_CREATE,
	CCS_MAC_FILE_UNLINK,
	CCS_MAC_FILE_MKDIR,
	CCS_MAC_FILE_RMDIR,
	CCS_MAC_FILE_MKFIFO,
	CCS_MAC_FILE_MKSOCK,
	CCS_MAC_FILE_TRUNCATE,
	CCS_MAC_FILE_SYMLINK,
	CCS_MAC_FILE_MKBLOCK,
	CCS_MAC_FILE_MKCHAR,
	CCS_MAC_FILE_LINK,
	CCS_MAC_FILE_RENAME,
	CCS_MAC_FILE_CHMOD,
	CCS_MAC_FILE_CHOWN,
	CCS_MAC_FILE_CHGRP,
	CCS_MAC_FILE_IOCTL,
	CCS_MAC_FILE_CHROOT,
	CCS_MAC_FILE_MOUNT,
	CCS_MAC_FILE_UMOUNT,
	CCS_MAC_FILE_PIVOT_ROOT,
	//CCS_MAC_FILE_TRANSIT,
	CCS_MAC_NETWORK_INET_STREAM_BIND,
	CCS_MAC_NETWORK_INET_STREAM_LISTEN,
	CCS_MAC_NETWORK_INET_STREAM_CONNECT,
	CCS_MAC_NETWORK_INET_STREAM_ACCEPT,
	CCS_MAC_NETWORK_INET_DGRAM_BIND,
	CCS_MAC_NETWORK_INET_DGRAM_SEND,
	CCS_MAC_NETWORK_INET_DGRAM_RECV,
	CCS_MAC_NETWORK_INET_RAW_BIND,
	CCS_MAC_NETWORK_INET_RAW_SEND,
	CCS_MAC_NETWORK_INET_RAW_RECV,
	CCS_MAC_NETWORK_UNIX_STREAM_BIND,
	CCS_MAC_NETWORK_UNIX_STREAM_LISTEN,
	CCS_MAC_NETWORK_UNIX_STREAM_CONNECT,
	CCS_MAC_NETWORK_UNIX_STREAM_ACCEPT,
	CCS_MAC_NETWORK_UNIX_DGRAM_BIND,
	CCS_MAC_NETWORK_UNIX_DGRAM_SEND,
	CCS_MAC_NETWORK_UNIX_DGRAM_RECV,
	CCS_MAC_NETWORK_UNIX_SEQPACKET_BIND,
	CCS_MAC_NETWORK_UNIX_SEQPACKET_LISTEN,
	CCS_MAC_NETWORK_UNIX_SEQPACKET_CONNECT,
	CCS_MAC_NETWORK_UNIX_SEQPACKET_ACCEPT,
	CCS_MAC_ENVIRON,
	CCS_MAC_SIGNAL,
	CCS_MAC_CAPABILITY_USE_ROUTE_SOCKET,
	CCS_MAC_CAPABILITY_USE_PACKET_SOCKET,
	CCS_MAC_CAPABILITY_SYS_REBOOT,
	CCS_MAC_CAPABILITY_SYS_VHANGUP,
	CCS_MAC_CAPABILITY_SYS_SETTIME,
	CCS_MAC_CAPABILITY_SYS_NICE,
	CCS_MAC_CAPABILITY_SYS_SETHOSTNAME,
	CCS_MAC_CAPABILITY_USE_KERNEL_MODULE,
	CCS_MAC_CAPABILITY_SYS_KEXEC_LOAD,
	CCS_MAC_CAPABILITY_SYS_PTRACE,
	CCS_MAX_MAC_INDEX
};

enum ccs_mac_category_index {
	CCS_MAC_CATEGORY_FILE,
	CCS_MAC_CATEGORY_NETWORK,
	CCS_MAC_CATEGORY_MISC,
	CCS_MAC_CATEGORY_IPC,
	CCS_MAC_CATEGORY_CAPABILITY,
	CCS_MAX_MAC_CATEGORY_INDEX
};

enum ccs_conditions_index {
	CCS_TASK_UID,             /* current_uid()   */
	CCS_TASK_EUID,            /* current_euid()  */
	CCS_TASK_SUID,            /* current_suid()  */
	CCS_TASK_FSUID,           /* current_fsuid() */
	CCS_TASK_GID,             /* current_gid()   */
	CCS_TASK_EGID,            /* current_egid()  */
	CCS_TASK_SGID,            /* current_sgid()  */
	CCS_TASK_FSGID,           /* current_fsgid() */
	CCS_TASK_PID,             /* sys_getpid()   */
	CCS_TASK_PPID,            /* sys_getppid()  */
	CCS_EXEC_ARGC,            /* "struct linux_binprm *"->argc */
	CCS_EXEC_ENVC,            /* "struct linux_binprm *"->envc */
	CCS_TYPE_IS_SOCKET,       /* S_IFSOCK */
	CCS_TYPE_IS_SYMLINK,      /* S_IFLNK */
	CCS_TYPE_IS_FILE,         /* S_IFREG */
	CCS_TYPE_IS_BLOCK_DEV,    /* S_IFBLK */
	CCS_TYPE_IS_DIRECTORY,    /* S_IFDIR */
	CCS_TYPE_IS_CHAR_DEV,     /* S_IFCHR */
	CCS_TYPE_IS_FIFO,         /* S_IFIFO */
	CCS_MODE_SETUID,          /* S_ISUID */
	CCS_MODE_SETGID,          /* S_ISGID */
	CCS_MODE_STICKY,          /* S_ISVTX */
	CCS_MODE_OWNER_READ,      /* S_IRUSR */
	CCS_MODE_OWNER_WRITE,     /* S_IWUSR */
	CCS_MODE_OWNER_EXECUTE,   /* S_IXUSR */
	CCS_MODE_GROUP_READ,      /* S_IRGRP */
	CCS_MODE_GROUP_WRITE,     /* S_IWGRP */
	CCS_MODE_GROUP_EXECUTE,   /* S_IXGRP */
	CCS_MODE_OTHERS_READ,     /* S_IROTH */
	CCS_MODE_OTHERS_WRITE,    /* S_IWOTH */
	CCS_MODE_OTHERS_EXECUTE,  /* S_IXOTH */
	CCS_TASK_TYPE,            /* ((u8) task->ccs_flags) &
				     CCS_TASK_IS_EXECUTE_HANDLER */
	CCS_TASK_EXECUTE_HANDLER, /* CCS_TASK_IS_EXECUTE_HANDLER */
	CCS_EXEC_REALPATH,
	CCS_SYMLINK_TARGET,
	CCS_PATH1_UID,
	CCS_PATH1_GID,
	CCS_PATH1_INO,
	CCS_PATH1_MAJOR,
	CCS_PATH1_MINOR,
	CCS_PATH1_PERM,
	CCS_PATH1_TYPE,
	CCS_PATH1_DEV_MAJOR,
	CCS_PATH1_DEV_MINOR,
	CCS_PATH2_UID,
	CCS_PATH2_GID,
	CCS_PATH2_INO,
	CCS_PATH2_MAJOR,
	CCS_PATH2_MINOR,
	CCS_PATH2_PERM,
	CCS_PATH2_TYPE,
	CCS_PATH2_DEV_MAJOR,
	CCS_PATH2_DEV_MINOR,
	CCS_PATH1_PARENT_UID,
	CCS_PATH1_PARENT_GID,
	CCS_PATH1_PARENT_INO,
	CCS_PATH1_PARENT_PERM,
	CCS_PATH2_PARENT_UID,
	CCS_PATH2_PARENT_GID,
	CCS_PATH2_PARENT_INO,
	CCS_PATH2_PARENT_PERM,
	CCS_MAX_CONDITION_KEYWORD,
	CCS_NUMBER_UNION,
	CCS_NAME_UNION,
	CCS_ARGV_ENTRY,
	CCS_ENVP_ENTRY
};

enum ccs_path_stat_index {
	CCS_PATH1,
	CCS_PATH1_PARENT,
	CCS_PATH2,
	CCS_PATH2_PARENT,
	CCS_MAX_PATH_STAT
};

#define CCS_HASH_BITS 8
#define CCS_MAX_HASH (1 << CCS_HASH_BITS)

#define CCS_SOCK_MAX 6

enum ccs_shared_acl_id {
	CCS_CONDITION_LIST,
	CCS_IPV6ADDRESS_LIST,
	CCS_MAX_LIST
};

enum ccs_group_id {
	CCS_PATH_GROUP,
	CCS_NUMBER_GROUP,
	CCS_ADDRESS_GROUP,
	CCS_MAX_GROUP
};

enum ccs_domain_info_flags_index {
	/* Quota warnning flag.   */
	CCS_DIF_QUOTA_WARNED,
	/*
	 * This domain was unable to create a new domain at
	 * ccs_find_next_domain() because the name of the domain to be created
	 * was too long or it could not allocate memory.
	 * More than one process continued execve() without domain transition.
	 */
	CCS_DIF_TRANSITION_FAILED,
	CCS_MAX_DOMAIN_INFO_FLAGS
};

/* Index numbers for garbage collection. */
enum ccs_policy_id {
	CCS_ID_RESERVEDPORT,
	CCS_ID_GROUP,
	CCS_ID_ADDRESS_GROUP,
	CCS_ID_PATH_GROUP,
	CCS_ID_NUMBER_GROUP,
	CCS_ID_AGGREGATOR,
	CCS_ID_TRANSITION_CONTROL,
	CCS_ID_MANAGER,
	CCS_ID_IPV6_ADDRESS,
	CCS_ID_CONDITION,
	CCS_ID_NAME,
	CCS_ID_ACL,
	CCS_ID_DOMAIN,
	CCS_MAX_POLICY
};

/* A domain definition starts with <kernel>. */
#define CCS_ROOT_NAME                         "<kernel>"
#define CCS_ROOT_NAME_LEN                     (sizeof(CCS_ROOT_NAME) - 1)

/* Value type definition. */
enum ccs_value_type {
	CCS_VALUE_TYPE_INVALID,
	CCS_VALUE_TYPE_DECIMAL,
	CCS_VALUE_TYPE_OCTAL,
	CCS_VALUE_TYPE_HEXADECIMAL
};

#define CCS_EXEC_TMPSIZE     4096

/* Profile number is an integer between 0 and 255. */
#define CCS_MAX_PROFILES 256

#define CCS_MAX_ACL_GROUPS 256

enum ccs_mode_value {
	CCS_CONFIG_DISABLED,
	CCS_CONFIG_LEARNING,
	CCS_CONFIG_PERMISSIVE,
	CCS_CONFIG_ENFORCING,
	CCS_CONFIG_MAX_MODE,
	CCS_CONFIG_WANT_REJECT_LOG =  64,
	CCS_CONFIG_WANT_GRANT_LOG  = 128,
	CCS_CONFIG_USE_DEFAULT     = 255
};

#define CCS_OPEN_FOR_READ_TRUNCATE        1
#define CCS_OPEN_FOR_IOCTL_ONLY           2
#define CCS_TASK_IS_IN_EXECVE             4
#define CCS_DONT_SLEEP_ON_ENFORCE_ERROR   8
#define CCS_TASK_IS_EXECUTE_HANDLER      16
#define CCS_TASK_IS_MANAGER              32

#define CCS_RETRY_REQUEST 1 /* Retry this request. */

#ifndef __GFP_HIGHIO
#define __GFP_HIGHIO 0
#endif
#ifndef __GFP_NOWARN
#define __GFP_NOWARN 0
#endif
#ifndef __GFP_NORETRY
#define __GFP_NORETRY 0
#endif
#ifndef __GFP_NOMEMALLOC
#define __GFP_NOMEMALLOC 0
#endif

#define CCS_GFP_FLAGS (__GFP_WAIT | __GFP_IO | __GFP_HIGHIO | __GFP_NOWARN | \
		       __GFP_NORETRY | __GFP_NOMEMALLOC)

/* Common header for holding ACL entries. */
struct ccs_acl_head {
	struct list_head list;
	bool is_deleted;
} __attribute__((__packed__));

struct ccs_shared_acl_head {
	struct list_head list;
	atomic_t users;
} __attribute__((__packed__));

struct ccs_acl_info {
	struct list_head list;
	struct ccs_condition *cond;
	bool is_deleted;
	u8 type; /* = one of values in "enum ccs_acl_entry_type_index" */
} __attribute__((__packed__));

struct ccs_name_union {
	const struct ccs_path_info *filename;
	struct ccs_group *group;
	u8 is_group;
};

struct ccs_number_union {
	unsigned long values[2];
	struct ccs_group *group;
	u8 value_type[2];
	u8 is_group;
};

/* Structure for "path_group"/"number_group"/"address_group" directive. */
struct ccs_group {
	struct ccs_shared_acl_head head;
	const struct ccs_path_info *group_name;
	struct list_head member_list;
};

/* Structure for "path_group" directive. */
struct ccs_path_group {
	struct ccs_acl_head head;
	const struct ccs_path_info *member_name;
};

/* Structure for "number_group" directive. */
struct ccs_number_group {
	struct ccs_acl_head head;
	struct ccs_number_union number;
};

/* Structure for "address_group" directive. */
struct ccs_address_group {
	struct ccs_acl_head head;
	bool is_ipv6;
	union {
		u32 ipv4;                    /* Host byte order    */
		const struct in6_addr *ipv6; /* Network byte order */
	} min, max;
};

/* Subset of "struct stat". */
struct ccs_mini_stat {
	uid_t uid;
	gid_t gid;
	ino_t ino;
	mode_t mode;
	dev_t dev;
	dev_t rdev;
};

/* Structure for dumping argv[] and envp[] of "struct linux_binprm". */
struct ccs_page_dump {
	struct page *page;    /* Previously dumped page. */
	char *data;           /* Contents of "page". Size is PAGE_SIZE. */
};

/* Structure for attribute checks in addition to pathname checks. */
struct ccs_obj_info {
	bool validate_done;
	bool stat_valid[CCS_MAX_PATH_STAT];
	struct path path1;
	struct path path2;
	struct ccs_mini_stat stat[CCS_MAX_PATH_STAT];
	struct ccs_path_info *symlink_target;
};

struct ccs_condition_element {
	/*
	 * Left hand operand. A "struct ccs_argv" for CCS_ARGV_ENTRY, a
	 * "struct ccs_envp" for CCS_ENVP_ENTRY is attached to the tail
	 * of the array of this struct.
	 */
	u8 left;
	/*
	 * Right hand operand. A "struct ccs_number_union" for
	 * CCS_NUMBER_UNION, a "struct ccs_name_union" for CCS_NAME_UNION is
	 * attached to the tail of the array of this struct.
	 */
	u8 right;
	/* Equation operator. true if equals or overlaps, false otherwise. */
	bool equals;
};

/* Structure for optional arguments. */
struct ccs_condition {
	struct ccs_shared_acl_head head;
	u32 size;
	u16 condc;
	u16 numbers_count;
	u16 names_count;
	u16 argc;
	u16 envc;
	u8 grant_log;
	const struct ccs_path_info *transit; /* This may be NULL. */
	/*
	 * struct ccs_condition_element condition[condc];
	 * struct ccs_number_union values[numbers_count];
	 * struct ccs_name_union names[names_count];
	 * struct ccs_argv argv[argc];
	 * struct ccs_envp envp[envc];
	 */
};

struct ccs_execve;

/* Structure for request info. */
struct ccs_request_info {
	/*
	 * For holding parameters specific to operations which deal files.
	 */
	struct ccs_obj_info *obj;
	/*
	 * For holding parameters specific to execve() request.
	 */
	struct ccs_execve *ee;
	/* For holding parameters. */
	union {
		struct {
			const struct ccs_path_info *filename;
			/* For using wildcards at ccs_find_next_domain(). */
			const struct ccs_path_info *matched_path;
			u8 operation;
		} path;
		struct {
			const struct ccs_path_info *filename1;
			const struct ccs_path_info *filename2;
			u8 operation;
		} path2;
		struct {
			const struct ccs_path_info *filename;
			unsigned int mode;
			unsigned int major;
			unsigned int minor;
			u8 operation;
		} mkdev;
		struct {
			const struct ccs_path_info *filename;
			unsigned long number;
			u8 operation;
		} path_number;
		struct {
			const u32 *address;
			u32 ip;
			u16 port;
			u8 protocol;
			u8 operation;
			bool is_ipv6;
		} inet_network;
		struct {
			const struct ccs_path_info *address;
			u8 protocol;
			u8 operation;
		} unix_network;
		struct {
			const struct ccs_path_info *name;
		} environ;
		struct {
			u8 operation;
		} capability;
		struct {
			const char *dest_pattern;
			int sig;
		} signal;
		struct {
			const struct ccs_path_info *type;
			const struct ccs_path_info *dir;
			const struct ccs_path_info *dev;
			unsigned long flags;
			int need_dev;
		} mount;
		struct {
			const struct ccs_path_info *domainname;
		} task;
	} param;
	u8 param_type;
	bool granted;
	/*
	 * For updating current->ccs_domain_info at ccs_update_task_domain().
	 * Initialized to NULL at ccs_init_request_info().
	 * Matching "struct ccs_acl_info" is copied if access request was
	 * granted. Re-initialized to NULL at ccs_update_task_domain().
	 */
	struct ccs_acl_info *matched_acl;
	/*
	 * For counting number of retries made for this request.
	 * This counter is incremented whenever ccs_supervisor() returned
	 * CCS_RETRY_REQUEST.
	 */
	u8 retry;
	/*
	 * For holding profile number used for this request.
	 * One of values between 0 and CCS_MAX_PROFILES - 1.
	 */
	u8 profile;
	/*
	 * For holding access control mode used for this request.
	 * One of CCS_CONFIG_DISABLED, CCS_CONFIG_LEARNING,
	 * CCS_CONFIG_PERMISSIVE, CCS_CONFIG_ENFORCING.
	 */
	u8 mode;
	/*
	 * For holding operation index used for this request.
	 * Used by ccs_init_request_info() / ccs_get_mode() / 
	 * ccs_write_log(). One of values in "enum ccs_mac_index".
	 */
	u8 type;
};

/* Structure for holding a token. */
struct ccs_path_info {
	const char *name;
	u32 hash;          /* = full_name_hash(name, strlen(name)) */
	u16 total_len;     /* = strlen(name)                       */
	u16 const_len;     /* = ccs_const_part_length(name)        */
	bool is_dir;       /* = ccs_strendswith(name, "/")         */
	bool is_patterned; /* = const_len < total_len              */
};

/* Structure for execve() operation. */
struct ccs_execve {
	struct ccs_request_info r;
	struct ccs_obj_info obj;
	struct linux_binprm *bprm;
	struct ccs_domain_info *previous_domain;
	int reader_idx;
	/* For execute_handler */
	const struct ccs_path_info *handler;
	char *handler_path; /* = kstrdup(handler->name, CCS_GFP_FLAGS) */
	/* For dumping argv[] and envp[]. */
	struct ccs_page_dump dump;
	/* For temporary use. */
	char *tmp; /* Size is CCS_EXEC_TMPSIZE bytes */
};

/* Structure for domain information. */
struct ccs_domain_info {
	struct list_head list;
	struct list_head acl_info_list[2];
	/* Name of this domain. Never NULL.          */
	const struct ccs_path_info *domainname;
	u8 profile;        /* Profile number to use. */
	u8 group;
	bool is_deleted;   /* Delete flag.           */
	bool flags[CCS_MAX_DOMAIN_INFO_FLAGS];
	atomic_t users;
};

/*
 * Structure for "initialize_domain"/"no_initialize_domain" and
 * "keep_domain"/"no_keep_domain" keyword.
 */
struct ccs_transition_control {
	struct ccs_acl_head head;
	u8 type; /* = one of values in "enum ccs_transition_type" */
	bool is_last_name; /* True if the domainname is ccs_last_word(). */
	const struct ccs_path_info *domainname;
	const struct ccs_path_info *program;
};

/* Structure for "aggregator" keyword. */
struct ccs_aggregator {
	struct ccs_acl_head head;
	const struct ccs_path_info *original_name;
	const struct ccs_path_info *aggregated_name;
};

/* Structure for "deny_autobind" keyword. */
struct ccs_reserved {
	struct ccs_acl_head head;
	u16 min_port;                /* Start of port number range.          */
	u16 max_port;                /* End of port number range.            */
};

/* Structure for policy manager. */
struct ccs_manager {
	struct ccs_acl_head head;
	bool is_domain;  /* True if manager is a domainname. */
	/* A path to program or a domainname. */
	const struct ccs_path_info *manager;
};

/* Structure for argv[]. */
struct ccs_argv {
	unsigned int index;
	const struct ccs_path_info *value;
	bool is_not;
};

/* Structure for envp[]. */
struct ccs_envp {
	const struct ccs_path_info *name;
	const struct ccs_path_info *value;
	bool is_not;
};

/*
 * Structure for "auto_execute_handler" and "denied_execute_handler" directive.
 *
 * If "auto_execute_handler" directive exists and the current process is not
 * an execute handler, all execve() requests are replaced by execve() requests
 * of a program specified by "auto_execute_handler" directive.
 * If the current process is an execute handler,
 * "auto_execute_handler" and "denied_execute_handler" directives are ignored.
 * The program specified by "execute_handler" validates execve() parameters
 * and executes the original execve() requests if appropriate.
 *
 * "denied_execute_handler" directive is used only when execve() request was
 * rejected in enforcing mode (i.e. CONFIG::file::execute={ mode=enforcing }).
 * The program specified by "denied_execute_handler" does whatever it wants
 * to do (e.g. silently terminate, change firewall settings,
 * redirect the user to honey pot etc.).
 */
struct ccs_handler_acl {
	struct ccs_acl_info head;       /* type = CCS_TYPE_*_EXECUTE_HANDLER */
	const struct ccs_path_info *handler; /* Pointer to single pathname.  */
};

/*
 * Structure for "task auto_domain_transition" and
 * "task manual_domain_transition" directive.
 */
struct ccs_task_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_*_TASK_ACL */
	/* Pointer to domainname. */
	const struct ccs_path_info *domainname;
};

/*
 * Structure for "file execute", "file read", "file write", "file append",
 * "file unlink", "file rmdir", "file truncate", "file symlink", "file chroot"
 * and "file unmount" directive.
 */
struct ccs_path_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_PATH_ACL */
	u16 perm; /* Bitmask of values in "enum ccs_path_acl_index" */
	struct ccs_name_union name;
};

/*
 * Structure for "file rename", "file link" and "file pivot_root" directive.
 */
struct ccs_path2_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_PATH2_ACL */
	u8 perm; /* Bitmask of values in "enum ccs_path2_acl_index" */
	struct ccs_name_union name1;
	struct ccs_name_union name2;
};

/*
 * Structure for "file create", "file mkdir", "file mkfifo", "file mksock",
 * "file ioctl", "file chmod", "file chown" and "file chgrp" directive.
 */
struct ccs_path_number_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_PATH_NUMBER_ACL */
	u8 perm; /* Bitmask of values in "enum ccs_path_number_acl_index" */
	struct ccs_name_union name;
	struct ccs_number_union number;
};

/* Structure for "file mkblock" and "file mkchar" directive. */
struct ccs_mkdev_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_MKDEV_ACL */
	u8 perm; /* Bitmask of values in "enum ccs_mkdev_acl_index" */
	struct ccs_name_union name;
	struct ccs_number_union mode;
	struct ccs_number_union major;
	struct ccs_number_union minor;
};

/* Structure for "file mount" keyword. */
struct ccs_mount_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_MOUNT_ACL */
	struct ccs_name_union dev_name;
	struct ccs_name_union dir_name;
	struct ccs_name_union fs_type;
	struct ccs_number_union flags;
};

/* Structure for "misc env" directive in domain policy. */
struct ccs_env_acl {
	struct ccs_acl_info head;        /* type = CCS_TYPE_ENV_ACL  */
	const struct ccs_path_info *env; /* environment variable */
};

/* Structure for "capability" directive. */
struct ccs_capability_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_CAPABILITY_ACL */
	u8 operation;
};

/* Structure for "ipc signal" directive. */
struct ccs_signal_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_SIGNAL_ACL */
	u16 sig;
	/* Pointer to destination pattern. */
	const struct ccs_path_info *domainname;
};

struct ccs_ipv6addr {
	struct ccs_shared_acl_head head;
	struct in6_addr addr;
};

/* Structure for "network inet" directive. */
struct ccs_inet_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_INET_ACL */
	u8 protocol;
	u8 perm; /* Bitmask of values in "enum ccs_network_acl_index" */
	/*
	 * address_type takes one of the following constants.
	 *   CCS_IP_ADDRESS_TYPE_ADDRESS_GROUP
	 *                if address points to "address_group" directive.
	 *   CCS_IP_ADDRESS_TYPE_IPv4
	 *                if address points to an IPv4 address.
	 *   CCS_IP_ADDRESS_TYPE_IPv6
	 *                if address points to an IPv6 address.
	 */
	u8 address_type;
	union {
		struct {
			/* Start of IPv4 address range. Host endian. */
			u32 min;
			/* End of IPv4 address range. Host endian.   */
			u32 max;
		} ipv4;
		struct {
			/* Start of IPv6 address range. Big endian.  */
			const struct in6_addr *min;
			/* End of IPv6 address range. Big endian.    */
			const struct in6_addr *max;
		} ipv6;
		/* Pointer to address group. */
		struct ccs_group *group;
	} address;
	struct ccs_number_union port;
};

/* Structure for "network unix" directive. */
struct ccs_unix_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_UNIX_ACL */
	u8 protocol;
	u8 perm; /* Bitmask of values in "enum ccs_network_acl_index" */
	struct ccs_name_union name;
};

/* Structure for string data. */
struct ccs_name {
	struct ccs_shared_acl_head head;
	int size;
	struct ccs_path_info entry;
};

struct ccs_acl_param {
	char *data;
	struct ccs_domain_info *domain;
	bool is_delete;
};

#define CCS_MAX_IO_READ_QUEUE 32

/* Structure for reading/writing policy via /proc interfaces. */
struct ccs_io_buffer {
	void (*read) (struct ccs_io_buffer *);
	int (*write) (struct ccs_io_buffer *);
	int (*poll) (struct file *file, poll_table *wait);
	/* Exclusive lock for this structure.   */
	struct mutex io_sem;
	/* Index returned by ccs_lock().        */
	int reader_idx;
	char __user *read_user_buf;
	int read_user_buf_avail;
	struct {
		struct list_head *domain;
		struct list_head *group;
		struct list_head *acl;
		int avail;
		int step;
		int query_index;
		u16 index;
		u16 cond_index;
		u8 group_index;
		u8 cond_step;
		u8 bit;
		u8 w_pos;
		bool eof;
		bool print_this_domain_only;
		bool print_execute_only;
		bool print_cond_part;
		const char *w[CCS_MAX_IO_READ_QUEUE];
	} r;
	struct {
		struct ccs_domain_info *domain;
		int avail;
	} w;
	/* Buffer for reading.                  */
	char *read_buf;
	/* Size of read buffer.                 */
	int readbuf_size;
	/* Buffer for writing.                  */
	char *write_buf;
	/* Size of write buffer.                */
	int writebuf_size;
	/* Type of this interface.              */
	u8 type;
};

struct ccs_profile {
	const struct ccs_path_info *comment;
	u8 default_config;
	u8 config[CCS_MAX_MAC_INDEX + CCS_MAX_MAC_CATEGORY_INDEX];
	unsigned int pref[CCS_MAX_PREF];
};

/* Prototype definition for "struct ccsecurity_operations". */

void __init ccs_capability_init(void);
void __init ccs_domain_init(void);
void __init ccs_file_init(void);
void __init ccs_mm_init(void);
void __init ccs_mount_init(void);
void __init ccs_network_init(void);
void __init ccs_policy_io_init(void);
void __init ccs_signal_init(void);

/* Prototype definition for internal use. */

bool ccs_address_matches_group(const bool is_ipv6, const u32 *address,
			       const struct ccs_group *group);
const struct ccs_path_info *
ccs_compare_name_union(const struct ccs_path_info *name,
		       const struct ccs_name_union *ptr);
bool ccs_compare_number_union(const unsigned long value,
			      const struct ccs_number_union *ptr);
bool ccs_condition(struct ccs_request_info *r,
		   const struct ccs_condition *cond);
bool ccs_correct_domain(const unsigned char *domainname);
bool ccs_correct_path(const char *filename);
bool ccs_correct_word(const char *string);
bool ccs_domain_def(const unsigned char *buffer);
bool ccs_domain_quota_ok(struct ccs_request_info *r);
bool ccs_dump_page(struct linux_binprm *bprm, unsigned long pos,
		   struct ccs_page_dump *dump);
void ccs_io_printf(struct ccs_io_buffer *head, const char *fmt, ...)
     __attribute__ ((format(printf, 2, 3)));
bool ccs_memory_ok(const void *ptr, const unsigned int size);
bool ccs_number_matches_group(const unsigned long min, const unsigned long max,
			      const struct ccs_group *group);
bool ccs_parse_name_union(const char *filename, struct ccs_name_union *ptr);
bool ccs_parse_number_union(char *data, struct ccs_number_union *num);
char *ccs_read_token(struct ccs_acl_param *param);
const struct ccs_path_info *
ccs_path_matches_group(const struct ccs_path_info *pathname,
		       const struct ccs_group *group);
bool ccs_path_matches_pattern(const struct ccs_path_info *filename,
			      const struct ccs_path_info *pattern);
bool ccs_permstr(const char *string, const char *keyword);
bool ccs_str_starts(char **src, const char *find);
bool ccs_tokenize(char *buffer, char *w[], size_t size);
char *ccs_encode(const char *str);
char *ccs_encode2(const char *str, int str_len);
char *ccs_init_log(int *len, struct ccs_request_info *r, const char *fmt,
		   va_list args);
char *ccs_realpath_from_path(struct path *path);
const char *ccs_get_exe(void);
const struct ccs_path_info *ccs_get_domainname(struct ccs_acl_param *param);
const struct ccs_path_info *ccs_get_name(const char *name);
const struct in6_addr *ccs_get_ipv6_address(const struct in6_addr *addr);
int ccs_close_control(struct file *file);
int ccs_delete_domain(char *data);
int ccs_env_perm(struct ccs_request_info *r, const char *env);
int ccs_get_path(const char *pathname, struct path *path);
int ccs_init_request_info(struct ccs_request_info *r, const u8 index);
int ccs_lock(void);
int ccs_open_control(const u8 type, struct file *file);
int ccs_parse_ip_address(char *address, u16 *min, u16 *max);
int ccs_path_permission(struct ccs_request_info *r, u8 operation,
			const struct ccs_path_info *filename);
int ccs_poll_control(struct file *file, poll_table *wait);
int ccs_poll_log(struct file *file, poll_table *wait);
int ccs_read_control(struct file *file, char __user *buffer,
		     const int buffer_len);
int ccs_supervisor(struct ccs_request_info *r, const char *fmt, ...)
	__attribute__ ((format(printf, 2, 3)));
int ccs_symlink_path(const char *pathname, struct ccs_path_info *name);
int ccs_update_domain(struct ccs_acl_info *new_entry, const int size,
		      struct ccs_acl_param *param,
		      bool (*check_duplicate) (const struct ccs_acl_info *,
					       const struct ccs_acl_info *),
		      bool (*merge_duplicate) (struct ccs_acl_info *,
					       struct ccs_acl_info *,
					       const bool));
int ccs_update_policy(struct ccs_acl_head *new_entry, const int size,
		      bool is_delete, struct list_head *list,
		      bool (*check_duplicate) (const struct ccs_acl_head *,
					       const struct ccs_acl_head *));
int ccs_write_aggregator(char *data, const bool is_delete);
int ccs_write_capability(struct ccs_acl_param *param);
int ccs_write_control(struct file *file, const char __user *buffer,
		      const int buffer_len);
int ccs_write_file(struct ccs_acl_param *param);
int ccs_write_group(char *data, const bool is_delete, const u8 type);
int ccs_write_ipc(struct ccs_acl_param *param);
int ccs_write_memory_quota(struct ccs_io_buffer *head);
int ccs_write_misc(struct ccs_acl_param *param);
int ccs_write_inet_network(struct ccs_acl_param *param);
int ccs_write_unix_network(struct ccs_acl_param *param);
int ccs_write_reserved_port(char *data, const bool is_delete);
int ccs_write_transition_control(char *data, const bool is_delete,
				 const u8 type);
size_t ccs_del_condition(struct list_head *element);
struct ccs_condition *ccs_get_condition(char *condition);
struct ccs_domain_info *ccs_assign_domain(const char *domainname,
					  const u8 profile, const u8 group,
					  const bool transit);
struct ccs_domain_info *ccs_find_domain(const char *domainname);
struct ccs_group *ccs_get_group(const char *group_name, const u8 idx);
struct ccs_profile *ccs_profile(const u8 profile);
u8 ccs_get_config(const u8 profile, const u8 index);
u8 ccs_parse_ulong(unsigned long *result, char **str);
void *ccs_commit_ok(void *data, const unsigned int size);
void ccs_check_acl(struct ccs_request_info *r,
		   bool (*check_entry) (struct ccs_request_info *,
					const struct ccs_acl_info *));
void ccs_fill_path_info(struct ccs_path_info *ptr);
void ccs_get_attributes(struct ccs_obj_info *obj);
void ccs_memory_free(const void *ptr, size_t size);
void ccs_normalize_line(unsigned char *buffer);
void ccs_print_ipv4(char *buffer, const int buffer_len, const u32 min_ip,
		    const u32 max_ip);
void ccs_print_ipv6(char *buffer, const int buffer_len,
		    const struct in6_addr *min_ip,
		    const struct in6_addr *max_ip);
void ccs_print_ulong(char *buffer, const int buffer_len,
		     const unsigned long value, const u8 type);
void ccs_put_name_union(struct ccs_name_union *ptr);
void ccs_put_number_union(struct ccs_number_union *ptr);
void ccs_read_log(struct ccs_io_buffer *head);
void ccs_read_memory_counter(struct ccs_io_buffer *head);
void ccs_run_gc(void);
void ccs_transition_failed(const char *domainname);
void ccs_unlock(const int idx);
void ccs_update_stat(const u8 index);
void ccs_warn_oom(const char *function);
void ccs_write_log(struct ccs_request_info *r, const char *fmt, ...)
	__attribute__ ((format(printf, 2, 3)));
void ccs_write_log2(struct ccs_request_info *r, const char *fmt, va_list args);

/* strcmp() for "struct ccs_path_info" structure. */
static inline bool ccs_pathcmp(const struct ccs_path_info *a,
			       const struct ccs_path_info *b)
{
	return a->hash != b->hash || strcmp(a->name, b->name);
}

static inline bool ccs_same_name_union(const struct ccs_name_union *p1,
				       const struct ccs_name_union *p2)
{
	return p1->filename == p2->filename && p1->group == p2->group &&
		p1->is_group == p2->is_group;
}

static inline bool ccs_same_number_union(const struct ccs_number_union *p1,
					 const struct ccs_number_union *p2)
{
	return p1->values[0] == p2->values[0] && p1->values[1] == p2->values[1]
		&& p1->group == p2->group &&
		p1->value_type[0] == p2->value_type[0] &&
		p1->value_type[1] == p2->value_type[1] &&
		p1->is_group == p2->is_group;
}

extern struct mutex ccs_policy_lock;
extern struct list_head ccs_domain_list;
extern struct list_head ccs_policy_list[CCS_MAX_POLICY];
extern struct list_head ccs_group_list[CCS_MAX_GROUP];
extern struct list_head ccs_shared_list[CCS_MAX_LIST];
extern struct list_head ccs_name_list[CCS_MAX_HASH];
extern bool ccs_policy_loaded;
extern struct ccs_domain_info ccs_acl_group[CCS_MAX_ACL_GROUPS];
extern struct ccs_domain_info ccs_kernel_domain;
extern const char * const ccs_condition_keyword[CCS_MAX_CONDITION_KEYWORD];
extern const char * const ccs_dif[CCS_MAX_DOMAIN_INFO_FLAGS];
extern const char * const ccs_mac_keywords[CCS_MAX_MAC_INDEX
				    + CCS_MAX_MAC_CATEGORY_INDEX];
extern const char * const ccs_mode[CCS_CONFIG_MAX_MODE];
extern const char * const ccs_path_keyword[CCS_MAX_PATH_OPERATION];
extern const char * const ccs_socket_keyword[CCS_MAX_NETWORK_OPERATION];
extern const char * const ccs_proto_keyword[CCS_SOCK_MAX];
extern const u8 ccs_index2category[CCS_MAX_MAC_INDEX];
extern const u8 ccs_c2mac[CCS_MAX_CAPABILITY_INDEX];
extern const u8 ccs_pn2mac[CCS_MAX_PATH_NUMBER_OPERATION];
extern const u8 ccs_pnnn2mac[CCS_MAX_MKDEV_OPERATION];
extern const u8 ccs_pp2mac[CCS_MAX_PATH2_OPERATION];
extern unsigned int ccs_memory_used[CCS_MAX_MEMORY_STAT];
extern unsigned int ccs_memory_quota[CCS_MAX_MEMORY_STAT];
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 19)
extern struct srcu_struct ccs_ss;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 19)
static inline int ccs_read_lock(void)
{
	return srcu_read_lock(&ccs_ss);
}
static inline void ccs_read_unlock(const int idx)
{
	srcu_read_unlock(&ccs_ss, idx);
}
#else
static inline int ccs_read_lock(void)
{
	return ccs_lock();
}
static inline void ccs_read_unlock(const int idx)
{
	ccs_unlock(idx);
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)

#include <linux/lglock.h>
DECLARE_BRLOCK(vfsmount_lock);
static inline void ccs_realpath_lock(void)
{
	spin_lock(&dcache_lock);
	br_read_lock(vfsmount_lock);
}
static inline void ccs_realpath_unlock(void)
{
	br_read_unlock(vfsmount_lock);
	spin_unlock(&dcache_lock);
}

#elif defined(D_PATH_DISCONNECT) && !defined(CONFIG_SUSE_KERNEL)

static inline void ccs_realpath_lock(void)
{
	spin_lock(ccsecurity_exports.vfsmount_lock);
	spin_lock(&dcache_lock);
}
static inline void ccs_realpath_unlock(void)
{
	spin_unlock(&dcache_lock);
	spin_unlock(ccsecurity_exports.vfsmount_lock);
}

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)

static inline void ccs_realpath_lock(void)
{
	spin_lock(&dcache_lock);
	spin_lock(ccsecurity_exports.vfsmount_lock);
}
static inline void ccs_realpath_unlock(void)
{
	spin_unlock(ccsecurity_exports.vfsmount_lock);
	spin_unlock(&dcache_lock);
}

#else

static inline void ccs_realpath_lock(void)
{
	spin_lock(&dcache_lock);
}
static inline void ccs_realpath_unlock(void)
{
	spin_unlock(&dcache_lock);
}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)

static inline void ccs_tasklist_lock(void)
{
	rcu_read_lock();
}
static inline void ccs_tasklist_unlock(void)
{
	rcu_read_unlock();
}

#else

static inline void ccs_tasklist_lock(void)
{
	read_lock(&tasklist_lock);
}
static inline void ccs_tasklist_unlock(void)
{
	read_unlock(&tasklist_lock);
}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
static inline pid_t ccs_sys_getppid(void)
{
	pid_t pid;
	rcu_read_lock();
	pid = task_tgid_vnr(current->real_parent);
	rcu_read_unlock();
	return pid;
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
static inline pid_t ccs_sys_getppid(void)
{
	pid_t pid;
	rcu_read_lock();
#if (defined(RHEL_MAJOR) && RHEL_MAJOR == 5) || (defined(AX_MAJOR) && AX_MAJOR == 3)
	pid = rcu_dereference(current->parent)->tgid;
#else
	pid = rcu_dereference(current->real_parent)->tgid;
#endif
	rcu_read_unlock();
	return pid;
}
#elif defined(TASK_DEAD)
static inline pid_t ccs_sys_getppid(void)
{
	pid_t pid;
	read_lock(&tasklist_lock);
	pid = current->group_leader->real_parent->tgid;
	read_unlock(&tasklist_lock);
	return pid;
}
#else
static inline pid_t ccs_sys_getppid(void)
{
	pid_t pid;
	read_lock(&tasklist_lock);
	pid = current->p_opptr->pid;
	read_unlock(&tasklist_lock);
	return pid;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
static inline pid_t ccs_sys_getpid(void)
{
	return task_tgid_vnr(current);
}
#else
static inline pid_t ccs_sys_getpid(void)
{
	return current->tgid;
}
#endif

static inline u8 ccs_get_mode(const u8 profile, const u8 index)
{
	return ccs_get_config(profile, index) & (CCS_CONFIG_MAX_MODE - 1);
}

#if defined(CONFIG_SLOB)
static inline int ccs_round2(size_t size)
{
	return size;
}
#else
static inline int ccs_round2(size_t size)
{
#if PAGE_SIZE == 4096
	size_t bsize = 32;
#else
	size_t bsize = 64;
#endif
	if (!size)
		return 0;
	while (size > bsize)
		bsize <<= 1;
	return bsize;
}
#endif

static inline void ccs_put_condition(struct ccs_condition *cond)
{
	if (cond)
		atomic_dec(&cond->head.users);
}

static inline void ccs_put_group(struct ccs_group *group)
{
	if (group)
		atomic_dec(&group->head.users);
}

static inline void ccs_put_ipv6_address(const struct in6_addr *addr)
{
	if (addr)
		atomic_dec(&container_of(addr, struct ccs_ipv6addr,
					 addr)->head.users);
}

static inline void ccs_put_name(const struct ccs_path_info *name)
{
	if (name)
		atomic_dec(&container_of(name, struct ccs_name, entry)->
			   head.users);
}

struct ccs_security {
	struct list_head list;
	struct task_struct *task;
	const struct cred *cred;
	struct ccs_domain_info *ccs_domain_info;
	u32 ccs_flags;
	struct ccs_execve *ee;
	struct rcu_head rcu;
};

extern void __init ccs_main_init(void);
extern struct ccs_security *ccs_find_task_security(const struct task_struct *
						   task);
extern void ccs_update_security_domain(struct ccs_domain_info **pdomain,
				       struct ccs_domain_info *domain);

static inline struct ccs_security *ccs_current_security(void)
{
	return ccs_find_task_security(current);
}

static inline struct ccs_domain_info *ccs_task_domain(struct task_struct *task)
{
	return ccs_find_task_security(task)->ccs_domain_info;
}

static inline struct ccs_domain_info *ccs_current_domain(void)
{
	return ccs_task_domain(current);
}

static inline u32 ccs_task_flags(struct task_struct *task)
{
	return ccs_find_task_security(task)->ccs_flags;
}

static inline u32 ccs_current_flags(void)
{
	return ccs_task_flags(current);
}

#endif
