/*
 * uuid.c
 *
 * Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
 *
 * This LSM module can do three things.
 *
 *  (1) Isolate processes by comparing UUID (which is associated with processes
 *      by this module, from LSM hooks which take "struct task_struct *" in
 *      their arguments).
 *  (2) Restrict communication via UNIX domain sockets by comparing UUID of
 *      socket's creator.
 *  (3) Restrict opening files by using userspace daemon program (which
 *      determines whether to grant acess or not).
 *
 * Any process is classified as one of "unrestricted", "half-restricted",
 * "restricted" states. A process is permitted to transit from "unrestricted"
 * state to "half restricted" state by opening /proc/uuid interface.
 * A process is permitted to transit from "half restricted" state to
 * "restricted" state by writing a UUID to /proc/uuid interface.
 *
 * Process's state is automatically inherited to child processes created
 * afterward. The UUID cannot be changed after once configured.
 *
 * Otherwise, operations are granted in accordance with permission bits.
 * The permission consists with 9 bits. The first 3 bits (counting from most
 * significant bit) are for "unrestricted" subject, the next 3 bits are for
 * "half-restricted" subjects, the last 3 bits are for "restricted" subjects.
 * The first bit (counting from most significant bit) of each 3 bits is for
 * "unrestricted" object, the next bit of each 3 bits is for "half-restricted"
 * object, the last bit of each 3 bits is for "restricted" object.
 *
 * Note that oprations against restricted object by restricted subject is
 * granted when both permission bit is granmted and their UUID are identical.
 * This means that they are classified as a different class if their UUID
 * differs.
 *
 * Permission to open a file is granted in below rules. By performance reason,
 * permission to read()/write()/ioctl() etc. are not checked.
 *
 *   Subjective | unrestricted | half restricted | restricted
 * -------------+--------------+-----------------+--------------
 *   Object     |  always      | ack by daemon   | ack by daemon
 *
 * To compile, put this file on some directory under kernel's source directory
 * (e.g. uuid/ directory) and do "echo 'obj-m := uuid.o' > uuid/Makefile" and
 * do "make -s SUBDIRS=uuid modules modules_install". This file supports kernel
 * 2.6.3 and higher.
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
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/fs_struct.h>
#include <asm/uaccess.h>
#include <net/sock.h>

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

enum uuid_operation_index {
	UUID_PTRACE,
	UUID_CAPGET,
	UUID_CAPABLE,
	UUID_CAPSET,
	UUID_SIGIOTASK,
	UUID_SETPGID,
	UUID_GETPGID,
	UUID_GETSID,
	UUID_SETNICE,
	UUID_SETIOPRIO,
	UUID_GETIOPRIO,
	UUID_SETRLIMIT,
	UUID_SETSCHEDULER,
	UUID_GETSCHEDULER,
	UUID_MOVEMEMORY,
	UUID_KILL,
	UUID_WAIT,
	UUID_MSGRECV,
	UUID_GETPROCATTR,
	UUID_SETPROCATTR,
	UUID_KEY,
	UUID_UNIX_STREAM_CONNECT,
	UUID_UNIX_MAY_SEND,
	UUID_OPEN_PIPE,
	UUID_MAX_OPERATIONS,
};

static u16 uuid_config[UUID_MAX_OPERATIONS] = {
	[UUID_PTRACE] = 0777,
	[UUID_CAPGET] = 0777,
	[UUID_CAPABLE] = 0777,
	[UUID_CAPSET] = 0777,
	[UUID_SIGIOTASK] = 0777,
	[UUID_SETPGID] = 0777,
	[UUID_GETPGID] = 0777,
	[UUID_GETSID] = 0777,
	[UUID_SETNICE] = 0777,
	[UUID_SETIOPRIO] = 0777,
	[UUID_GETIOPRIO] = 0777,
	[UUID_SETRLIMIT] = 0777,
	[UUID_SETSCHEDULER] = 0777,
	[UUID_GETSCHEDULER] = 0777,
	[UUID_MOVEMEMORY] = 0777,
	[UUID_KILL] = 0777,
	[UUID_WAIT] = 0777,
	[UUID_MSGRECV] = 0777,
	[UUID_GETPROCATTR] = 0777,
	[UUID_SETPROCATTR] = 0777,
	[UUID_KEY] = 0777,
	[UUID_UNIX_STREAM_CONNECT] = 0777,
	[UUID_UNIX_MAY_SEND] = 0777,
	[UUID_OPEN_PIPE] = 0777,
};

static const char *uuid_prompt[UUID_MAX_OPERATIONS] = {
	[UUID_PTRACE] = "check_ptrace",
	[UUID_CAPGET] = "get_capability",
	[UUID_CAPABLE] = "check_capability",
	[UUID_CAPSET]  = "set_capability",
	[UUID_SIGIOTASK] = "check_sigiotask",
	[UUID_SETPGID] = "set_pgid",
	[UUID_GETPGID] = "get_pgid",
	[UUID_GETSID]  = "set_sid",
	[UUID_SETNICE] = "set_taskpriority",
	[UUID_SETIOPRIO] = "set_iopriority",
	[UUID_GETIOPRIO] = "get_iopriority",
	[UUID_SETRLIMIT] = "set_taskrlimit",
	[UUID_SETSCHEDULER] = "set_scheduler",
	[UUID_GETSCHEDULER] = "get_scheduler",
	[UUID_MOVEMEMORY] = "check_movememory",
	[UUID_KILL] = "check_kill",
	[UUID_WAIT] = "check_wait",
	[UUID_MSGRECV] = "check_msgrecv",
	[UUID_GETPROCATTR] = "get_procattr",
	[UUID_SETPROCATTR] = "set_procattr",
	[UUID_KEY] = "check_key",
	[UUID_UNIX_STREAM_CONNECT] = "check_unix_connect",
	[UUID_UNIX_MAY_SEND] = "check_unix_send",
	[UUID_OPEN_PIPE] = "check_pipe_open",
};

static char *uuid_encode(const char *str);
static char *uuid_encode2(const char *str, int str_len);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)

/**
 * uuid_sys_getpid - Copy of getpid().
 *
 * Returns current thread's PID.
 *
 * Alpha does not have getpid() defined. To be able to build this module on
 * Alpha, I have to copy getpid() from kernel/timer.c.
 */
static inline pid_t uuid_sys_getpid(void)
{
	return task_tgid_vnr(current);
}

#else

/**
 * uuid_sys_getpid - Copy of getpid().
 *
 * Returns current thread's PID.
 */
static inline pid_t uuid_sys_getpid(void)
{
	return current->tgid;
}

#endif

static struct {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
	char *(*__d_path) (const struct path *path, struct path *root,
			   char *buf, int buflen);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
	spinlock_t *vfsmount_lock;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
	struct task_struct *(*find_task_by_vpid) (pid_t pid);
#endif
} uuid_exports;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)

/* Structure for holding "struct vfsmount *" and "struct dentry *". */
struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};

#endif

#ifndef current_uid
#define current_uid()   (current->uid)
#endif
#ifndef current_gid
#define current_gid()   (current->gid)
#endif
#ifndef current_euid
#define current_euid()  (current->euid)
#endif
#ifndef current_egid
#define current_egid()  (current->egid)
#endif
#ifndef current_suid
#define current_suid()  (current->suid)
#endif
#ifndef current_sgid
#define current_sgid()  (current->sgid)
#endif
#ifndef current_fsuid
#define current_fsuid() (current->fsuid)
#endif
#ifndef current_fsgid
#define current_fsgid() (current->fsgid)
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

struct uuid_query_param {
	const char *operation;
	struct path path;
};

static int uuid_supervisor(struct uuid_query_param *p);

#define UUID_SIZE 16 

static inline bool uuid_eq(const u8 *a, const u8 *b)
{
	return !memcmp(a, b, UUID_SIZE);
}

static inline void uuid_copy(u8 *a, const u8 *b)
{
	memcpy(a, b, UUID_SIZE);
}

struct uuid_security {
	struct list_head list;
	/* "struct cred" or "struct task_struct" or "struct inode" */
	const void *owner;
	u8 uuid[UUID_SIZE];
	u8 uuid_configured;
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
	if (old_security->uuid_configured) {
		uuid_copy(new_security->uuid, old_security->uuid);
		new_security->uuid_configured = 1;
	}
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
	if (old_security->uuid_configured) {
		uuid_copy(new_security->uuid, old_security->uuid);
		new_security->uuid_configured = 1;
	}
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

#define UUID_PRINT_SIZE 37

static void uuid_print_uuid(const struct uuid_security *ptr,
			    char uuid_buf[UUID_PRINT_SIZE])
{
	
	if (!ptr)
		snprintf(uuid_buf, UUID_PRINT_SIZE, "unrestricted");
	else if (!ptr->uuid_configured)
		snprintf(uuid_buf, UUID_PRINT_SIZE, "half-restricted");
	else {
		const char *uuid = ptr->uuid;
		snprintf(uuid_buf, UUID_PRINT_SIZE,
			 "%08x-%04x-%04x-%04x-%04x%08x",
			 htonl(* (u32 *) uuid), htons(* (u16 *) (uuid + 4)),
			 htons(* (u16 *) (uuid + 6)),
			 htons(* (u16 *) (uuid + 8)),
			 htons(* (u16 *) (uuid + 10)),
			 htonl(* (u32 *) (uuid + 12)));
	}
}

static bool uuid_check_task(struct task_struct *task,
			    const enum uuid_operation_index index)
{
	struct uuid_security *sbj;
	struct uuid_security *obj;
	int ret = 0;
	char buf_sbj[UUID_PRINT_SIZE];
	char buf_obj[UUID_PRINT_SIZE];
	u16 perm;
	if (task == current)
		return 0;
	perm = uuid_config[index];
	rcu_read_lock();
	sbj = uuid_find_security(current_cred());
	obj = uuid_find_security(__task_cred(task));
	if (!sbj)
		perm >>= 6;
	else if (!sbj->uuid_configured)
		perm >>= 3;
	if (!obj)
		perm &= 4;
	else if (!obj->uuid_configured)
		perm &= 2;
	else
		perm &= 1;
	if (sbj && sbj->uuid_configured && obj && obj->uuid_configured &&
	    !uuid_eq(sbj->uuid, obj->uuid))
		perm = 0;
	if (perm)
		goto ok;
	uuid_print_uuid(sbj, buf_sbj);
	uuid_print_uuid(obj, buf_obj);
	printk(KERN_INFO "Prevented task(%s) ('%s',pid=%u) from accessing "
	       "task(%s) ('%s',pid=%u) at %s\n", buf_sbj, current->comm,
	       current->pid, buf_obj, task->comm, task->pid,
	       uuid_prompt[index]);
	ret = -EPERM;
ok:
	rcu_read_unlock();
	return ret;
}

static int uuid_check_inode(struct inode *inode, const char *type,
			    const enum uuid_operation_index index)
{
	struct uuid_security *sbj;
	struct uuid_security *obj;
	int ret = 0;
	char buf_sbj[UUID_PRINT_SIZE];
	char buf_obj[UUID_PRINT_SIZE];
	u16 perm = uuid_config[index];
	rcu_read_lock();
	sbj = uuid_find_security(current_cred());
	obj = uuid_find_security(inode);
	if (!sbj)
		perm >>= 6;
	else if (!sbj->uuid_configured)
		perm >>= 3;
	if (!obj)
		perm &= 4;
	else if (!obj->uuid_configured)
		perm &= 2;
	else
		perm &= 1;
	if (sbj && sbj->uuid_configured && obj && obj->uuid_configured &&
	    !uuid_eq(sbj->uuid, obj->uuid))
		perm = 0;
	if (perm)
		goto ok;
	uuid_print_uuid(sbj, buf_sbj);
	uuid_print_uuid(obj, buf_obj);
	printk(KERN_INFO "Prevented task(%s) ('%s',pid=%u) from accessing "
	       "%s(%s) at %s\n", buf_sbj, current->comm, current->pid, type,
	       buf_obj, uuid_prompt[index]);
	ret = -EPERM;
ok:
	rcu_read_unlock();
	return ret;
}

#ifdef CONFIG_SECURITY_NETWORK

#include <net/sock.h>

static int uuid_check_socket(struct socket *sock,
			     const enum uuid_operation_index index)
{
	return uuid_check_inode(SOCK_INODE(sock), "socket", index);
}

#endif

static int uuid_check_pipe(struct inode *inode,
			   const enum uuid_operation_index index)
{
	if (!S_ISFIFO(inode->i_mode))
		return 0;
	return uuid_check_inode(inode, "pipe", index);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)

static int uuid_ptrace_access_check(struct task_struct *child,
				    unsigned int mode)
{
	if (uuid_check_task(child, UUID_PTRACE))
		return -EPERM;
	while (!original_security_ops.ptrace_access_check);
	return original_security_ops.ptrace_access_check(child, mode);
}

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)

static int uuid_ptrace_may_access(struct task_struct *child, unsigned int mode)
{
	if (uuid_check_task(child, UUID_PTRACE))
		return -EPERM;
	while (!original_security_ops.ptrace_may_access);
	return original_security_ops.ptrace_may_access(child, mode);
}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)

static int uuid_ptrace_traceme(struct task_struct *parent)
{
	if (uuid_check_task(parent, UUID_PTRACE))
		return -EPERM;
	while (!original_security_ops.ptrace_traceme);
	return original_security_ops.ptrace_traceme(parent);
}

#else

static inline int uuid_ptrace(struct task_struct *parent,
			      struct task_struct *child)
{
	if (uuid_check_task(parent, UUID_PTRACE))
		return -EPERM;
	if (uuid_check_task(child, UUID_PTRACE))
		return -EPERM;
	while (!original_security_ops.ptrace);
	return original_security_ops.ptrace(parent, child);
}

#endif

static int uuid_capget(struct task_struct *target, kernel_cap_t *effective,
		       kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
	if (uuid_check_task(target, UUID_CAPGET))
		return -EPERM;
	while (!original_security_ops.capget);
	return original_security_ops.capget(target, effective, inheritable,
					    permitted);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)

static int uuid_capable(struct task_struct *tsk, const struct cred *cred,
			int cap, int audit)
{
	if (uuid_check_task(tsk, UUID_CAPABLE))
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
	if (uuid_check_task(target, UUID_CAPSET))
		return -EPERM;
	while (!original_security_ops.capset_check);
	return original_security_ops.capset_check(target, effective,
						  inheritable, permitted);
}

static int uuid_capable(struct task_struct *tsk, int cap)
{
	if (uuid_check_task(tsk, UUID_CAPABLE))
		return -EPERM;
	while (!original_security_ops.capable);
	return original_security_ops.capable(tsk, cap);
}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)

static int uuid_file_send_sigiotask(struct task_struct *tsk,
				    struct fown_struct *fown, int sig)
{
	if (uuid_check_task(tsk, UUID_SIGIOTASK))
		return -EPERM;
	while (!original_security_ops.file_send_sigiotask);
	return original_security_ops.file_send_sigiotask(tsk, fown, sig);
}

#else

static int uuid_file_send_sigiotask(struct task_struct *tsk,
				    struct fown_struct *fown, int sig,
				    int reason)
{
	if (uuid_check_task(tsk, UUID_SIGIOTASK))
		return -EPERM;
	while (!original_security_ops.file_send_sigiotask);
	return original_security_ops.file_send_sigiotask(tsk, fown, sig,
							 reason);
}

#endif

static int uuid_task_setpgid(struct task_struct *p, pid_t pgid)
{
	if (uuid_check_task(p, UUID_SETPGID))
		return -EPERM;
	while (!original_security_ops.task_setpgid);
	return original_security_ops.task_setpgid(p, pgid);
}

static int uuid_task_getpgid(struct task_struct *p)
{
	if (uuid_check_task(p, UUID_GETPGID))
		return -EPERM;
	while (!original_security_ops.task_getpgid);
	return original_security_ops.task_getpgid(p);
}

static int uuid_task_getsid(struct task_struct *p)
{
	if (uuid_check_task(p, UUID_GETSID))
		return -EPERM;
	while (!original_security_ops.task_getsid);
	return original_security_ops.task_getsid(p);
}

static int uuid_task_setnice(struct task_struct *p, int nice)
{
	if (uuid_check_task(p, UUID_SETNICE))
		return -EPERM;
	while (!original_security_ops.task_setnice);
	return original_security_ops.task_setnice(p, nice);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)

static int uuid_task_setioprio(struct task_struct *p, int ioprio)
{
	if (uuid_check_task(p, UUID_SETIOPRIO))
		return -EPERM;
	while (!original_security_ops.task_setioprio);
	return original_security_ops.task_setioprio(p, ioprio);
}

static int uuid_task_getioprio(struct task_struct *p)
{
	if (uuid_check_task(p, UUID_GETIOPRIO))
		return -EPERM;
	while (!original_security_ops.task_getioprio);
	return original_security_ops.task_getioprio(p);
}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)

static int uuid_task_setrlimit(struct task_struct *p, unsigned int resource,
			       struct rlimit *new_rlim)
{
	if (uuid_check_task(p, UUID_SETRLIMIT))
		return -EPERM;
	while (!original_security_ops.task_setrlimit);
	return original_security_ops.task_setrlimit(p, resource, new_rlim);
}

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 37)

static int uuid_task_setscheduler(struct task_struct *p, int policy,
				  struct sched_param *lp)
{
	if (uuid_check_task(p, UUID_SETSCHEDULER))
		return -EPERM;
	while (!original_security_ops.task_setscheduler);
	return original_security_ops.task_setscheduler(p, policy, lp);
}

#else

static int uuid_task_setscheduler(struct task_struct *p)
{
	if (uuid_check_task(p, UUID_SETSCHEDULER))
		return -EPERM;
	while (!original_security_ops.task_setscheduler);
	return original_security_ops.task_setscheduler(p);
}

#endif

static int uuid_task_getscheduler(struct task_struct *p)
{
	if (uuid_check_task(p, UUID_GETSCHEDULER))
		return -EPERM;
	while (!original_security_ops.task_getscheduler);
	return original_security_ops.task_getscheduler(p);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)

static int uuid_task_movememory(struct task_struct *p)
{
	if (uuid_check_task(p, UUID_MOVEMEMORY))
		return -EPERM;
	while (!original_security_ops.task_movememory);
	return original_security_ops.task_movememory(p);
}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)

static int uuid_task_kill(struct task_struct *p, struct siginfo *info, int sig,
			  u32 secid)
{
	if (sig && uuid_check_task(p, UUID_KILL)) {
		printk(KERN_INFO "signo = %d\n", sig);
		return -EPERM;
	}
	while (!original_security_ops.task_kill);
	return original_security_ops.task_kill(p, info, sig, secid);
}

#else

static int uuid_task_kill(struct task_struct *p, struct siginfo *info, int sig)
{
	if (sig && uuid_check_task(p, UUID_KILL))
		return -EPERM;
	while (!original_security_ops.task_kill);
	return original_security_ops.task_kill(p, info, sig);
}

#endif

static int uuid_task_wait(struct task_struct *p)
{
	if (uuid_check_task(p, UUID_WAIT))
		return -EPERM;
	while (!original_security_ops.task_wait);
	return original_security_ops.task_wait(p);
}

static int uuid_msg_queue_msgrcv(struct msg_queue *msq, struct msg_msg *msg,
				 struct task_struct *target, long type,
				 int mode)
{
	if (uuid_check_task(target, UUID_MSGRECV))
		return -EPERM;
	while (!original_security_ops.msg_queue_msgrcv);
	return original_security_ops.msg_queue_msgrcv(msq, msg, target, type,
						      mode);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 21)

static int uuid_getprocattr(struct task_struct *p, char *name, char **value)
{
	if (uuid_check_task(p, UUID_GETPROCATTR))
		return -EPERM;
	while (!original_security_ops.getprocattr);
	return original_security_ops.getprocattr(p, name, value);
}

#else

static int uuid_getprocattr(struct task_struct *p, char *name, void *value,
			    size_t size)
{
	if (uuid_check_task(p, UUID_GETPROCATTR))
		return -EPERM;
	while (!original_security_ops.getprocattr);
	return original_security_ops.getprocattr(p, name, value, size);
}

#endif

static int uuid_setprocattr(struct task_struct *p, char *name, void *value,
			    size_t size)
{
	if (uuid_check_task(p, UUID_SETPROCATTR))
		return -EPERM;
	while (!original_security_ops.setprocattr);
	return original_security_ops.setprocattr(p, name, value, size);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 15) && LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29) && defined(CONFIG_KEYS)

static int uuid_key_permission(key_ref_t key_ref, struct task_struct *context,
			       key_perm_t perm)
{
	if (uuid_check_task(context, UUID_KEY))
		return -EPERM;
	while (!original_security_ops.key_permission);
	return original_security_ops.key_permission(key_ref, context, perm);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)

static int uuid_key_alloc(struct key *key, struct task_struct *tsk,
			  unsigned long flags)
{
	if (uuid_check_task(tsk, UUID_KEY))
		return -EPERM;
	while (!original_security_ops.key_alloc);
	return original_security_ops.key_alloc(key, tsk, flags);
}

#endif
#endif

static int uuid_inode_alloc_security(struct inode *inode)
{
	int rc;
	if (S_ISSOCK(inode->i_mode) || S_ISFIFO(inode->i_mode)) {
		/*
		char buf_sbj[UUID_PRINT_SIZE];
		char buf_obj[UUID_PRINT_SIZE];
		*/
		rc = uuid_copy_security(inode, current_cred(), GFP_KERNEL);
		if (rc)
			return rc;
		/*
		uuid_print_uuid(uuid_find_security(current_cred()), buf_sbj);
		uuid_print_uuid(uuid_find_security(inode), buf_obj);
		printk(KERN_DEBUG "Allocated %s(%s) by "
		       "task(%s) ('%s',pid=%u) (%p)\n",
		       S_ISSOCK(inode->i_mode) ? "socket" : "pipe",
		       buf_obj, buf_sbj, current->comm,
		       current->pid, inode);
		*/
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
	int rc = uuid_check_socket(other, UUID_UNIX_STREAM_CONNECT);
	if (rc)
		return rc;
	while (!original_security_ops.unix_stream_connect);
	return original_security_ops.unix_stream_connect(sock, other, newsk);
}

static int uuid_unix_may_send(struct socket *sock, struct socket *other)
{
	int rc = uuid_check_socket(other, UUID_UNIX_MAY_SEND);
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
	int rc = uuid_check_pipe(f->f_dentry->d_inode, UUID_OPEN_PIPE);
	if (rc)
		return rc;
	if (uuid_find_security(current_cred())) {
		struct uuid_query_param p = { };
		p.operation = "file open";
		p.path = f->f_path;
		rc = uuid_supervisor(&p);
		if (rc)
			return rc;
	}
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
	int rc = uuid_check_pipe(f->f_dentry->d_inode, UUID_OPEN_PIPE);
	if (rc)
		return rc;
	if (uuid_find_security(current_cred())) {
		struct uuid_query_param p = { };
		p.operation = "file open";
		p.path = f->f_path;
		rc = uuid_supervisor(&p);
		if (rc)
			return rc;
	}
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
	int rc = uuid_check_pipe(inode, UUID_OPEN_PIPE);
	if (rc)
		return rc;
	if (nd && nd->dentry && uuid_find_security(current)) {
		struct uuid_query_param p = { };
		p.operation = "file open";
		p.path.dentry = nd->dentry;
		p.path.mnt = nd->mnt;
		rc = uuid_supervisor(&p);
		if (rc)
			return rc;
	}
	while (!original_security_ops.inode_permission);
	return original_security_ops.inode_permission(inode, mask, nd);
}

#endif

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)

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

#endif

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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 15)

/* Never mark this variable as __initdata . */
static spinlock_t uuid_vfsmount_lock;

/**
 * lsm_floup - Dummy function which does identical to follow_up() in fs/namei.c.
 *
 * @mnt:    Pointer to "struct vfsmount *".
 * @dentry: Pointer to "struct dentry *".
 *
 * Returns 1 if followed up, 0 otehrwise.
 *
 * Never mark this function as __init in order to make sure that compiler
 * generates identical code for follow_up() and this function.
 */
static int lsm_flwup(struct vfsmount **mnt, struct dentry **dentry)
{
	struct vfsmount *parent;
	struct dentry *mountpoint;
	spin_lock(&uuid_vfsmount_lock);
	parent = (*mnt)->mnt_parent;
	if (parent == *mnt) {
		spin_unlock(&uuid_vfsmount_lock);
		return 0;
	}
	mntget(parent);
	mountpoint = dget((*mnt)->mnt_mountpoint);
	spin_unlock(&uuid_vfsmount_lock);
	dput(*dentry);
	*dentry = mountpoint;
	mntput(*mnt);
	*mnt = parent;
	return 1;
}

#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)

/* Never mark this variable as __initdata . */
static spinlock_t uuid_vfsmount_lock;

/**
 * lsm_pin - Dummy function which does identical to mnt_pin() in fs/namespace.c.
 *
 * @mnt: Pointer to "struct vfsmount".
 *
 * Returns nothing.
 *
 * Never mark this function as __init in order to make sure that compiler
 * generates identical code for mnt_pin() and this function.
 */
static void lsm_pin(struct vfsmount *mnt)
{
	spin_lock(&uuid_vfsmount_lock);
	mnt->mnt_pinned++;
	spin_lock(&uuid_vfsmount_lock);
}

#endif

/**
 * uuid_find_vfsmount_lock - Find address of "spinlock_t vfsmount_lock".
 *
 * Returns true on success, false otherwise.
 */
static bool __init uuid_find_vfsmount_lock(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 15)
	void *cp;
	spinlock_t *ptr;
	/* Guess "spinlock_t vfsmount_lock;". */
	cp = uuid_find_variable(lsm_flwup, (unsigned long) &uuid_vfsmount_lock,
			       "follow_up");
	if (!cp) {
		printk(KERN_ERR "Can't resolve follow_up().\n");
		goto out;
	}
	/* This should be "spinlock_t *vfsmount_lock;". */
	ptr = *(spinlock_t **) cp;
	if (!ptr) {
		printk(KERN_ERR "Can't resolve vfsmount_lock .\n");
		goto out;
	}
	uuid_exports.vfsmount_lock = ptr;
	printk(KERN_INFO "vfsmount_lock=%p\n", ptr);
	return true;
out:
	return false;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	void *cp;
	spinlock_t *ptr;
	/* Guess "spinlock_t vfsmount_lock;". */
	cp = uuid_find_variable(lsm_pin, (unsigned long) &uuid_vfsmount_lock,
			       "mnt_pin");
	if (!cp) {
		printk(KERN_ERR "Can't resolve mnt_pin().\n");
		goto out;
	}
	/* This should be "spinlock_t *vfsmount_lock;". */
	ptr = *(spinlock_t **) cp;
	if (!ptr) {
		printk(KERN_ERR "Can't resolve vfsmount_lock .\n");
		goto out;
	}
	uuid_exports.vfsmount_lock = ptr;
	printk(KERN_INFO "vfsmount_lock=%p\n", ptr);
	return true;
out:
	return false;
#else
	void *ptr = uuid_find_symbol(" __d_path\n");
	if (!ptr) {
		printk(KERN_ERR "Can't resolve __d_path().\n");
		return false;
	}
	uuid_exports.__d_path = ptr;
	printk(KERN_INFO "__d_path=%p\n", ptr);
	return true;
#endif
}

static bool __init uuid_find_find_task_by_pid(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
	void *ptr;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 31)
	ptr = uuid_find_symbol(" find_task_by_vpid\n");
#else
	ptr = __symbol_get("find_task_by_vpid");
#endif
	if (!ptr) {
		printk(KERN_ERR "Can't resolve find_task_by_vpid().\n");
		goto out;
	}
	uuid_exports.find_task_by_vpid = ptr;
	printk(KERN_INFO "find_task_by_vpid=%p\n", ptr);
	return true;
out:
	return false;
#else
	return true;
#endif
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
	swap_security_ops(file_send_sigiotask);
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
static DEFINE_SPINLOCK(uuid_alloc_lock);
#endif

/**
 * uuid_open - open() for /proc/uuid interface.
 *
 * @inode: Pointer to "struct inode".
 * @file:  Pointer to "struct file".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int uuid_open(struct inode *inode, struct file *file)
{
	int rc = 0;
	const struct cred *cred = current_cred();
	struct uuid_security *uuid = kzalloc(sizeof(*uuid), GFP_KERNEL);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
	/* We need to serialize because "struct cred" may be shared. */
	spin_lock(&uuid_alloc_lock);
	/*
	 * This function must not be called between override_creds() and
	 * revert_creds() because we loose "struct uuid_security" as soon as
	 * the caller calls revert_creds().
	 */
	if (cred != current->real_cred) {
		kfree(uuid);
		rc = -EINVAL;
		goto out;
	}
#endif
	/*
	 * Nothing to do if "struct uuid_security" was already associated with
	 * "struct cred".
	 */
	if (uuid_find_security(cred)) {
		kfree(uuid);
		goto out;
	}
	if (!uuid) {
		rc = -ENOMEM;
		goto out;
	}
	uuid->owner = cred;
	uuid_add_security(uuid);
	printk(KERN_INFO "Tagged task('%s',pid=%u)\n", current->comm,
	       current->pid);
 out:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
	spin_unlock(&uuid_alloc_lock);
#endif
	return rc;
}

static ssize_t uuid_write(struct file *file, const char __user *buf, size_t count,
			  loff_t *ppos)
{
	int rc;
	u8 uuid[UUID_SIZE] = {};
	const struct cred *cred = current_cred();
	struct uuid_security *ptr;
	/*
	 * Read UUID as big endian. Truncate if longer. Pad with 0 if shorter.
	 */
	if (count > UUID_SIZE)
		count = UUID_SIZE;
	if (copy_from_user(uuid + UUID_SIZE - count, buf, count))
		return -EFAULT;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
	/* We need to serialize because "struct cred" may be shared. */
	spin_lock(&uuid_alloc_lock);
	/*
	 * This function must not be called between override_creds() and
	 * revert_creds() because we loose "struct uuid_security" as soon as
	 * the caller calls revert_creds().
	 */
	if (cred != current->real_cred) {
		rc = -EINVAL;
		goto out;
	}
#endif
	ptr = uuid_find_security(cred);
	if (!ptr) {
		/*
		 * This won't happen because we allocate "struct uuid_security"
		 * upon open(). But in case something went wrong... 
		 */
		rc = -EINVAL;
		goto out;
	}
	/* Reject if UUID was already assigned. */
	if (ptr->uuid_configured) {
		rc = -EEXIST;
		goto out;
	}
	/* Assign UUID. */
	uuid_copy(ptr->uuid, uuid);
	/* Wait for UUID to be written. */
	smp_wmb();
	ptr->uuid_configured = 1;
	{
		char buf[UUID_PRINT_SIZE];
		uuid_print_uuid(ptr, buf);
		printk(KERN_INFO "Allocated %s on task('%s',pid=%u)\n", buf,
		       current->comm, current->pid);
	}
	rc = count;
out:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
	spin_unlock(&uuid_alloc_lock);
#endif
	return rc;
}

static ssize_t uuid_read(struct file *file, char __user *buf, size_t count,
			 loff_t *ppos)
{
	loff_t pos = *ppos;
	loff_t len = UUID_SIZE;
	const struct cred *cred = current_cred();
	struct uuid_security *ptr;
	if (pos >= len || !count)
		return 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
	/*
	 * This function must not be called between override_creds() and
	 * revert_creds() because we loose "struct uuid_security" as soon as
	 * the caller calls revert_creds().
	 */
	if (cred != current->real_cred)
		return -EINVAL;
#endif
	ptr = uuid_find_security(cred);
	if (!ptr)
		/*
		 * This won't happen because we allocate "struct uuid_security"
		 * upon open(). But in case something went wrong... 
		 */
		return -EINVAL;
	if (!ptr->uuid_configured)
		return 0;
	len -= pos;
	if (count < len)
		len = count;
	if (copy_to_user(buf, ((u8 *) ptr->uuid) + pos, len))
		return -EFAULT;
	*ppos += len;
	return len;
}

/* Operations for /proc/uuid interface. */
static
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 17)
const
#endif
struct file_operations uuid_operations = {
	.open  = uuid_open,
	.write = uuid_write,
	.read  = uuid_read,
};

////////////////////////////////////////////////////////
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)

/**
 * uuid_realpath_lock - Take locks for __d_path().
 *
 * Returns nothing.
 */
static inline void uuid_realpath_lock(void)
{
	/* dcache_lock is locked by __d_path(). */
	/* vfsmount_lock is locked by __d_path(). */
}

/**
 * uuid_realpath_unlock - Release locks for __d_path().
 *
 * Returns nothing.
 */
static inline void uuid_realpath_unlock(void)
{
	/* vfsmount_lock is unlocked by __d_path(). */
	/* dcache_lock is unlocked by __d_path(). */
}

#elif LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 36)

/**
 * uuid_realpath_lock - Take locks for __d_path().
 *
 * Returns nothing.
 */
static inline void uuid_realpath_lock(void)
{
	spin_lock(&dcache_lock);
	/* vfsmount_lock is locked by __d_path(). */
}

/**
 * uuid_realpath_unlock - Release locks for __d_path().
 *
 * Returns nothing.
 */
static inline void uuid_realpath_unlock(void)
{
	/* vfsmount_lock is unlocked by __d_path(). */
	spin_unlock(&dcache_lock);
}

#elif defined(D_PATH_DISCONNECT) && !defined(CONFIG_SUSE_KERNEL)

/**
 * uuid_realpath_lock - Take locks for __d_path().
 *
 * Returns nothing.
 *
 * Original unambiguous-__d_path.diff in patches.apparmor.tar.bz2 inversed the
 * order of holding dcache_lock and vfsmount_lock. That patch was applied on
 * (at least) SUSE 11.1 and Ubuntu 8.10 and Ubuntu 9.04 kernels.
 *
 * However, that patch was updated to use original order and the updated patch
 * is applied to (as far as I know) only SUSE kernels.
 *
 * Therefore, I need to use original order for SUSE 11.1 kernels and inversed
 * order for other kernels. I detect it by checking D_PATH_DISCONNECT and
 * CONFIG_SUSE_KERNEL. I don't know whether other distributions are using the
 * updated patch or not. If you got deadlock, check fs/dcache.c for locking
 * order, and add " && 0" to this "#elif " block if fs/dcache.c uses original
 * order.
 */
static inline void uuid_realpath_lock(void)
{
	spin_lock(uuid_exports.vfsmount_lock);
	spin_lock(&dcache_lock);
}

/**
 * uuid_realpath_unlock - Release locks for __d_path().
 *
 * Returns nothing.
 */
static inline void uuid_realpath_unlock(void)
{
	spin_unlock(&dcache_lock);
	spin_unlock(uuid_exports.vfsmount_lock);
}

#else

/**
 * uuid_realpath_lock - Take locks for __d_path().
 *
 * Returns nothing.
 */
static inline void uuid_realpath_lock(void)
{
	spin_lock(&dcache_lock);
	spin_lock(uuid_exports.vfsmount_lock);
}

/**
 * uuid_realpath_unlock - Release locks for __d_path()).
 *
 * Returns nothing.
 */
static inline void uuid_realpath_unlock(void)
{
	spin_unlock(uuid_exports.vfsmount_lock);
	spin_unlock(&dcache_lock);
}

#endif

/**
 * uuid_get_absolute_path - Get the path of a dentry but ignores chroot'ed root.
 *
 * @path:   Pointer to "struct path".
 * @buffer: Pointer to buffer to return value in.
 * @buflen: Sizeof @buffer.
 *
 * Returns the buffer on success, an error code otherwise.
 *
 * Caller holds the dcache_lock and vfsmount_lock.
 * Based on __d_path() in fs/dcache.c
 *
 * If dentry is a directory, trailing '/' is appended.
 */
static char *uuid_get_absolute_path(struct path *path, char * const buffer,
				    const int buflen)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
	char *pos = ERR_PTR(-ENOMEM);
	if (buflen >= 256) {
		struct path root = { };
		pos = uuid_exports.__d_path(path, &root, buffer, buflen - 1);
		if (!IS_ERR(pos) && *pos == '/' && pos[1]) {
			struct inode *inode = path->dentry->d_inode;
			if (inode && S_ISDIR(inode->i_mode)) {
				buffer[buflen - 2] = '/';
				buffer[buflen - 1] = '\0';
			}
		}
	}
	return pos;
#else
	char *pos = buffer + buflen - 1;
	struct dentry *dentry = path->dentry;
	struct vfsmount *vfsmnt = path->mnt;
	const char *name;
	int len;

	if (buflen < 256)
		goto out;

	*pos = '\0';
	if (dentry->d_inode && S_ISDIR(dentry->d_inode->i_mode))
		*--pos = '/';
	for (;;) {
		struct dentry *parent;
		if (dentry == vfsmnt->mnt_root || IS_ROOT(dentry)) {
			if (vfsmnt->mnt_parent == vfsmnt)
				break;
			dentry = vfsmnt->mnt_mountpoint;
			vfsmnt = vfsmnt->mnt_parent;
			continue;
		}
		parent = dentry->d_parent;
		name = dentry->d_name.name;
		len = dentry->d_name.len;
		pos -= len;
		if (pos <= buffer)
			goto out;
		memmove(pos, name, len);
		*--pos = '/';
		dentry = parent;
	}
	if (*pos == '/')
		pos++;
	len = dentry->d_name.len;
	pos -= len;
	if (pos < buffer)
		goto out;
	memmove(pos, dentry->d_name.name, len);
	return pos;
out:
	return ERR_PTR(-ENOMEM);
#endif
}

/**
 * uuid_get_dentry_path - Get the path of a dentry.
 *
 * @dentry: Pointer to "struct dentry".
 * @buffer: Pointer to buffer to return value in.
 * @buflen: Sizeof @buffer.
 *
 * Returns the buffer on success, an error code otherwise.
 *
 * Caller holds the dcache_lock.
 * Based on dentry_path() in fs/dcache.c
 *
 * If dentry is a directory, trailing '/' is appended.
 */
static char *uuid_get_dentry_path(struct dentry *dentry, char * const buffer,
				 const int buflen)
{
	char *pos = buffer + buflen - 1;
	if (buflen < 256)
		goto out;
	*pos = '\0';
	if (dentry->d_inode && S_ISDIR(dentry->d_inode->i_mode))
		*--pos = '/';
	while (!IS_ROOT(dentry)) {
		struct dentry *parent = dentry->d_parent;
		const char *name = dentry->d_name.name;
		const int len = dentry->d_name.len;
		pos -= len;
		if (pos <= buffer)
			goto out;
		memmove(pos, name, len);
		*--pos = '/';
		dentry = parent;
	}
	return pos;
out:
	return ERR_PTR(-ENOMEM);
}

/**
 * uuid_get_local_path - Get the path of a dentry.
 *
 * @path:   Pointer to "struct path".
 * @buffer: Pointer to buffer to return value in.
 * @buflen: Sizeof @buffer.
 *
 * Returns the buffer on success, an error code otherwise.
 */
static char *uuid_get_local_path(struct path *path, char * const buffer,
				const int buflen)
{
	char *pos;
	struct dentry *dentry = path->dentry;
	struct super_block *sb = dentry->d_sb;
	spin_lock(&dcache_lock);
	pos = uuid_get_dentry_path(dentry, buffer, buflen);
	spin_unlock(&dcache_lock);
	if (IS_ERR(pos))
		return pos;
	/* Convert from $PID to self if $PID is current thread. */
	if (sb->s_magic == PROC_SUPER_MAGIC && *pos == '/') {
		char *ep;
		const pid_t pid = (pid_t) simple_strtoul(pos + 1, &ep, 10);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
		if (*ep == '/' && pid && pid ==
		    task_tgid_nr_ns(current, sb->s_fs_info)) {
			pos = ep - 5;
			if (pos < buffer)
				goto out;
			memmove(pos, "/self", 5);
		}
#else
		if (*ep == '/' && pid == uuid_sys_getpid()) {
			pos = ep - 5;
			if (pos < buffer)
				goto out;
			memmove(pos, "/self", 5);
		}
#endif
		goto prepend_filesystem_name;
	}
	{
		struct inode *inode = sb->s_root->d_inode;
		/*
		 * Use filesystem name if filesystems does not support rename()
		 * operation.
		 */
		if (inode->i_op && !inode->i_op->rename)
			goto prepend_filesystem_name;
	}
	/* Prepend device name if vfsmount is not available. */
	if (!path->mnt) {
		char name[64] = { };
		int name_len;
		const dev_t dev = sb->s_dev;
		snprintf(name, sizeof(name) - 1, "dev(%u,%u):", MAJOR(dev),
			 MINOR(dev));
		name_len = strlen(name);
		pos -= name_len;
		if (pos < buffer)
			goto out;
		memmove(pos, name, name_len);
		return pos;
	}
	/* Prepend filesystem name. */
prepend_filesystem_name:
	{
		const char *name = sb->s_type->name;
		const int name_len = strlen(name);
		pos -= name_len + 1;
		if (pos < buffer)
			goto out;
		memmove(pos, name, name_len);
		pos[name_len] = ':';
	}
	return pos;
out:
	return ERR_PTR(-ENOMEM);
}

/**
 * uuid_get_socket_name - Get the name of a socket.
 *
 * @path:   Pointer to "struct path".
 * @buffer: Pointer to buffer to return value in.
 * @buflen: Sizeof @buffer.
 *
 * Returns the buffer.
 */
static char *uuid_get_socket_name(struct path *path, char * const buffer,
				 const int buflen)
{
	struct inode *inode = path->dentry->d_inode;
	struct socket *sock = inode ? SOCKET_I(inode) : NULL;
	struct sock *sk = sock ? sock->sk : NULL;
	if (sk) {
		snprintf(buffer, buflen, "socket:[family=%u:type=%u:"
			 "protocol=%u]", sk->sk_family, sk->sk_type,
			 sk->sk_protocol);
	} else {
		snprintf(buffer, buflen, "socket:[unknown]");
	}
	return buffer;
}

#define SOCKFS_MAGIC 0x534F434B

/**
 * uuid_realpath_from_path - Returns realpath(3) of the given pathname but ignores chroot'ed root.
 *
 * @path: Pointer to "struct path".
 *
 * Returns the realpath of the given @path on success, NULL otherwise.
 *
 * This function uses kzalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
static char *uuid_realpath_from_path(struct path *path)
{
	char *buf = NULL;
	char *name = NULL;
	unsigned int buf_len = PAGE_SIZE / 2;
	struct dentry *dentry = path->dentry;
	struct super_block *sb;
	if (!dentry)
		return NULL;
	sb = dentry->d_sb;
	while (1) {
		char *pos;
		struct inode *inode;
		buf_len <<= 1;
		kfree(buf);
		buf = kmalloc(buf_len, GFP_KERNEL);
		if (!buf)
			break;
		/* To make sure that pos is '\0' terminated. */
		buf[buf_len - 1] = '\0';
		/* Get better name for socket. */
		if (sb->s_magic == SOCKFS_MAGIC) {
			pos = uuid_get_socket_name(path, buf, buf_len - 1);
			goto encode;
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 22)
		/* For "pipe:[\$]". */
		if (dentry->d_op && dentry->d_op->d_dname) {
			pos = dentry->d_op->d_dname(dentry, buf, buf_len - 1);
			goto encode;
		}
#endif
		inode = sb->s_root->d_inode;
		/*
		 * Get local name for filesystems without rename() operation
		 * or dentry without vfsmount.
		 */
		if (!path->mnt || (inode->i_op && !inode->i_op->rename)) {
			pos = uuid_get_local_path(path, buf, buf_len - 1);
			goto encode;
		}
		/* Get absolute name for the rest. */
		uuid_realpath_lock();
		pos = uuid_get_absolute_path(path, buf, buf_len - 1);
		uuid_realpath_unlock();
encode:
		if (IS_ERR(pos))
			continue;
		name = uuid_encode(pos);
		break;
	}
	kfree(buf);
	return name;
}

/**
 * uuid_encode2 - Encode binary string to ascii string.
 *
 * @str:     String in binary format.
 * @str_len: Size of @str in byte.
 *
 * Returns pointer to @str in ascii format on success, NULL otherwise.
 *
 * This function uses kzalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
static char *uuid_encode2(const char *str, int str_len)
{
	int i;
	int len = 0;
	const char *p = str;
	char *cp;
	char *cp0;
	if (!p)
		return NULL;
	for (i = 0; i < str_len; i++) {
		const unsigned char c = p[i];
		if (c == '\\')
			len += 2;
		else if (c > ' ' && c < 127)
			len++;
		else
			len += 4;
	}
	len++;
	/* Reserve space for appending "/". */
	cp = kzalloc(len + 10, GFP_KERNEL);
	if (!cp)
		return NULL;
	cp0 = cp;
	p = str;
	for (i = 0; i < str_len; i++) {
		const unsigned char c = p[i];
		if (c == '\\') {
			*cp++ = '\\';
			*cp++ = '\\';
		} else if (c > ' ' && c < 127) {
			*cp++ = c;
		} else {
			*cp++ = '\\';
			*cp++ = (c >> 6) + '0';
			*cp++ = ((c >> 3) & 7) + '0';
			*cp++ = (c & 7) + '0';
		}
	}
	return cp0;
}

/**
 * uuid_encode - Encode binary string to ascii string.
 *
 * @str: String in binary format.
 *
 * Returns pointer to @str in ascii format on success, NULL otherwise.
 *
 * This function uses kzalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
static char *uuid_encode(const char *str)
{
	return str ? uuid_encode2(str, strlen(str)) : NULL;
}
////////////////////////////////////////////////////////


/* Wait queue for kernel -> userspace notification. */
static DECLARE_WAIT_QUEUE_HEAD(uuid_query_wait);
/* Wait queue for userspace -> kernel notification. */
static DECLARE_WAIT_QUEUE_HEAD(uuid_answer_wait);

static DEFINE_MUTEX(uuid_query_mutex);
static DEFINE_SPINLOCK(uuid_answer_lock);
static char uuid_query_buf[32768];
static int uuid_query_buf_len;
static unsigned int uuid_answer;
static unsigned int uuid_serial;

/* Number of "struct file" referring /proc/uuid_query interface. */
static atomic_t uuid_query_observers = ATOMIC_INIT(0);

static int uuid_supervisor(struct uuid_query_param *p)
{
	int len;
	int error;
	struct uuid_security *ptr = uuid_find_security(current_cred());
	char buf_sbj[UUID_PRINT_SIZE];
	char *path;
	return 0; // for now.
	if (!ptr) {
		/*
		 * This won't happen because we check only "half-restricted"
		 * and "restricted" tasks. But in case something went wrong... 
		 */
		printk(KERN_INFO "%s: NULL security.\n", __func__);
		return -EPERM;
	}
	if (!atomic_read(&uuid_query_observers)) {
		printk(KERN_INFO "%s: No listener.\n", __func__);
		return -EPERM;
	}
	if (mutex_lock_interruptible(&uuid_query_mutex)) {
		printk(KERN_INFO "%s: Interrupted.\n", __func__);
		return -EPERM;
	}
	path = uuid_realpath_from_path(&p->path);
	if (!path) {
		printk(KERN_INFO "%s: Out of memory.\n", __func__);
		error = -ENOMEM;
		goto out;
	}
	spin_lock(&uuid_answer_lock);
	len = ++uuid_serial;
	uuid_answer = 0;
	spin_unlock(&uuid_answer_lock);
	uuid_print_uuid(ptr, buf_sbj);
	snprintf(uuid_query_buf, sizeof(uuid_query_buf) - 1,
		 "Q%u\nUUID=%s uid=%u gid=%u euid=%u egid=%u suid=%u "
		 "sgid=%u fsuid=%u fsgid=%u\n", len, buf_sbj,
		 current_uid(), current_gid(), current_euid(), current_egid(),
		 current_suid(), current_sgid(), current_fsuid(),
		 current_fsgid());
	len = strlen(uuid_query_buf);
	snprintf(uuid_query_buf + len, sizeof(uuid_query_buf) - 1 - len,
		 "%s %s", p->operation, path);
	kfree(path);
	uuid_query_buf_len = strlen(uuid_query_buf) + 1;
	wake_up_all(&uuid_query_wait);
	wait_event_interruptible_timeout(uuid_answer_wait, uuid_answer ||
					 !atomic_read(&uuid_query_observers),
					 10 * HZ);
	error = uuid_answer == 1 ? 0 : -EPERM;
	uuid_query_buf_len = 0;
out:
	mutex_unlock(&uuid_query_mutex);
	return error;
}

static int uuid_open_query(struct inode *inode, struct file *file)
{
	atomic_inc(&uuid_query_observers);
	return 0;
}

static int uuid_close_query(struct inode *inode, struct file *file)
{
	if (atomic_dec_and_test(&uuid_query_observers))
		wake_up_all(&uuid_answer_wait);
	return 0;
}

static ssize_t uuid_read_query(struct file *file, char __user *buf,
			       size_t count, loff_t *ppos)
{
	int len;
	wait_event_interruptible(uuid_query_wait, uuid_query_buf_len);
	len = uuid_query_buf_len;
	if (!len || !count)
		return 0;
	if (count < len)
		len = count;
	if (copy_to_user(buf, uuid_query_buf, len))
		return -EFAULT;
	uuid_query_buf_len -= len;
	memmove(uuid_query_buf, uuid_query_buf + len, uuid_query_buf_len);
	return len;
}

static ssize_t uuid_write_query(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	char tmp[128];
	unsigned int serial;
	unsigned int answer;
	if (!count)
		return 0;
	if (count > sizeof(tmp))
		count = sizeof(tmp);
	if (copy_from_user(tmp, buf, count))
		return -EFAULT;
	if (tmp[count - 1] || sscanf(tmp, "A%u=%u", &serial, &answer) != 2)
		return -EINVAL;
	spin_lock(&uuid_answer_lock);
	if (serial == uuid_serial)
		uuid_answer = answer;
	spin_unlock(&uuid_answer_lock);
	wake_up_all(&uuid_answer_wait);
	return count;
}

/* Operations for /proc/uuid_query interface. */
static
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 17)
const
#endif
struct file_operations uuid_query_operations = {
	.open    = uuid_open_query,
	.write   = uuid_write_query,
	.read    = uuid_read_query,
	.release = uuid_close_query,
};

static ssize_t uuid_read_config(struct file *file, char __user *buf,
				size_t count, loff_t *ppos)
{
	loff_t i = *ppos;
	char tmp[128];
	if (count < sizeof(tmp))
		return -EINVAL;
	if (i < 0 || i >= UUID_MAX_OPERATIONS)
		return 0;
	snprintf(tmp, sizeof(tmp) - 1, "%s: %03o\n", uuid_prompt[i],
		 uuid_config[i]);
	count = strlen(tmp);
	if (copy_to_user(buf, tmp, count))
		return -EFAULT;
	(*ppos)++;
	return count;
}

static ssize_t uuid_write_config(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	char tmp[128];
	char *cp;
	int i;
	if (!count)
		return 0;
	if (count > sizeof(tmp))
		count = sizeof(tmp);
	if (copy_from_user(tmp, buf, count))
		return -EFAULT;
	cp = memchr(tmp, '\n', count);
	if (!cp)
		return -EINVAL;
	*cp = '\0';
	count = cp - tmp + 1;
	cp = strchr(tmp, ':');
	if (!cp)
		return -EINVAL;
	*cp++ = '\0';
	for (i = 0; i < UUID_MAX_OPERATIONS; i++) {
		unsigned int perm;
		if (strcmp(tmp, uuid_prompt[i]))
			continue;
		if (sscanf(cp, "%o", &perm) == 1 && perm <= 0777) {
			uuid_config[i] = perm;
			return count;
		}
		break;
	}
	return -EINVAL;
}

/* Operations for /proc/uuid_config interface. */
static
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 17)
const
#endif
struct file_operations uuid_config_operations = {
	.write   = uuid_write_config,
	.read    = uuid_read_config,
};

static ssize_t uuid_write_status(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	char tmp[128];
	char *cp;
	unsigned int pid;
	if (!count)
		return 0;
	if (count > sizeof(tmp))
		count = sizeof(tmp);
	if (copy_from_user(tmp, buf, count))
		return -EFAULT;
	cp = memchr(tmp, '\n', count);
	if (!cp)
		return -EINVAL;
	*cp = '\0';
	if (sscanf(tmp, "%u", &pid) != 1)
		return -EINVAL;
	file->private_data = ERR_PTR(pid);
	return count;
}

static ssize_t uuid_read_status(struct file *file, char __user *buf,
				size_t count, loff_t *ppos)
{
	char tmp[128];
	struct task_struct *p;
	const unsigned int pid = PTR_ERR(file->private_data);
	if (count < sizeof(tmp))
		return -EINVAL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18)
	/* 2.6.18 and later uses rcu_read_lock(). */
	read_lock(&tasklist_lock);
#endif
	rcu_read_lock();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
	p = uuid_exports.find_task_by_vpid(pid);
#else
	p = find_task_by_pid(pid);
#endif
	if (p) {
		char uuid[UUID_PRINT_SIZE];
		struct uuid_security *ptr =
			uuid_find_security(__task_cred(p));
		uuid_print_uuid(ptr, uuid);
		snprintf(tmp, sizeof(tmp) - 1,
			 "%u %s\n", pid, uuid);
	} else {
		printk(KERN_INFO "%s: task not found.\n", __func__);
		tmp[0] = '\0';
	}
	rcu_read_unlock();
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18)
	/* 2.6.18 and later uses rcu_read_unlock(). */
	read_unlock(&tasklist_lock);
#endif
	count = strlen(tmp);
	if (copy_to_user(buf, tmp, count))
		return -EFAULT;
	return count;
}

/* Operations for /proc/uuid_status interface. */
static
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 17)
const
#endif
struct file_operations uuid_status_operations = {
	.write   = uuid_write_status,
	.read    = uuid_read_status,
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
	if (!uuid_find_vfsmount_lock())
		return -EINVAL;
	if (!uuid_find_find_task_by_pid())
		return -EINVAL;
	for (idx = 0; idx < UUID_MAX_SECURITY_HASH; idx++)
		INIT_LIST_HEAD(&uuid_security_list[idx]);
	entry = create_proc_entry("uuid", 0666, NULL);
	if (!entry)
		goto out_clean;
	entry->proc_fops = &uuid_operations;
	entry = create_proc_entry("uuid_config", 0600, NULL);
	if (!entry)
		goto out_clean;
	entry->proc_fops = &uuid_config_operations;
	entry = create_proc_entry("uuid_status", 0600, NULL);
	if (!entry)
		goto out_clean;
	entry->proc_fops = &uuid_status_operations;
	entry = create_proc_entry("uuid_query", 0600, NULL);
	if (!entry)
		goto out_clean;
	entry->proc_fops = &uuid_query_operations;
	uuid_update_security_ops(ops);
	printk(KERN_INFO "UUID: 0.0.0   2011/01/04\n");
	return 0;
out_clean:
	remove_proc_entry("uuid_query", NULL);
	remove_proc_entry("uuid_status", NULL);
	remove_proc_entry("uuid_config", NULL);
	remove_proc_entry("uuid", NULL);
	return -EINVAL;
}

module_init(uuid_init);
MODULE_LICENSE("GPL");

#if 0
/*
 * This is a userspace daemon that acks unconditionally.
 * You can modify this program to nack as needed.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char *argv[])
{
	int fd = open("/proc/uuid_query", O_RDWR);
	static char buffer[32768];
	if (fd == EOF)
		return 1;
	while (1) {
		unsigned int serial;
		char *cp;
		memset(buffer, 0, sizeof(buffer));
		if (read(fd, buffer, sizeof(buffer) - 1) <= 0) {
			sleep(1);
			continue;
		}
		cp = strchr(buffer, '\n');
		if (!cp)
			continue;
		*cp = '\0';
		if (sscanf(buffer, "Q%u", &serial) != 1)
			continue;
		printf("Q=%u\n%s\n", serial, cp + 1);
		fflush(stdout);
		snprintf(buffer, sizeof(buffer) - 1, "A%u=1", serial);
		write(fd, buffer, strlen(buffer) + 1);
	}
	return 0;
}

#endif
