/*
 * check.c
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
 *  (3) Restrict opening files by using external configuration files.
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
 * Permission to open a file by unrestricted subject and half-restricted
 * subject are always granted and by restricted subject is granted only when
 * explicitly listed in /etc/uuid/$UUID file or /etc/uuid/common file.
 * By performance reason, permission to read()/write()/ioctl() etc. are not
 * checked.
 *
 * To compile, put this file as check.c on some directory under kernel's
 * source directory (e.g. uuid/check.c ) and also put probe.h and probe.c on
 * the same directory and run below commands.
 *
 * # echo 'uuid-objs := check.o probe.o' > uuid/Makefile 
 * # echo 'obj-m += uuid.o' >> uuid/Makefile
 * # make -s SUBDIRS=$PWD/uuid modules
 * # make -s SUBDIRS=$PWD/uuid modules_install
 *
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
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
#include <linux/namespace.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36) && LINUX_VERSION_CODE < KERNEL_VERSION(3, 2, 0)
#include <linux/nsproxy.h>
#include <linux/mnt_namespace.h>
#endif
#include "probe.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 0)
#error This module supports only 2.6.0 and later kernels.
#endif
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
	char * (*d_absolute_path) (const struct path *, char *, int);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
	typeof(__d_path) (*__d_path);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
	spinlock_t *vfsmount_lock;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
	struct task_struct * (*find_task_by_vpid) (pid_t nr);
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
	u8 uuid_recursive;
	struct rcu_head rcu;
};

struct uuid_query_param {
	struct uuid_security *uuid;
	const char *operation;
	struct path path;
};

static int uuid_supervisor(struct uuid_query_param *p);

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)

static int uuid_check_cred(const struct cred *cred,
			    const enum uuid_operation_index index)
{
	struct uuid_security *sbj;
	struct uuid_security *obj;
	int ret = 0;
	char buf_sbj[UUID_PRINT_SIZE];
	char buf_obj[UUID_PRINT_SIZE];
	u16 perm;
	if (cred == current_cred())
		return 0;
	perm = uuid_config[index];
	rcu_read_lock();
	sbj = uuid_find_security(current_cred());
	obj = uuid_find_security(cred);
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
	       "cred('%s') at %s\n", buf_sbj, current->comm, current->pid,
	       buf_obj, uuid_prompt[index]);
	ret = -EPERM;
ok:
	rcu_read_unlock();
	return ret;
}

#endif

static int uuid_check_task(struct task_struct *task,
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0)

static int uuid_capable(const struct cred *cred, struct user_namespace *ns,
			int cap, int audit)
{
	if (uuid_check_cred(cred, UUID_CAPABLE))
		return -EPERM;
	while (!original_security_ops.capable);
	return original_security_ops.capable(cred, ns, cap, audit);
}

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)

static int uuid_capable(struct task_struct *tsk, const struct cred *cred,
			struct user_namespace *ns, int cap, int audit)
{
	if (uuid_check_cred(cred, UUID_CAPABLE))
		return -EPERM;
	while (!original_security_ops.capable);
	return original_security_ops.capable(tsk, cred, ns, cap, audit);
}

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)

static int uuid_capable(struct task_struct *tsk, const struct cred *cred,
			int cap, int audit)
{
	if (uuid_check_cred(cred, UUID_CAPABLE))
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
	/*
	char buf_sbj[UUID_PRINT_SIZE];
	char buf_obj[UUID_PRINT_SIZE];
	*/
	int rc = uuid_copy_security(inode, current_cred(), GFP_NOFS);
	if (rc)
		return rc;
	/*
	uuid_print_uuid(uuid_find_security(current_cred()), buf_sbj);
	uuid_print_uuid(uuid_find_security(inode), buf_obj);
	printk(KERN_DEBUG "Allocated inode(%s) by "
	       "task(%s) ('%s',pid=%u) (%p)\n",
	       buf_obj, buf_sbj, current->comm,
	       current->pid, inode);
	*/
	while (!original_security_ops.inode_alloc_security);
	rc = original_security_ops.inode_alloc_security(inode);
	if (rc)
		uuid_del_security(uuid_find_security(inode));
	return rc;
}

static void uuid_inode_free_security(struct inode *inode)
{
	while (!original_security_ops.inode_free_security);
	original_security_ops.inode_free_security(inode);
	uuid_del_security(uuid_find_security(inode));
}

#ifdef CONFIG_SECURITY_NETWORK

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)

static int uuid_unix_stream_connect(struct sock *sock, struct sock *other,
				    struct sock *newsk)
{
	struct socket *s = other->sk_socket;
	if (s) {
		int rc = uuid_check_socket(s, UUID_UNIX_STREAM_CONNECT);
		if (rc)
			return rc;
	}
	while (!original_security_ops.unix_stream_connect);
	return original_security_ops.unix_stream_connect(sock, other, newsk);
}

#else

static int uuid_unix_stream_connect(struct socket *sock, struct socket *other,
				    struct sock *newsk)
{
	int rc = uuid_check_socket(other, UUID_UNIX_STREAM_CONNECT);
	if (rc)
		return rc;
	while (!original_security_ops.unix_stream_connect);
	return original_security_ops.unix_stream_connect(sock, other, newsk);
}

#endif

static int uuid_unix_may_send(struct socket *sock, struct socket *other)
{
	int rc = uuid_check_socket(other, UUID_UNIX_MAY_SEND);
	if (rc)
		return rc;
	while (!original_security_ops.unix_may_send);
	return original_security_ops.unix_may_send(sock, other);
}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)

/**
 * uuid_file_open - Check permission for open().
 *
 * @f:    Pointer to "struct file".
 * @cred: Pointer to "struct cred".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int uuid_file_open(struct file *f, const struct cred *cred)
{
	struct uuid_security *uuid;
	int rc = uuid_check_pipe(f->f_dentry->d_inode, UUID_OPEN_PIPE);
	if (rc)
		return rc;
	uuid = uuid_find_security(current_cred());
	if (uuid && uuid->uuid_configured && !uuid->uuid_recursive) {
		struct uuid_query_param p = { };
		p.uuid = uuid;
		p.operation = "file open";
		p.path = f->f_path;
		rc = uuid_supervisor(&p);
		if (rc)
			return rc;
	}
	while (!original_security_ops.file_open);
	return original_security_ops.file_open(f, cred);
}

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)

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
	struct uuid_security *uuid;
	int rc = uuid_check_pipe(f->f_dentry->d_inode, UUID_OPEN_PIPE);
	if (rc)
		return rc;
	uuid = uuid_find_security(current_cred());
	if (uuid && uuid->uuid_configured && !uuid->uuid_recursive) {
		struct uuid_query_param p = { };
		p.uuid = uuid;
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
	struct uuid_security *uuid;
	int rc = uuid_check_pipe(f->f_dentry->d_inode, UUID_OPEN_PIPE);
	if (rc)
		return rc;
	uuid = uuid_find_security(current_cred());
	if (uuid && uuid->uuid_configured && !uuid->uuid_recursive) {
		struct uuid_query_param p = { };
		p.uuid = uuid;
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
	struct uuid_security *uuid;
	int rc = uuid_check_pipe(inode, UUID_OPEN_PIPE);
	if (rc)
		return rc;
	uuid = uuid_find_security(current);
	if (nd && nd->dentry && uuid && !uuid->uuid_recursive) {
		struct uuid_query_param p = { };
		p.uuid = uuid;
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	swap_security_ops(file_open);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
	char *pos = ERR_PTR(-ENOMEM);
	if (buflen >= 256) {
		pos = uuid_exports.d_absolute_path(path, buffer, buflen - 1);
		if (!IS_ERR(pos) && *pos == '/' && pos[1]) {
			struct inode *inode = path->dentry->d_inode;
			if (inode && S_ISDIR(inode->i_mode)) {
				buffer[buflen - 2] = '/';
				buffer[buflen - 1] = '\0';
			}
		}
	}
	return pos;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
	/*
	 * __d_path() will start returning NULL by backporting commit 02125a82
	 * "fix apparmor dereferencing potentially freed dentry, sanitize
	 * __d_path() API".
	 *
	 * Unfortunately, __d_path() after applying that commit always returns
	 * NULL when root is empty. d_absolute_path() is provided for TOMOYO
	 * 2.x and AppArmor but TOMOYO 1.x does not use it, for TOMOYO 1.x
	 * might be built as a loadable kernel module and there is no warrantee
	 * that TOMOYO 1.x is recompiled after applying that commit. Also,
	 * I don't want to search /proc/kallsyms for d_absolute_path() because
	 * I want to keep TOMOYO 1.x architecture independent. Thus, supply
	 * non empty root like AppArmor's d_namespace_path() did.
	 */
	char *pos = ERR_PTR(-ENOMEM);
	if (buflen >= 256) {
		static bool uuid_no_empty;
		if (!uuid_no_empty) {
			struct path root = { };
			pos = uuid_exports.__d_path(path, &root, buffer,
						    buflen - 1);
		} else {
			pos = NULL;
		}
		if (!pos) {
			struct task_struct *task = current;
			struct path root;
			struct path tmp;
			spin_lock(&task->fs->lock);
			root.mnt = task->nsproxy->mnt_ns->root;
			root.dentry = root.mnt->mnt_root;
			path_get(&root);
			spin_unlock(&task->fs->lock);
			tmp = root;
			pos = uuid_exports.__d_path(path, &tmp, buffer,
						    buflen - 1);
			path_put(&root);
			if (!pos)
				return ERR_PTR(-EINVAL);
			/* Remember if __d_path() needs non empty root. */
			uuid_no_empty = true;
		}
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
	char *pos = ERR_PTR(-ENOMEM);
	if (buflen >= 256) {
		/* rename_lock is locked/unlocked by dentry_path_raw(). */
		pos = dentry_path_raw(dentry, buffer, buflen - 1);
		if (!IS_ERR(pos) && *pos == '/' && pos[1]) {
			struct inode *inode = dentry->d_inode;
			if (inode && S_ISDIR(inode->i_mode)) {
				buffer[buflen - 2] = '/';
				buffer[buflen - 1] = '\0';
			}
		}
	}
	return pos;
#else
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
#endif
}

/**
 * uuid_get_local_path - Get the path of a dentry.
 *
 * @dentry: Pointer to "struct dentry".
 * @buffer: Pointer to buffer to return value in.
 * @buflen: Sizeof @buffer.
 *
 * Returns the buffer on success, an error code otherwise.
 */
static char *uuid_get_local_path(struct dentry *dentry, char * const buffer,
				const int buflen)
{
	char *pos;
	struct super_block *sb = dentry->d_sb;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38)
	spin_lock(&dcache_lock);
#endif
	pos = uuid_get_dentry_path(dentry, buffer, buflen);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38)
	spin_unlock(&dcache_lock);
#endif
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
	/* Use filesystem name for unnamed devices. */
	if (!MAJOR(sb->s_dev))
		goto prepend_filesystem_name;
	{
		struct inode *inode = sb->s_root->d_inode;
		/*
		 * Use filesystem name if filesystems does not support rename()
		 * operation.
		 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0)
		if (inode->i_op && !inode->i_op->rename)
			goto prepend_filesystem_name;
#else
		if (!inode->i_op->rename && !inode->i_op->rename2)
			goto prepend_filesystem_name;
#endif
	}
	/* Prepend device name. */
	{
		char name[64];
		int name_len;
		const dev_t dev = sb->s_dev;
		name[sizeof(name) - 1] = '\0';
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
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0)
		if (!path->mnt || (inode->i_op && !inode->i_op->rename)) {
			pos = uuid_get_local_path(path->dentry, buf,
						  buf_len - 1);
			goto encode;
		}
#else
		if (!path->mnt ||
		    (!inode->i_op->rename && !inode->i_op->rename2)) {
			pos = uuid_get_local_path(path->dentry, buf,
						  buf_len - 1);
			goto encode;
		}
#endif
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

/**
 * uuid_byte_range - Check whether the string is a \ooo style octal value.
 *
 * @str: Pointer to the string.
 *
 * Returns true if @str is a \ooo style octal value, false otherwise.
 */
static bool uuid_byte_range(const char *str)
{
	return *str >= '0' && *str++ <= '3' &&
		*str >= '0' && *str++ <= '7' &&
		*str >= '0' && *str <= '7';
}

/**
 * uuid_decimal - Check whether the character is a decimal character.
 *
 * @c: The character to check.
 *
 * Returns true if @c is a decimal character, false otherwise.
 */
static bool uuid_decimal(const char c)
{
	return c >= '0' && c <= '9';
}

/**
 * uuid_hexadecimal - Check whether the character is a hexadecimal character.
 *
 * @c: The character to check.
 *
 * Returns true if @c is a hexadecimal character, false otherwise.
 */
static bool uuid_hexadecimal(const char c)
{
	return (c >= '0' && c <= '9') ||
		(c >= 'A' && c <= 'F') ||
		(c >= 'a' && c <= 'f');
}

/**
 * uuid_alphabet_char - Check whether the character is an alphabet.
 *
 * @c: The character to check.
 *
 * Returns true if @c is an alphabet character, false otherwise.
 */
static bool uuid_alphabet_char(const char c)
{
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

/**
 * uuid_make_byte - Make byte value from three octal characters.
 *
 * @c1: The first character.
 * @c2: The second character.
 * @c3: The third character.
 *
 * Returns byte value.
 */
static u8 uuid_make_byte(const u8 c1, const u8 c2, const u8 c3)
{
	return ((c1 - '0') << 6) + ((c2 - '0') << 3) + (c3 - '0');
}

/**
 * uuid_correct_word2 - Check whether the given string follows the naming rules.
 *
 * @string: The byte sequence to check. Not '\0'-terminated.
 * @len:    Length of @string.
 *
 * Returns true if @string follows the naming rules, false otherwise.
 */
static bool uuid_correct_word2(const char *string, size_t len)
{
	const char *const start = string;
	bool in_repetition = false;
	unsigned char c;
	unsigned char d;
	unsigned char e;
	if (!len)
		goto out;
	while (len--) {
		c = *string++;
		if (c == '\\') {
			if (!len--)
				goto out;
			c = *string++;
			switch (c) {
			case '\\':  /* "\\" */
				continue;
			case '$':   /* "\$" */
			case '+':   /* "\+" */
			case '?':   /* "\?" */
			case '*':   /* "\*" */
			case '@':   /* "\@" */
			case 'x':   /* "\x" */
			case 'X':   /* "\X" */
			case 'a':   /* "\a" */
			case 'A':   /* "\A" */
			case '-':   /* "\-" */
				continue;
			case '{':   /* "/\{" */
				if (string - 3 < start || *(string - 3) != '/')
					break;
				in_repetition = true;
				continue;
			case '}':   /* "\}/" */
				if (*string != '/')
					break;
				if (!in_repetition)
					break;
				in_repetition = false;
				continue;
			case '0':   /* "\ooo" */
			case '1':
			case '2':
			case '3':
				if (!len-- || !len--)
					break;
				d = *string++;
				e = *string++;
				if (d < '0' || d > '7' || e < '0' || e > '7')
					break;
				c = uuid_make_byte(c, d, e);
				if (c <= ' ' || c >= 127)
					continue;
			}
			goto out;
		} else if (in_repetition && c == '/') {
			goto out;
		} else if (c <= ' ' || c >= 127) {
			goto out;
		}
	}
	if (in_repetition)
		goto out;
	return true;
out:
	return false;
}

/**
 * uuid_correct_word - Check whether the given string follows the naming rules.
 *
 * @string: The string to check.
 *
 * Returns true if @string follows the naming rules, false otherwise.
 */
static bool uuid_correct_word(const char *string)
{
	return uuid_correct_word2(string, strlen(string));
}

/**
 * uuid_file_matches_pattern2 - Pattern matching without '/' character and "\-" pattern.
 *
 * @filename:     The start of string to check.
 * @filename_end: The end of string to check.
 * @pattern:      The start of pattern to compare.
 * @pattern_end:  The end of pattern to compare.
 *
 * Returns true if @filename matches @pattern, false otherwise.
 */
static bool uuid_file_matches_pattern2(const char *filename,
				      const char *filename_end,
				      const char *pattern,
				      const char *pattern_end)
{
	while (filename < filename_end && pattern < pattern_end) {
		char c;
		if (*pattern != '\\') {
			if (*filename++ != *pattern++)
				return false;
			continue;
		}
		c = *filename;
		pattern++;
		switch (*pattern) {
			int i;
			int j;
		case '?':
			if (c == '/') {
				return false;
			} else if (c == '\\') {
				if (filename[1] == '\\')
					filename++;
				else if (uuid_byte_range(filename + 1))
					filename += 3;
				else
					return false;
			}
			break;
		case '\\':
			if (c != '\\')
				return false;
			if (*++filename != '\\')
				return false;
			break;
		case '+':
			if (!uuid_decimal(c))
				return false;
			break;
		case 'x':
			if (!uuid_hexadecimal(c))
				return false;
			break;
		case 'a':
			if (!uuid_alphabet_char(c))
				return false;
			break;
		case '0':
		case '1':
		case '2':
		case '3':
			if (c == '\\' && uuid_byte_range(filename + 1)
			    && !strncmp(filename + 1, pattern, 3)) {
				filename += 3;
				pattern += 2;
				break;
			}
			return false; /* Not matched. */
		case '*':
		case '@':
			for (i = 0; i <= filename_end - filename; i++) {
				if (uuid_file_matches_pattern2(filename + i,
							      filename_end,
							      pattern + 1,
							      pattern_end))
					return true;
				c = filename[i];
				if (c == '.' && *pattern == '@')
					break;
				if (c != '\\')
					continue;
				if (filename[i + 1] == '\\')
					i++;
				else if (uuid_byte_range(filename + i + 1))
					i += 3;
				else
					break; /* Bad pattern. */
			}
			return false; /* Not matched. */
		default:
			j = 0;
			c = *pattern;
			if (c == '$') {
				while (uuid_decimal(filename[j]))
					j++;
			} else if (c == 'X') {
				while (uuid_hexadecimal(filename[j]))
					j++;
			} else if (c == 'A') {
				while (uuid_alphabet_char(filename[j]))
					j++;
			}
			for (i = 1; i <= j; i++) {
				if (uuid_file_matches_pattern2(filename + i,
							      filename_end,
							      pattern + 1,
							      pattern_end))
					return true;
			}
			return false; /* Not matched or bad pattern. */
		}
		filename++;
		pattern++;
	}
	while (*pattern == '\\' &&
	       (*(pattern + 1) == '*' || *(pattern + 1) == '@'))
		pattern += 2;
	return filename == filename_end && pattern == pattern_end;
}

/**
 * uuid_file_matches_pattern - Pattern matching without '/' character.
 *
 * @filename:     The start of string to check.
 * @filename_end: The end of string to check.
 * @pattern:      The start of pattern to compare.
 * @pattern_end:  The end of pattern to compare.
 *
 * Returns true if @filename matches @pattern, false otherwise.
 */
static bool uuid_file_matches_pattern(const char *filename,
				     const char *filename_end,
				     const char *pattern,
				     const char *pattern_end)
{
	const char *pattern_start = pattern;
	bool first = true;
	bool result;
	while (pattern < pattern_end - 1) {
		/* Split at "\-" pattern. */
		if (*pattern++ != '\\' || *pattern++ != '-')
			continue;
		result = uuid_file_matches_pattern2(filename, filename_end,
						   pattern_start, pattern - 2);
		if (first)
			result = !result;
		if (result)
			return false;
		first = false;
		pattern_start = pattern;
	}
	result = uuid_file_matches_pattern2(filename, filename_end,
					   pattern_start, pattern_end);
	return first ? result : !result;
}

/**
 * uuid_path_matches_pattern2 - Do pathname pattern matching.
 *
 * @f: The start of string to check.
 * @p: The start of pattern to compare.
 *
 * Returns true if @f matches @p, false otherwise.
 */
static bool uuid_path_matches_pattern2(const char *f, const char *p)
{
	const char *f_delimiter;
	const char *p_delimiter;
	while (*f && *p) {
		f_delimiter = strchr(f, '/');
		if (!f_delimiter)
			f_delimiter = f + strlen(f);
		p_delimiter = strchr(p, '/');
		if (!p_delimiter)
			p_delimiter = p + strlen(p);
		if (*p == '\\' && *(p + 1) == '{')
			goto recursive;
		if (!uuid_file_matches_pattern(f, f_delimiter, p, p_delimiter))
			return false;
		f = f_delimiter;
		if (*f)
			f++;
		p = p_delimiter;
		if (*p)
			p++;
	}
	/* Ignore trailing "\*" and "\@" in @pattern. */
	while (*p == '\\' &&
	       (*(p + 1) == '*' || *(p + 1) == '@'))
		p += 2;
	return !*f && !*p;
recursive:
	/*
	 * The "\{" pattern is permitted only after '/' character.
	 * This guarantees that below "*(p - 1)" is safe.
	 * Also, the "\}" pattern is permitted only before '/' character
	 * so that "\{" + "\}" pair will not break the "\-" operator.
	 */
	if (*(p - 1) != '/' || p_delimiter <= p + 3 || *p_delimiter != '/' ||
	    *(p_delimiter - 1) != '}' || *(p_delimiter - 2) != '\\')
		return false; /* Bad pattern. */
	do {
		/* Compare current component with pattern. */
		if (!uuid_file_matches_pattern(f, f_delimiter, p + 2,
					      p_delimiter - 2))
			break;
		/* Proceed to next component. */
		f = f_delimiter;
		if (!*f)
			break;
		f++;
		/* Continue comparison. */
		if (uuid_path_matches_pattern2(f, p_delimiter + 1))
			return true;
		f_delimiter = strchr(f, '/');
	} while (f_delimiter);
	return false; /* Not matched. */
}
////////////////////////////////////////////////////////

static int uuid_check_perm(const struct uuid_query_param *p,
			   struct file *file1, struct file *file2,
			   const char *path, char *page)
{
	int len;
	unsigned long offset;
	const int op_len = strlen(p->operation);
	struct file *file = file1;
restart:
	if (IS_ERR(file) || !file)
		goto skip;
	offset = 0;
	while ((len = kernel_read(file, offset, page, PAGE_SIZE - 1)) > 0) {
		char *line = page;
		page[len] = '\0';
		while (1) {
			char *cp = strchr(line, '\n');
			if (!cp)
				break;
			*cp++ = '\0';
			offset += cp - line;
			if (strncmp(line, p->operation, op_len) ||
			    line[op_len] != ' ' ||
			    !uuid_correct_word(line + op_len + 1) ||
			    !uuid_path_matches_pattern2(path,
							line + op_len + 1)) {
				line = cp;
				continue;
			}
			printk(KERN_INFO "%s: Granted %s %s .\n",
			       __func__, p->operation, path);
			return 0;
		} 
	}
skip:
	if (file == file1 && file1 != file2) {
		file = file2;
		goto restart;
	}
	printk(KERN_INFO "%s: Rejected %s %s .\n", __func__,
	       p->operation, path);
	return -EPERM;
}

static int uuid_supervisor(struct uuid_query_param *p)
{
	int error;
	char *page;
	struct file *file1;
	struct file *file2;
	char *path;
	page = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!page) {
		printk(KERN_INFO "%s: Out of memory.\n", __func__);
		return -ENOMEM;
	}
	{
		char buf[UUID_PRINT_SIZE];
		uuid_print_uuid(p->uuid, buf);
		snprintf(page, PAGE_SIZE - 1, "/etc/uuid/%s", buf);
		page[PAGE_SIZE - 1] = '\0';
	}
	p->uuid->uuid_recursive++;
	file1 = filp_open(page, O_RDONLY, 0);
	file2 = filp_open("/etc/uuid/common", O_RDONLY, 0);
	p->uuid->uuid_recursive--;
	path = uuid_realpath_from_path(&p->path);
	if (!path) {
		printk(KERN_INFO "%s: Out of memory.\n", __func__);
		error = -ENOMEM;
	} else {
		error = uuid_check_perm(p, file1, file2, path, page);
		kfree(path);
	}
 	if (file2 && !IS_ERR(file2))
		filp_close(file2, NULL);
	if (file1 && !IS_ERR(file1))
		filp_close(file1, NULL);
	kfree(page);
	return error;
}

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
	struct security_operations *ops = probe_security_ops();
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
	struct proc_dir_entry *entry;
#endif
	if (!ops)
		return -EINVAL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
	uuid_exports.find_task_by_vpid = probe_find_task_by_vpid();
	if (!uuid_exports.find_task_by_vpid)
		return -EINVAL;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	uuid_exports.vfsmount_lock = probe_vfsmount_lock();
	if (!uuid_exports.vfsmount_lock)
		return -EINVAL;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 2, 0)
	uuid_exports.__d_path = probe___d_path();
	if (!uuid_exports.__d_path)
		return -EINVAL;
#else
	uuid_exports.d_absolute_path = probe_d_absolute_path();
	if (!uuid_exports.d_absolute_path)
		return -EINVAL;
#endif
	for (idx = 0; idx < UUID_MAX_SECURITY_HASH; idx++)
		INIT_LIST_HEAD(&uuid_security_list[idx]);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26)
	if (!proc_create("uuid", 0600, NULL, &uuid_operations) ||
	    !proc_create("uuid_config", 0600, NULL, &uuid_config_operations) ||
	    !proc_create("uuid_status", 0600, NULL, &uuid_status_operations))
		goto out_clean;
#else
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
#endif
	uuid_update_security_ops(ops);
	printk(KERN_INFO "UUID: 0.0.0   2011/02/04\n");
	return 0;
out_clean:
	remove_proc_entry("uuid_status", NULL);
	remove_proc_entry("uuid_config", NULL);
	remove_proc_entry("uuid", NULL);
	return -EINVAL;
}

module_init(uuid_init);
MODULE_LICENSE("GPL");
