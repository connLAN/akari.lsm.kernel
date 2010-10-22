/*
 * security/ccsecurity/compat.h
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.8.0-pre   2010/10/22
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#define false 0
#define true 1

#ifndef __user
#define __user
#endif

#ifndef current_uid
#define current_uid()           (current->uid)
#endif
#ifndef current_gid
#define current_gid()           (current->gid)
#endif
#ifndef current_euid
#define current_euid()          (current->euid)
#endif
#ifndef current_egid
#define current_egid()          (current->egid)
#endif
#ifndef current_suid
#define current_suid()          (current->suid)
#endif
#ifndef current_sgid
#define current_sgid()          (current->sgid)
#endif
#ifndef current_fsuid
#define current_fsuid()         (current->fsuid)
#endif
#ifndef current_fsgid
#define current_fsgid()         (current->fsgid)
#endif

#ifndef DEFINE_SPINLOCK
#define DEFINE_SPINLOCK(x) spinlock_t x = SPIN_LOCK_UNLOCKED
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
#define bool _Bool
#endif

#ifndef KERN_CONT
#define KERN_CONT ""
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
#define fatal_signal_pending(p) (signal_pending(p) &&			\
				 sigismember(&p->pending.signal, SIGKILL))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 16)
#define mutex semaphore
#define mutex_init(mutex) init_MUTEX(mutex)
#define mutex_unlock(mutex) up(mutex)
#define mutex_lock(mutex) down(mutex)
#define mutex_lock_interruptible(mutex) down_interruptible(mutex)
#define mutex_trylock(mutex) (!down_trylock(mutex))
#define DEFINE_MUTEX(mutexname) DECLARE_MUTEX(mutexname)
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({				\
			const typeof(((type *)0)->member) *__mptr = (ptr); \
			(type *)((char *)__mptr - offsetof(type, member)); })
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 14)
#define kzalloc(size, flags) ({					\
			void *ret = kmalloc((size), (flags));	\
			if (ret)				\
				memset(ret, 0, (size));		\
			ret; })
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 0)
#define smp_read_barrier_depends smp_rmb
#endif

#ifndef ACCESS_ONCE
#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))
#endif

#ifndef rcu_dereference
#define rcu_dereference(p)     ({					\
			typeof(p) _________p1 = ACCESS_ONCE(p);		\
			smp_read_barrier_depends(); /* see RCU */	\
			(_________p1);					\
		})
#endif

#ifndef rcu_assign_pointer
#define rcu_assign_pointer(p, v)			\
	({						\
		if (!__builtin_constant_p(v) ||		\
		    ((v) != NULL))			\
			smp_wmb(); /* see RCU */	\
		(p) = (v);				\
	})
#endif

#ifndef srcu_dereference
#define srcu_dereference(p, ss) rcu_dereference(p)
#endif

#ifndef list_for_each_entry_srcu
#define list_for_each_entry_srcu(pos, head, member, ss)		      \
	for (pos = list_entry(srcu_dereference((head)->next, ss),     \
			      typeof(*pos), member);		      \
	     prefetch(pos->member.next), &pos->member != (head);      \
	     pos = list_entry(srcu_dereference(pos->member.next, ss), \
			      typeof(*pos), member))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
static inline void __list_add_rcu(struct list_head *new,
				  struct list_head *prev,
				  struct list_head *next)
{
	new->next = next;
	new->prev = prev;
	rcu_assign_pointer(prev->next, new);
	next->prev = new;
}

static inline void list_add_tail_rcu(struct list_head *new,
				     struct list_head *head)
{
	__list_add_rcu(new, head->prev, head);
}

static inline void list_add_rcu(struct list_head *new, struct list_head *head)
{
	__list_add_rcu(new, head, head->next);
}

#ifndef LIST_POISON2
#define LIST_POISON2  ((void *) 0x00200200)
#endif

static inline void list_del_rcu(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	entry->prev = LIST_POISON2;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
#define __wait_event_interruptible_timeout(wq, condition, ret)		\
do {									\
	wait_queue_t __wait;						\
	init_waitqueue_entry(&__wait, current);				\
									\
	add_wait_queue(&wq, &__wait);					\
	for (;;) {							\
		set_current_state(TASK_INTERRUPTIBLE);			\
		if (condition)						\
			break;						\
		if (!signal_pending(current)) {				\
			ret = schedule_timeout(ret);			\
			if (!ret)					\
				break;					\
			continue;					\
		}							\
		ret = -ERESTARTSYS;					\
		break;							\
	}								\
	current->state = TASK_RUNNING;					\
	remove_wait_queue(&wq, &__wait);				\
} while (0)

#define wait_event_interruptible_timeout(wq, condition, timeout)	\
({									\
	long __ret = timeout;						\
	if (!(condition))						\
		__wait_event_interruptible_timeout(wq, condition, __ret); \
	__ret;								\
})
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 4, 30)
#undef ssleep
#define ssleep(secs) {						\
		set_current_state(TASK_UNINTERRUPTIBLE);	\
		schedule_timeout((HZ * secs) + 1);		\
	}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 9)
#undef ssleep
#define ssleep(secs) {						\
		set_current_state(TASK_UNINTERRUPTIBLE);	\
		schedule_timeout((HZ * secs) + 1);		\
	}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
#define s_fs_info u.generic_sbp
#endif

#ifndef list_for_each_entry_safe
#define list_for_each_entry_safe(pos, n, head, member)                  \
	for (pos = list_entry((head)->next, typeof(*pos), member),      \
		     n = list_entry(pos->member.next, typeof(*pos), member); \
	     &pos->member != (head);					\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
#define sk_family family
#define sk_protocol protocol
#define sk_type type
static inline struct socket *SOCKET_I(struct inode *inode)
{
	return inode->i_sock ? &inode->u.socket_i : NULL;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
#if defined(__LITTLE_ENDIAN)
#define HIPQUAD(addr)				\
	((unsigned char *)&addr)[3],		\
		((unsigned char *)&addr)[2],	\
		((unsigned char *)&addr)[1],	\
		((unsigned char *)&addr)[0]
#elif defined(__BIG_ENDIAN)
#define HIPQUAD NIPQUAD
#else
#error "Please fix asm/byteorder.h"
#endif /* __LITTLE_ENDIAN */
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)

#include <linux/mount.h>

static inline void path_get(struct path *path)
{
	dget(path->dentry);
	mntget(path->mnt);
}

static inline void path_put(struct path *path)
{
	dput(path->dentry);
	mntput(path->mnt);
}

#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 35)

#include <linux/fs_struct.h>

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
