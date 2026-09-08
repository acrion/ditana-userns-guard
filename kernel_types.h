/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef DITANA_KERNEL_TYPES_H
#define DITANA_KERNEL_TYPES_H

/* The handful of kernel structures this program reads, declared rather than
 * generated. The usual route is a vmlinux.h produced by bpftool from
 * /sys/kernel/btf/vmlinux, which is three and a half megabytes and describes the
 * kernel of whichever machine happened to run the build. Both are avoided here:
 * the package is built unattended in a chroot, where /sys/kernel/btf need not be
 * visible, and a build that silently depends on the builder's kernel is the kind
 * of thing that fails on some other night for reasons nobody can see.
 *
 * Only the fields actually touched are named. preserve_access_index turns every
 * access below into a CO-RE relocation, so the offsets are resolved against the
 * kernel that loads the program, not against these declarations. A field that
 * moves is therefore harmless; a field that is renamed upstream would fail to
 * relocate, loudly, at load time.
 */

/* The fixed-width names and the map-type enumerations come from the kernel's own
 * user-space headers, which are stable interfaces. Only the internal structures
 * below have to be declared by hand.
 */
#include <linux/types.h>
#include <linux/bpf.h>
#include <stdbool.h>

typedef __u32 dev_t;

typedef struct {
	__u32 val;
} kuid_t;

#define __ksym __attribute__((section(".ksyms")))
#define preserve_access __attribute__((preserve_access_index))

typedef struct {
	__u64 val;
} kernel_cap_t;

struct user_namespace {
	int level;
} preserve_access;

struct cred {
	kernel_cap_t cap_effective;
	struct user_namespace *user_ns;
} preserve_access;

struct super_block {
	dev_t s_dev;
} preserve_access;

struct inode {
	unsigned long i_ino;
	kuid_t i_uid;
	struct super_block *i_sb;
} preserve_access;

struct path {
	struct dentry *dentry;
} preserve_access;

struct file {
	struct inode *f_inode;
} preserve_access;

struct mm_struct {
	struct file *exe_file;
} preserve_access;

struct task_struct {
	struct mm_struct *mm;
} preserve_access;

#endif /* DITANA_KERNEL_TYPES_H */
