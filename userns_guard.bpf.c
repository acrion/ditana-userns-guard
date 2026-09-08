// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This one file is GPL-2.0-or-later rather than AGPL-3.0-or-later like the rest
 * of ditana-userns-guard. It is loaded into the kernel, and the kernel grants
 * the helpers it uses only to a program whose license string is GPL-compatible.
 * The loader beside it, which never enters the kernel, keeps the project
 * license.
 */
#include "kernel_types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define CAP_SYS_ADMIN 21
#define EPERM 1

#define MAX_ALLOWED 256
/* Twice the loader's limit, because a reload adds the new entries before it
 * removes the stale ones and therefore needs room for both sets at once.
 */
#define MAP_SLOTS (2 * MAX_ALLOWED)

/* An executable is identified by the device and inode of the file the calling
 * task was started from, never by its path. The userns_create hook receives
 * only "const struct cred *", so there is neither a file nor a name to inspect;
 * the task's own mm->exe_file is the only thing left that points at the binary.
 *
 * Reading exe_file rather than marking the task at exec time is what makes
 * bwrap work: bwrap forks and calls unshare in the child, and a fork does not
 * exec. The child shares its parent's exe_file, so it matches without any
 * bookkeeping of its own.
 */
struct exe_key {
	__u32 dev;
	__u32 uid;
	__u64 ino;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAP_SLOTS);
	__type(key, struct exe_key);
	__type(value, __u8);
} userns_allow SEC(".maps");

/* Both numbers are learned here rather than taken from stat() in the loader,
 * and that is not a refinement: on btrfs the two disagree. stat() reports the
 * anonymous device of the subvolume, while the kernel keeps the superblock's
 * own number in i_sb->s_dev, which is what the guard below compares against. A
 * bwrap on btrfs was measured not to match a key built from stat(); zfs and
 * tmpfs did match, which is exactly what makes the mistake easy to ship.
 *
 * Reading the pair through this hook takes it from the same field of the same
 * structure that the guard reads, so the two cannot disagree by construction,
 * whatever the filesystem does.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAP_SLOTS);
	__type(key, struct exe_key);
	__type(value, __u8);
} userns_learn SEC(".maps");

/* Non-zero while the loader is opening the files named in the allowlist, and
 * then only for the duration of those open calls. It holds the loader's thread
 * group id so that nothing another process opens in that window is picked up.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} userns_learn_tgid SEC(".maps");

#define STATE_ENFORCE 0
#define STATE_DENIED  1
#define STATE_ALLOWED 2

/* Index 0 is written by the loader, the other two are counters it reads back.
 * Keeping enforcement in a map rather than in a compile-time constant is what
 * allows the program to be attached in observation mode on a machine whose
 * sandboxes have to keep running while it is being measured.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 3);
	__type(key, __u32);
	__type(value, __u64);
} userns_state SEC(".maps");

static __always_inline void bump(__u32 slot)
{
	__u64 *cell = bpf_map_lookup_elem(&userns_state, &slot);

	if (cell)
		__sync_fetch_and_add(cell, 1);
}

/* The owner is part of the identity, not decoration. On btrfs an inode number
 * is unique only within a subvolume while the superblock - and therefore
 * i_sb->s_dev - is shared by all of them, so two files in different subvolumes
 * of one filesystem can carry the same device and inode. That is precisely why
 * btrfs reports a made-up per-subvolume device number to user space, where
 * POSIX demands the pair be unique.
 *
 * An unprivileged user may create a subvolume and then create files until one
 * lands on the inode number of an allowed binary. What they cannot do is make
 * that file root-owned, so the owner is what keeps the collision from becoming
 * a match. The loader refuses to allow a file that is not owned by root or that
 * is group- or world-writable, which is the other half of the same argument.
 */
static __always_inline void key_of_inode(struct inode *inode, struct exe_key *key)
{
	key->ino = BPF_CORE_READ(inode, i_ino);
	key->dev = BPF_CORE_READ(inode, i_sb, s_dev);
	key->uid = BPF_CORE_READ(inode, i_uid.val);
}

SEC("lsm/file_open")
int BPF_PROG(ditana_userns_learn, struct file *file, int prev)
{
	struct exe_key key = {};
	__u32 slot = 0;
	__u32 *want;
	__u8 one = 1;

	want = bpf_map_lookup_elem(&userns_learn_tgid, &slot);
	if (!want || *want == 0)
		return prev;
	if (*want != (__u32)(bpf_get_current_pid_tgid() >> 32))
		return prev;

	key_of_inode(BPF_CORE_READ(file, f_inode), &key);
	if (key.ino)
		bpf_map_update_elem(&userns_learn, &key, &one, BPF_ANY);

	/* Observing only. This hook is attached for the length of a handful of
	 * open calls and must never be able to refuse one.
	 */
	return prev;
}

SEC("lsm/userns_create")
int BPF_PROG(ditana_userns_create, const struct cred *cred, int prev)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct inode *inode;
	struct exe_key key = {};
	__u32 slot = STATE_ENFORCE;
	__u64 *enforce;
	__u64 caps;
	int level;

	/* An LSM hook may only ever add a denial. Returning 0 here after another
	 * module has refused would turn this guard into a way of overruling it.
	 */
	if (prev != 0)
		return prev;

	/* A task holding CAP_SYS_ADMIN in the initial user namespace can create a
	 * namespace whatever this program says, so refusing it would only break
	 * container tooling run by root without adding anything.
	 *
	 * The level test is not decoration, and leaving it out made this guard
	 * nearly useless. Inside any user namespace every task carries the full
	 * capability set relative to that namespace, and create_user_ns() calls
	 * this hook before it installs the new namespace on the credentials - so
	 * for a nested creation the hook sees a caller whose cap_effective is
	 * already full. Any user could then run the one allowed binary, bwrap,
	 * ask it for a namespace, and from inside it create as many more as they
	 * liked with any program at all. Measured: CapEff is 0 in the initial
	 * namespace and 0x1ffffffffff inside `unshare -Ur`.
	 *
	 * level is 0 for the initial user namespace alone, so this asks the
	 * question that was meant: is the caller privileged on this machine,
	 * rather than privileged inside something it just created.
	 */
	caps = BPF_CORE_READ(cred, cap_effective.val);
	level = BPF_CORE_READ(cred, user_ns, level);
	if (level == 0 && (caps & (1ULL << CAP_SYS_ADMIN)))
		return 0;

	task = (struct task_struct *)bpf_get_current_task_btf();
	mm = BPF_CORE_READ(task, mm);
	if (!mm)
		return 0; /* a kernel thread has no executable to match against */

	inode = BPF_CORE_READ(mm, exe_file, f_inode);
	if (!inode)
		return 0;

	key_of_inode(inode, &key);

	if (bpf_map_lookup_elem(&userns_allow, &key)) {
		bump(STATE_ALLOWED);
		return 0;
	}

	bump(STATE_DENIED);

	enforce = bpf_map_lookup_elem(&userns_state, &slot);
	if (enforce && *enforce)
		return -EPERM;

	return 0;
}
