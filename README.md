# ditana-userns-guard

Restricts unprivileged user namespaces to a declared list of executables, rather than disabling them completely.

## Why this exists

Unprivileged user namespaces represent a recognized method to widen the kernel attack surface. Among the sixteen Linux kernel entries included by CISA in its [Known Exploited Vulnerabilities catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) over three years, six are exploitable through them – as per catalogue version 2026.09.04, and which six is our own reading of it rather than a figure anybody published. Ditana therefore ships with `kernel.unprivileged_userns_clone=0`.

Sandboxes rely on them, though. Flatpak and Bubblejail both rest upon bubblewrap, and bubblewrap creates a user namespace. Until 2026 the solution was a setuid `bwrap`, which does not need the sysctl to be raised. That option has vanished: bubblewrap 0.12.0 [removed setuid support](https://github.com/containers/bubblewrap/pull/742) one day after 0.11.2 fixed [CVE-2026-41163](https://nvd.nist.gov/vuln/detail/CVE-2026-41163), a privilege escalation present solely in setuid mode. Arch dropped `bubblewrap-suid`, no replacement was written, and nobody maintains the 0.11.x branch that was offered at the time.

So the choice is no longer between a hardened kernel and working sandboxes. It is between switching user namespaces on for everything, and permitting them per executable. This program implements the second option.

## How it works

A BPF LSM program is attached to the `userns_create` hook. It refuses the creation of a user namespace unless the calling task was started from a binary on the allowlist, and it lets through tasks that hold `CAP_SYS_ADMIN` **in the initial user namespace**, because those could create the namespace anyway.

Those last five words carry the whole guarantee. Inside any user namespace every task carries the full capability set relative to that namespace, and the kernel calls this hook before it installs the new namespace on the credentials – so for a nested creation the hook sees a caller whose `cap_effective` is already full. A check on the capability alone would therefore have let anybody run the one allowed binary, ask it for a namespace, and from inside it create as many more as they liked with any program at all. The guard reads `cred->user_ns->level`, which is zero for the initial user namespace and nothing else, and only then trusts the capability.

The hook receives nothing but `const struct cred *`. There is no file and no path in it, so the binary is identified through the task's own `mm->exe_file`. That choice matters more than it looks: bubblewrap forks and calls `unshare` in the child, and a fork does not exec. A child shares its parent's `exe_file`, so it matches without any bookkeeping.

An executable is identified by the device, the inode and the **owner** of that file. The owner is not decoration either. On btrfs an inode number is unique only within a subvolume while the superblock, and with it `i_sb->s_dev`, is shared by all of them, so two files in two subvolumes of one filesystem can carry the same device and inode – which is precisely why btrfs reports a made-up per-subvolume device number to user space, where POSIX requires the pair to be unique. An unprivileged user may create a subvolume and therefore controls the inode numbers in it. What they cannot do is make a file root-owned, so the owner is what keeps the collision from becoming a match. For the same reason the loader refuses to allow a file that is not owned by root or that is group- or world-writable.

All three are learned by a second, short-lived hook on `file_open` while the loader opens the listed paths, rather than being taken from `stat()`. This is not a refinement. On btrfs the device numbers disagree: `stat()` reports the anonymous device of the subvolume, while the kernel keeps the superblock's own number in `i_sb->s_dev`, which is what the guard compares against. A `bwrap` copy on btrfs was measured not to match a key built from `stat()`, while the same test passed on zfs and on tmpfs – which is what makes the mistake easy to ship unnoticed.

## Why the sysctl is raised, and why that is still safe

An LSM hook may only ever add a denial. It cannot grant anything. While `kernel.unprivileged_userns_clone` is `0`, the kernel refuses each unprivileged user namespace prior to any allowlist being examined, so the guard would have nothing to permit.

The sysctl therefore must be `1` for this to work, and the whole restriction lives in the BPF program. What keeps that safe is the order in the service unit:

1. load the program, fill the allowlist, attach it;
2. and only then raise the sysctl.

systemd does not proceed to the second step if the first one failed. A machine that cannot build, load or attach the program keeps the sysctl it was installed with and stays exactly as locked as it was before – with sandboxes broken, but nothing exposed. Stopping the unit reverses the order for the same reason.

## Where the allowlist comes from

`/etc/ditana/userns-allow.conf` holds one absolute path per line. Lines that are empty or start with `#` are ignored. A path that does not resolve aborts the run rather than being skipped: it means the list and the installed system have drifted apart, and the sandbox it was written for would fail later with nothing to point at.

On Ditana the file is generated during installation. Each setting in `ditana-config` that needs a user namespace declares it beside the package it belongs to:

```kdl
- name="flatpak" default-value=#true {
    arch-packages "flatpak"
    userns-allow "/usr/bin/bwrap"
  }
```

The installer collects the declarations of the settings that are enabled and writes the file. Nothing in the configuration ever names the sysctl, and no setting has to repeat the safe default.

## Keeping it current

Because the match is by inode, replacing one of the listed binaries makes the running allowlist point at a file that no longer exists. Nothing would report it – the sandbox would simply stop being permitted. A pacman hook therefore reloads the list after every transaction. The reload is a handful of `open` calls, it adds the new entries before it removes the stale ones so that no sandbox launch falls into a gap, and it does nothing at all on a machine where the guard is not running.

A binary inside a Flatpak would not be covered by that hook, since `flatpak update` is not a pacman transaction. This is one of the reasons Ditana still installs Chromium-based browsers as native packages rather than as Flatpaks.

## Usage

```
ditana-userns-guard                 # load and attach, or reload if already attached
ditana-userns-guard --observe       # attach without refusing anything, and count
ditana-userns-guard --reload        # refresh the list; silent no-op if not attached
ditana-userns-guard --unload        # detach
ditana-userns-guard --status        # enforcing or not, and the two counters
```

Observation mode is what makes the guard measurable on a machine whose sandboxes have to keep running: it counts what it would have refused instead of refusing it.

## Building and testing

```
make
sudo make check
```

The tests need root, because attaching a BPF LSM program does. They create a loop-mounted btrfs filesystem to cover the device-number scenario mentioned above, and they skip that scenario when `btrfs-progs` is absent. The enforcing tests deny unprivileged user namespaces machine-wide for as long as they run, so they refuse to start where a graphical session is present unless `DITANA_USERNS_TEST_ENFORCE=yes` says the machine is expendable.

## Requirements

A kernel with `CONFIG_BPF_LSM=y` and `bpf` present in the active LSM stack (`cat /sys/kernel/security/lsm`), along with `CONFIG_DEBUG_INFO_BTF=y`. Arch's stock kernels satisfy all three.

## Licence

AGPL-3.0-or-later, except `userns_guard.bpf.c`, which is GPL-2.0-or-later. That file is loaded into the kernel, and the kernel grants the helpers it uses only to a program whose licence string is GPL-compatible.
