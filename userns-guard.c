// SPDX-License-Identifier: AGPL-3.0-or-later
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PIN_DIR    "/sys/fs/bpf/ditana-userns-guard"
#define PIN_LINK   PIN_DIR "/link"
#define PIN_ALLOW  PIN_DIR "/userns_allow"
#define PIN_LEARN  PIN_DIR "/userns_learn"
#define PIN_TGID   PIN_DIR "/userns_learn_tgid"
#define PIN_STATE  PIN_DIR "/userns_state"

#define OBJECT     "/usr/lib/ditana/userns_guard.bpf.o"
#define ALLOWLIST  "/etc/ditana/userns-allow.conf"

#define MAX_ALLOWED 256
#define MAP_SLOTS (2 * MAX_ALLOWED)
#define MAX_PATH_LEN 4096
#define LOCK_FILE "/run/ditana-userns-guard.lock"

struct exe_key {
	unsigned int dev;
	unsigned int uid;
	unsigned long long ino;
};

enum { STATE_ENFORCE = 0, STATE_DENIED = 1, STATE_ALLOWED = 2 };

static int be_quiet(enum libbpf_print_level level, const char *fmt, va_list ap)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, fmt, ap);
}

static void complain(const char *what, int err)
{
	fprintf(stderr, "ditana-userns-guard: %s: %s\n", what, strerror(err < 0 ? -err : err));
}

/* A path that does not resolve aborts the whole run instead of being skipped:
 * an entry naming a binary that is not installed means the generated allowlist
 * and the installed system have drifted apart, and the sandbox it was written
 * for would fail later with nothing to point at.
 */
/* The kernel side matches on device, inode and owner. The owner is what stops an
 * inode-number collision from becoming a match, so a file that is not root-owned
 * would be identifying itself with a number an unprivileged user can reproduce.
 * Group- or world-writable is refused for the same reason one step further on:
 * the file could be replaced by whoever can write it.
 */
static int owner_is_safe(const char *path, const struct stat *st)
{
	if (st->st_uid != 0) {
		fprintf(stderr, "ditana-userns-guard: %s is not owned by root\n", path);
		return 0;
	}
	if (st->st_mode & (S_IWGRP | S_IWOTH)) {
		fprintf(stderr, "ditana-userns-guard: %s is writable by others than its owner\n", path);
		return 0;
	}
	return 1;
}

static int read_allowlist(const char *file, char paths[][MAX_PATH_LEN], int max, int *count,
			  int tolerate_missing)
{
	char line[MAX_PATH_LEN];
	FILE *f;

	*count = 0;
	f = fopen(file, "re");
	if (!f) {
		if (errno == ENOENT)
			return 0; /* nothing declared a need, which is a valid state */
		complain(file, errno);
		return -1;
	}

	while (fgets(line, sizeof(line), f)) {
		struct stat st;
		char *p = line;
		char *nl;

		while (*p == ' ' || *p == '\t')
			p++;
		nl = strchr(p, '\n');
		if (nl)
			*nl = '\0';
		if (*p == '\0' || *p == '#')
			continue;

		if (*count >= max) {
			fprintf(stderr, "ditana-userns-guard: more than %d entries in %s\n", max, file);
			fclose(f);
			return -1;
		}
		if (stat(p, &st) != 0) {
			/* At load time this is drift between the generated list and
			 * the installed system, and stopping is right: the unit
			 * fails and the sysctl is never raised. On a reload it is
			 * ordinary - a package was removed - and stopping there
			 * would be worse than useless, because the live map would
			 * keep every stale entry and every later reload would fail
			 * at the same path.
			 */
			if (tolerate_missing && errno == ENOENT) {
				fprintf(stderr, "ditana-userns-guard: %s is gone, dropping it\n", p);
				continue;
			}
			complain(p, errno);
			fclose(f);
			return -1;
		}
		if (!owner_is_safe(p, &st)) {
			fclose(f);
			return -1;
		}
		snprintf(paths[*count], MAX_PATH_LEN, "%s", p);
		(*count)++;
	}

	fclose(f);
	return 0;
}

static int map_count(int fd)
{
	struct exe_key key, next;
	int n = 0;

	if (bpf_map_get_next_key(fd, NULL, &key) != 0)
		return 0;
	for (;;) {
		n++;
		if (bpf_map_get_next_key(fd, &key, &next) != 0)
			break;
		key = next;
	}
	return n;
}

static void map_clear(int fd)
{
	struct exe_key key;

	while (bpf_map_get_next_key(fd, NULL, &key) == 0)
		if (bpf_map_delete_elem(fd, &key) != 0)
			break;
}

/* The window in which the learning hook is attached has to contain the opens
 * below and nothing else, which is why the allowlist is read into memory first
 * and every other file this process needs is already open by now.
 */
static int learn(int tgid_fd, int learn_fd, char paths[][MAX_PATH_LEN], int count)
{
	unsigned int slot = 0;
	unsigned int me = (unsigned int)getpid();
	unsigned int off = 0;
	int failed = 0;

	/* An empty list is refused rather than installed. Reconciling against it
	 * would empty the live map, and a guard whose allowlist is empty reads as
	 * "restricted" while behaving as "nothing may" - every sandbox on the
	 * machine refused, with a success message in the journal. A machine that
	 * needs no user namespaces has no allowlist file at all, and the unit's
	 * ConditionPathExists keeps it from starting.
	 */
	if (count == 0) {
		fprintf(stderr, "ditana-userns-guard: the allowlist names nothing\n");
		return -1;
	}

	/* Clearing the armed slot before the hook goes on, not after: a loader
	 * killed between arming and disarming leaves a thread group id behind,
	 * and that number belongs to some other process by now.
	 */
	map_clear(learn_fd);
	bpf_map_update_elem(tgid_fd, &slot, &off, BPF_ANY);

	if (bpf_map_update_elem(tgid_fd, &slot, &me, BPF_ANY) != 0) {
		complain("cannot arm the learning hook", errno);
		return -1;
	}

	for (int i = 0; i < count; i++) {
		int fd = open(paths[i], O_RDONLY | O_CLOEXEC);

		if (fd < 0) {
			complain(paths[i], errno);
			failed = 1;
			break;
		}
		close(fd);
	}

	bpf_map_update_elem(tgid_fd, &slot, &off, BPF_ANY);

	if (failed)
		return -1;

	/* If not a single open was seen, the hook is not doing its work, and
	 * carrying on would install an empty allowlist while reporting success -
	 * which reads as "restricted" and behaves as "nothing may".
	 */
	if (map_count(learn_fd) == 0) {
		fprintf(stderr, "ditana-userns-guard: the learning hook saw nothing\n");
		return -1;
	}

	return 0;
}

static int contains(int fd, const struct exe_key *key)
{
	unsigned char value;

	return bpf_map_lookup_elem(fd, key, &value) == 0;
}

/* Adding the new entries before removing the stale ones is not tidiness. The
 * guard reads this map live, so a moment in which neither the old nor the new
 * inode of bwrap is present is a moment in which every sandbox launch is
 * refused. An upgrade of bubblewrap must not be able to produce that moment.
 */
static int reconcile(int allow_fd, int learn_fd)
{
	struct exe_key key, next;
	unsigned char one = 1;
	int err;

	err = bpf_map_get_next_key(learn_fd, NULL, &key);
	while (err == 0) {
		int have_next = bpf_map_get_next_key(learn_fd, &key, &next) == 0;

		if (bpf_map_update_elem(allow_fd, &key, &one, BPF_ANY) != 0) {
			complain("cannot add an entry", errno);
			return -1;
		}
		if (!have_next)
			break;
		key = next;
	}

	err = bpf_map_get_next_key(allow_fd, NULL, &key);
	while (err == 0) {
		int have_next = bpf_map_get_next_key(allow_fd, &key, &next) == 0;

		if (!contains(learn_fd, &key))
			bpf_map_delete_elem(allow_fd, &key);

		if (!have_next)
			break;
		key = next;
	}

	return 0;
}

static int pins_exist(void)
{
	struct stat st;

	return stat(PIN_LINK, &st) == 0;
}

/* bpf_map__reuse_fd takes the pinned map's shape over the one just compiled,
 * without comparing them. A loader whose key or capacity changed would then
 * quietly go on writing into the map an older version left pinned, and the two
 * would disagree about what a key means. The pins outlive the package, so this
 * is an upgrade away rather than hypothetical.
 */
static int reuse(struct bpf_map *map, const char *pin)
{
	struct bpf_map_info info = {};
	unsigned int len = sizeof(info);
	int fd = bpf_obj_get(pin);

	if (fd < 0) {
		complain(pin, errno);
		return -1;
	}
	if (bpf_map_get_info_by_fd(fd, &info, &len) != 0) {
		complain("cannot inspect a pinned map", errno);
		close(fd);
		return -1;
	}
	if (info.key_size != bpf_map__key_size(map) ||
	    info.value_size != bpf_map__value_size(map) ||
	    info.max_entries != bpf_map__max_entries(map) ||
	    info.type != (unsigned int)bpf_map__type(map)) {
		fprintf(stderr, "ditana-userns-guard: the pinned map %s was left by a different "
				"version; stop the service and start it again\n", pin);
		close(fd);
		return -1;
	}
	if (bpf_map__reuse_fd(map, fd) != 0) {
		complain("cannot reuse a pinned map", errno);
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static int run(const char *object, const char *allowlist, int enforce, int reload_only)
{
	static char paths[MAX_ALLOWED][MAX_PATH_LEN];
	struct bpf_object *obj = NULL;
	struct bpf_program *guard, *learner;
	struct bpf_map *allow_map, *learn_map, *tgid_map, *state_map;
	struct bpf_link *learn_link = NULL;
	struct bpf_link *guard_link = NULL;
	int attached;
	int count;
	int rc = 1;
	int err;
	int lock_fd;

	/* The service unit and the pacman hook can meet: a transaction finishing
	 * while the unit starts would give two loaders one pinned learning map
	 * between them, and each would reconcile against the other's findings.
	 */
	lock_fd = open(LOCK_FILE, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (lock_fd < 0) {
		complain(LOCK_FILE, errno);
		return 1;
	}
	if (flock(lock_fd, LOCK_EX) != 0) {
		complain("cannot take the lock", errno);
		close(lock_fd);
		return 1;
	}

	attached = pins_exist();

	/* The pacman hook fires after every transaction, including on a machine
	 * that never restricted user namespaces in the first place. There the
	 * guard is simply not running, and refreshing it into existence would
	 * impose a policy nobody asked for.
	 */
	if (reload_only && !attached) {
		close(lock_fd);
		return 0;
	}

	/* A path that has gone missing is drift at load time and an ordinary
	 * package removal at reload time. See read_allowlist.
	 */
	if (read_allowlist(allowlist, paths, MAX_ALLOWED, &count, attached) != 0)
		goto out;

	obj = bpf_object__open_file(object, NULL);
	if (!obj) {
		complain(object, errno);
		goto out;
	}

	guard = bpf_object__find_program_by_name(obj, "ditana_userns_create");
	learner = bpf_object__find_program_by_name(obj, "ditana_userns_learn");
	allow_map = bpf_object__find_map_by_name(obj, "userns_allow");
	learn_map = bpf_object__find_map_by_name(obj, "userns_learn");
	tgid_map = bpf_object__find_map_by_name(obj, "userns_learn_tgid");
	state_map = bpf_object__find_map_by_name(obj, "userns_state");
	if (!guard || !learner || !allow_map || !learn_map || !tgid_map || !state_map) {
		fprintf(stderr, "ditana-userns-guard: the object is missing a map or a program\n");
		goto out;
	}

	/* A second start must not attach a second copy of the guard, and the
	 * reload the pacman hook asks for must go to the maps that are already
	 * in force rather than to fresh ones.
	 */
	if (attached) {
		bpf_program__set_autoload(guard, false);
		if (reuse(allow_map, PIN_ALLOW) != 0 ||
		    reuse(learn_map, PIN_LEARN) != 0 ||
		    reuse(tgid_map, PIN_TGID) != 0 ||
		    reuse(state_map, PIN_STATE) != 0)
			goto out;
	}

	err = bpf_object__load(obj);
	if (err) {
		complain("cannot load the program", err);
		goto out;
	}

	learn_link = bpf_program__attach_lsm(learner);
	if (!learn_link) {
		complain("cannot attach the learning hook", errno);
		goto out;
	}

	err = learn(bpf_map__fd(tgid_map), bpf_map__fd(learn_map), paths, count);

	/* The learning hook sees every open on the machine while it is attached,
	 * so it comes off again immediately, whether the learning worked or not.
	 */
	bpf_link__destroy(learn_link);
	learn_link = NULL;
	if (err != 0)
		goto out;

	if (reconcile(bpf_map__fd(allow_map), bpf_map__fd(learn_map)) != 0)
		goto out;

	unsigned int slot = STATE_ENFORCE;
	unsigned long long on = enforce;

	/* Written on every run, not only on the first. The unit raises the sysctl
	 * after this command succeeds, so a reload that left the guard observing
	 * would hand out user namespaces to everybody while reporting success -
	 * exactly the one outcome the whole arrangement exists to prevent.
	 */
	if (bpf_map_update_elem(bpf_map__fd(state_map), &slot, &on, BPF_ANY) != 0) {
		complain("cannot set the mode", errno);
		goto out;
	}

	if (attached) {
		printf("ditana-userns-guard: reloaded, %d executable(s) allowed\n", count);
		rc = 0;
		goto out;
	}

	guard_link = bpf_program__attach_lsm(guard);
	if (!guard_link) {
		complain("cannot attach to userns_create", errno);
		goto out;
	}

	/* Pinning is what keeps the guard alive after this process exits, and it
	 * is also the handle a reload works through. Without it the guard would
	 * be gone the moment the service unit reported success, and the unit
	 * would then raise the sysctl over nothing.
	 */
	if (mkdir(PIN_DIR, 0700) != 0 && errno != EEXIST) {
		complain(PIN_DIR, errno);
		goto out;
	}
	err = bpf_link__pin(guard_link, PIN_LINK);
	if (!err)
		err = bpf_map__pin(allow_map, PIN_ALLOW);
	if (!err)
		err = bpf_map__pin(learn_map, PIN_LEARN);
	if (!err)
		err = bpf_map__pin(tgid_map, PIN_TGID);
	if (!err)
		err = bpf_map__pin(state_map, PIN_STATE);
	if (err) {
		/* Half a pin set is worse than none: the next start would take the
		 * link for granted and reload into maps the guard is not reading.
		 */
		complain("cannot pin", err);
		bpf_link__destroy(guard_link);
		guard_link = NULL;
		unlink(PIN_LINK);
		unlink(PIN_ALLOW);
		unlink(PIN_LEARN);
		unlink(PIN_TGID);
		unlink(PIN_STATE);
		rmdir(PIN_DIR);
		goto out;
	}

	printf("ditana-userns-guard: %s, %d executable(s) allowed\n",
	       enforce ? "enforcing" : "observing", count);
	rc = 0;

out:
	bpf_link__destroy(learn_link);
	bpf_link__destroy(guard_link);
	bpf_object__close(obj);
	close(lock_fd);
	return rc;
}

static int do_unload(void)
{
	unlink(PIN_LINK);
	unlink(PIN_ALLOW);
	unlink(PIN_LEARN);
	unlink(PIN_TGID);
	unlink(PIN_STATE);
	rmdir(PIN_DIR);
	return 0;
}

static int do_status(void)
{
	static const char *names[] = { "enforce", "denied", "allowed" };
	unsigned long long value;
	int fd;

	fd = bpf_obj_get(PIN_STATE);
	if (fd < 0) {
		printf("not loaded\n");
		return 1;
	}
	for (unsigned int i = 0; i < 3; i++)
		if (bpf_map_lookup_elem(fd, &i, &value) == 0)
			printf("%-8s %llu\n", names[i], value);
	close(fd);

	fd = bpf_obj_get(PIN_ALLOW);
	if (fd >= 0) {
		printf("%-8s %d\n", "allowlist", map_count(fd));
		close(fd);
	}
	return 0;
}

static void usage(const char *me)
{
	fprintf(stderr,
		"usage: %s [--observe] [--allowlist FILE] [--object FILE]\n"
		"       %s --reload | --unload | --status\n"
		"\n"
		"Loading and reloading are the same work: which one happens follows\n"
		"from whether the guard is already attached. --reload additionally\n"
		"does nothing at all when it is not.\n", me, me);
}

int main(int argc, char **argv)
{
	const char *allowlist = ALLOWLIST;
	const char *object = OBJECT;
	int enforce = 1;
	int reload_only = 0;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--observe") == 0)
			enforce = 0;
		else if (strcmp(argv[i], "--unload") == 0)
			return do_unload();
		else if (strcmp(argv[i], "--status") == 0)
			return do_status();
		else if (strcmp(argv[i], "--reload") == 0)
			reload_only = 1;
		else if (strcmp(argv[i], "--allowlist") == 0 && i + 1 < argc)
			allowlist = argv[++i];
		else if (strcmp(argv[i], "--object") == 0 && i + 1 < argc)
			object = argv[++i];
		else {
			usage(argv[0]);
			return 2;
		}
	}

	libbpf_set_print(be_quiet);
	return run(object, allowlist, enforce, reload_only);
}
