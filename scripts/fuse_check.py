#!/usr/bin/env python3
"""
fuse_check.py - exercise a "veil" FUSE filesystem and compare against an oracle.

For every entry in the manifest produced by gen_tree.py, and for each test
user, perform a set of file operations through the mount, record the errno
actually returned, and compare it against what the filesystem SHOULD return.

Oracle model (matches veilfs):
  * LOOKUP (getattr of the path): succeeds iff the user has ANY of r/w/x on the
    entry itself, else ENOENT.  root always succeeds.
  * METADATA: if lookup succeeds but the user lacks r on the entry, stat() is
    stripped: size=0, nlink=0, blocks=0, atime/mtime/ctime=0,
    uid=-1 unless the caller owns it, gid=-1 unless caller's gid matches.
    st_mode is NOT stripped.  With r, everything is real.
  * LISTING (readdir): only entries on which the user has r are listed.
    ("." and ".." always are.)  A directory the user cannot read -> readdir
    fails with --noread-dir-errno (default ENOENT, as in veilfs_readdir).
  * OPERATIONS: once the path resolves, the op needs normal POSIX permission on
    the target (open_r -> r, open_w -> w, chdir -> x, create/mkdir -> w+x on the
    directory), else EACCES.
  * Group match uses the caller's PRIMARY gid only (like veilfs_can_access),
    unless --gid-match all.
  * Path walk (--order):
      no-parent-x  (default) only the final entry's visibility matters;
                   x on ancestors is not checked (no default_permissions).
      access-first x on each parent is checked first (EACCES), then the child's
                   visibility (ENOENT) - what the kernel does with
                   -o default_permissions.
      hide-first   child's visibility (ENOENT) before parent x (EACCES).
  * root (uid 0) bypasses everything.

Must run as root to test as several users (it forks and drops privileges).
The FUSE mount needs -o allow_other for other uids to reach it at all.

Example:
    sudo ./fuse_check.py /mnt/fusefs --manifest tree.json --users alice,bob,carol
    # sanity check of the harness itself on a plain directory:
    sudo ./fuse_check.py /srv/backing --hide-policy none
"""
import argparse
import collections
import errno
import json
import os
import pwd
import stat as statmod
import sys
import time

ROOT_BYPASSES = True
R, W, X = 4, 2, 1
# stripped uid/gid is (uid_t)-1; the kernel may present it as the overflow id
ID_NONE = {0xFFFFFFFF, 65534}

# op -> (applies to, permission bits needed on target, mutating?)
OPS = {
    "stat":    ("any",  0,     False),
    "open_r":  ("file", R,     False),
    "open_w":  ("file", W,     False),
    "listdir": ("dir",  R,     False),
    "chdir":   ("dir",  X,     False),
    "create":  ("dir",  W | X, True),
    "mkdir":   ("dir",  W | X, True),
}

CFG = {"policy": "veil", "order": "no-parent-x", "gid_match": "primary",
       "readdir_errno": errno.EACCES}


# --------------------------------------------------------------------------
# users
# --------------------------------------------------------------------------
def resolve_user(spec):
    try:
        uid = int(spec)
        try:
            pw = pwd.getpwuid(uid)
        except KeyError:
            return {"uid": uid, "name": str(uid), "gid": uid, "groups": [uid]}
    except ValueError:
        pw = pwd.getpwnam(spec)
    groups = sorted(set(os.getgrouplist(pw.pw_name, pw.pw_gid)))
    return {"uid": pw.pw_uid, "name": pw.pw_name, "gid": pw.pw_gid,
            "groups": groups}


# --------------------------------------------------------------------------
# oracle
# --------------------------------------------------------------------------
def is_root(user):
    return ROOT_BYPASSES and user["uid"] == 0


def gid_matches(entry, user):
    if CFG["gid_match"] == "all":
        return entry["gid"] in user["groups"]
    return entry["gid"] == user["gid"]


def perm_bits(entry, user):
    if entry["uid"] == user["uid"]:
        shift = 6
    elif gid_matches(entry, user):
        shift = 3
    else:
        shift = 0
    return (entry["mode"] >> shift) & 7


def can(entry, user, bit):
    if is_root(user):
        if bit == X and entry["type"] == "file":
            return bool(entry["mode"] & 0o111)
        return True
    return bool(perm_bits(entry, user) & bit)


def lookup_ok(entry, user):
    """Can the user resolve this entry by name?  (any of r/w/x)"""
    if CFG["policy"] == "none" or is_root(user):
        return True
    return perm_bits(entry, user) != 0


def listed(entry, user):
    """Does readdir of the parent show this entry?  (needs r)"""
    if CFG["policy"] == "none" or is_root(user):
        return True
    return bool(perm_bits(entry, user) & R)


def full_metadata(entry, user):
    return (CFG["policy"] == "none" or is_root(user)
            or bool(perm_bits(entry, user) & R))


def expected_lookup(path, user, entries):
    """errno the path walk should produce, or 0 if it resolves."""
    if path == ".":
        return 0 if lookup_ok(entries["."], user) else errno.ENOENT
    cur = entries["."]
    prefix = []
    for part in path.split("/"):
        prefix.append(part)
        child = entries["/".join(prefix)]
        order = CFG["order"]
        if order == "access-first":
            if not can(cur, user, X):
                return errno.EACCES
            if not lookup_ok(child, user):
                return errno.ENOENT
        elif order == "hide-first":
            if not lookup_ok(child, user):
                return errno.ENOENT
            if not can(cur, user, X):
                return errno.EACCES
        else:  # no-parent-x
            if not lookup_ok(child, user):
                return errno.ENOENT
        cur = child
    return 0


def expected(op, path, user, entries):
    err = expected_lookup(path, user, entries)
    if err:
        return err
    need = OPS[op][1]
    for bit in (R, W, X):
        if need & bit and not can(entries[path], user, bit):
            if op == "listdir" and bit == R and CFG["policy"] == "veil":
                return CFG["readdir_errno"]
            return errno.EACCES
    return 0


def check_meta(entry, user, st):
    """Return a list of problems with the stat() result."""
    probs = []
    if st["mode"] != entry["mode"]:
        probs.append(f"mode {oct(st['mode'])} != {oct(entry['mode'])}")
    if full_metadata(entry, user):
        if st["nlink"] == 0:
            probs.append("nlink is 0 but user has r")
        if st["uid"] != entry["uid"]:
            probs.append(f"uid {st['uid']} != {entry['uid']}")
        if st["gid"] != entry["gid"]:
            probs.append(f"gid {st['gid']} != {entry['gid']}")
        if entry["type"] == "file" and "size" in entry and st["size"] != entry["size"]:
            probs.append(f"size {st['size']} != {entry['size']}")
        if entry["type"] == "file" and "size" in entry and entry["size"] and st["blocks"] == 0:
            probs.append("blocks is 0 but user has r")
    else:
        if st["size"] != 0:
            probs.append(f"size {st['size']} not stripped")
        if st["nlink"] != 0:
            probs.append(f"nlink {st['nlink']} not stripped")
        if st["blocks"] != 0:
            probs.append(f"blocks {st['blocks']} not stripped")
        if st["atime_ns"] or st["mtime_ns"] or st["ctime_ns"]:
            probs.append("timestamps not zeroed")
        if user["uid"] == entry["uid"]:
            if st["uid"] != entry["uid"]:
                probs.append(f"owner's uid {st['uid']} should be kept")
        elif st["uid"] not in ID_NONE:
            probs.append(f"uid {st['uid']} leaked (want -1)")
        if user["gid"] == entry["gid"]:
            if st["gid"] != entry["gid"]:
                probs.append(f"matching gid {st['gid']} should be kept")
        elif st["gid"] not in ID_NONE:
            probs.append(f"gid {st['gid']} leaked (want -1)")
    return probs


# --------------------------------------------------------------------------
# actual operations (run as the target user)
# --------------------------------------------------------------------------
def execute(mount, plan):
    out = []
    for path, op in plan:
        p = mount if path == "." else os.path.join(mount, path)
        extra = None
        try:
            if op == "stat":
                s = os.lstat(p)
                extra = {"mode": statmod.S_IMODE(s.st_mode), "size": s.st_size,
                         "nlink": s.st_nlink, "uid": s.st_uid, "gid": s.st_gid,
                         "blocks": s.st_blocks, "atime_ns": s.st_atime_ns,
                         "mtime_ns": s.st_mtime_ns, "ctime_ns": s.st_ctime_ns}
            elif op == "open_r":
                os.close(os.open(p, os.O_RDONLY | os.O_NONBLOCK))
            elif op == "open_w":
                os.close(os.open(p, os.O_WRONLY | os.O_NONBLOCK))
            elif op == "listdir":
                extra = sorted(os.listdir(p))
            elif op == "chdir":
                os.chdir(p)
                os.chdir("/")
            elif op == "create":
                t = os.path.join(p, f".fusecheck_{os.getpid()}")
                os.close(os.open(t, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
                os.unlink(t)
            elif op == "mkdir":
                t = os.path.join(p, f".fusecheck_d_{os.getpid()}")
                os.mkdir(t)
                os.rmdir(t)
            err = 0
        except OSError as e:
            err = e.errno
            extra = None
        out.append([err, extra])
    return out


def run_as(user, fn):
    if user["uid"] == os.geteuid():
        return fn()
    rfd, wfd = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(rfd)
            os.setgroups(user["groups"])
            os.setgid(user["gid"])
            os.setuid(user["uid"])
            payload = json.dumps({"ok": fn()})
        except BaseException as e:  # noqa
            payload = json.dumps({"error": repr(e)})
        with os.fdopen(wfd, "w") as f:
            f.write(payload)
        os._exit(0)
    os.close(wfd)
    with os.fdopen(rfd) as f:
        data = f.read()
    os.waitpid(pid, 0)
    res = json.loads(data)
    if "error" in res:
        sys.exit(f"error running as {user['name']}: {res['error']}")
    return res["ok"]


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------
def ename(e):
    return "OK" if e == 0 else errno.errorcode.get(e, str(e))


def klass(e):
    return {0: "OK", errno.EACCES: "EACCES", errno.ENOENT: "ENOENT"}.get(e, "OTHER")


class Stat:
    def __init__(self):
        self.n = 0
        self.act = collections.Counter()
        self.exp = collections.Counter()
        self.mismatch = 0

    def add(self, other):
        self.n += other.n
        self.act.update(other.act)
        self.exp.update(other.exp)
        self.mismatch += other.mismatch


def print_table(title, per_op):
    total = Stat()
    for s in per_op.values():
        total.add(s)
    print(f"\n=== {title} ===")
    print(f"{'op':<9}{'n':>6} | {'EACCES act/exp':>15} | {'ENOENT act/exp':>15} | "
          f"{'OK act/exp':>13} | {'other':>5} | {'mismatch':>8}")
    for label, s in list(sorted(per_op.items())) + [("TOTAL", total)]:
        print(f"{label:<9}{s.n:>6} | "
              f"{s.act['EACCES']:>7}/{s.exp['EACCES']:<7} | "
              f"{s.act['ENOENT']:>7}/{s.exp['ENOENT']:<7} | "
              f"{s.act['OK']:>6}/{s.exp['OK']:<6} | "
              f"{s.act['OTHER']:>5} | {s.mismatch:>8}")
    return total


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mount", help="path of the tree as seen through the FUSE mount")
    ap.add_argument("--manifest", default="tree_manifest.json")
    ap.add_argument("--users", default=None,
                    help="comma-separated usernames/uids to test as (default: "
                         "all owners in manifest + 65534 when root; else self)")
    ap.add_argument("--hide-policy", choices=["veil", "none"], default="veil",
                    help="'none' = oracle for a plain POSIX fs (harness sanity check)")
    ap.add_argument("--order", choices=["no-parent-x", "access-first", "hide-first"],
                    default="no-parent-x", help="see module docstring")
    ap.add_argument("--gid-match", choices=["primary", "all"], default="primary",
                    help="match entry gid against caller's primary gid only "
                         "(veilfs) or all supplementary groups too")
    ap.add_argument("--noread-dir-errno", choices=["ENOENT", "EACCES"],
                    default="EACCES",
                    help="errno for listdir on a directory the user can look up "
                         "but not read")
    ap.add_argument("--mutating", action="store_true",
                    help="also test create/mkdir (creates and removes temp "
                         "entries inside writable directories)")
    ap.add_argument("--show-mismatches", type=int, default=20,
                    help="max mismatches to print per user")
    ap.add_argument("--report", help="write full per-check results as JSON")
    args = ap.parse_args()

    CFG["policy"] = args.hide_policy
    CFG["order"] = "access-first" if args.hide_policy == "none" else args.order
    CFG["gid_match"] = "all" if args.hide_policy == "none" else args.gid_match
    CFG["readdir_errno"] = getattr(errno, args.noread_dir_errno)

    with open(args.manifest) as f:
        manifest = json.load(f)
    entries = {e["path"]: e for e in manifest["entries"]}
    children = collections.defaultdict(list)
    for p in entries:
        if p != ".":
            parent, _, name = p.rpartition("/")
            children[parent or "."].append(name)

    mount = os.path.abspath(args.mount)

    if args.users:
        users = [resolve_user(s) for s in args.users.split(",") if s]
    elif os.geteuid() == 0:
        uids = sorted({e["uid"] for e in entries.values()} | {65534})
        users = [resolve_user(u) for u in uids]
    else:
        users = [resolve_user(os.geteuid())]
    if os.geteuid() != 0 and any(u["uid"] != os.geteuid() for u in users):
        sys.exit("error: need root to run operations as other users")

    ops = [op for op, (_, _, mut) in OPS.items() if args.mutating or not mut]
    plan = []
    for path in sorted(entries):
        etype = entries[path]["type"]
        for op in ops:
            applies = OPS[op][0]
            if applies == "any" or applies == etype:
                plan.append((path, op))

    grand = {}
    full_report = {}
    exit_bad = False

    total_ops = 0;
    start = time.perf_counter()

    for user in users:
        actual = run_as(user, lambda: execute(mount, plan))
        per_op = collections.defaultdict(Stat)
        mismatches = []
        records = []
        leaks = missing = 0
        meta_checked = meta_stripped = meta_bad = 0

        for (path, op), (act, extra) in zip(plan, actual):
            exp = expected(op, path, user, entries)
            s = per_op[op]
            s.n += 1
            s.act[klass(act)] += 1
            s.exp[klass(exp)] += 1
            if act != exp:
                s.mismatch += 1
                e = entries[path]
                mismatches.append(
                    f"{op:<8} {path}  expected={ename(exp)} actual={ename(act)}"
                    f"  [{e['type']} uid={e['uid']} gid={e['gid']} "
                    f"mode={oct(e['mode'])}; user uid={user['uid']} gid={user['gid']}]")
            records.append({"path": path, "op": op,
                            "expected": ename(exp), "actual": ename(act)})

            if op == "stat" and act == 0 and exp == 0 and extra:
                meta_checked += 1
                if not full_metadata(entries[path], user):
                    meta_stripped += 1
                probs = check_meta(entries[path], user, extra)
                if probs:
                    meta_bad += 1
                    mismatches.append(f"stat_meta {path}  " + "; ".join(probs))

            if op == "listdir" and act == 0 and extra is not None:
                want = {n for n in children.get(path, [])
                        if listed(entries[(path + "/" + n) if path != "." else n], user)}
                got = set(extra)
                leaks += len(got - want)
                missing += len(want - got)
                for n in sorted(got - want):
                    mismatches.append(f"readdir_leak    {path}/{n}  (listed without r)")
                for n in sorted(want - got):
                    mismatches.append(f"readdir_missing {path}/{n}  (has r but not listed)")

        end = time.perf_counter()
        user_total = sum(s.n for s in per_op.values())
        total_ops += user_total

        label = f"{user['name']} (uid {user['uid']})"
        total = print_table(label, per_op)
        print(f"readdir: {leaks} entries listed that should be hidden, "
              f"{missing} readable entries missing")
        print(f"stat metadata: {meta_checked} checked ({meta_stripped} expected "
              f"stripped), {meta_bad} wrong")
        for m in mismatches[:args.show_mismatches]:
            print("  MISMATCH", m)
        if len(mismatches) > args.show_mismatches:
            print(f"  ... {len(mismatches) - args.show_mismatches} more")

        grand[label] = total
        full_report[label] = records
        if mismatches:
            exit_bad = True

    if len(users) > 1:
        overall = Stat()
        for s in grand.values():
            overall.add(s)
        print_table("ALL USERS", {"all": overall})

    if args.report:
        with open(args.report, "w") as f:
            json.dump(full_report, f, indent=1)

    print("\nRESULT:", "MISMATCHES FOUND" if exit_bad else "all results match the oracle")
    print(f"\nWALL TIME ELAPSED: {end - start:.6f} seconds")
    print(f"\nTOTAL OPERATIONS: {total_ops:,}")
    print(f"\nTHROUGHPUT (BASED OFF WALL TIME): {(total_ops / (end - start)):,.2f} ops/sec")
    sys.exit(1 if exit_bad else 0)


if __name__ == "__main__":
    main()