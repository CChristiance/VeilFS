#!/usr/bin/env python3
"""
fuse_check.py - exercise a "hide-what-you-can't access" FUSE filesystem.

For every entry in the manifest produced by gen_tree.py, and for each test
user, perform a set of file operations through the mount, record the errno
actually returned, and compare it against an oracle of what the filesystem
SHOULD return.

Oracle model (edit the constants / functions below if your FS differs):
  * Resolving a path walks component by component. For each component:
      - the parent directory needs search (x) permission  -> else EACCES
      - the child must be "visible" to the user           -> else ENOENT
    (order configurable with --order)
  * Visibility is decided by --hide-policy:
      read : user has r on the entry                (default)
      any  : user has at least one of r/w/x on it
      rx   : user has r or x on it
      none : nothing is ever hidden (plain POSIX)
  * If the path resolves, the operation itself needs normal POSIX permission
    on the target, else EACCES.
  * root (uid 0) bypasses all checks (ROOT_BYPASSES).

Must run as root to test as several users (it forks and drops privileges).
The FUSE mount needs -o allow_other for other uids to reach it at all.

Example:
    sudo ./fuse_check.py /mnt/fusefs --manifest tree.json --users alice,bob,carol
"""
import argparse
import collections
import errno
import json
import os
import pwd
import sys

ROOT_BYPASSES = True
R, W, X = 4, 2, 1

# op -> (applies to, permission bits needed on target, mutating?)
OPS = {
    "stat":    ("any",  0,     False),
    "open_r":  ("any",  R,     False),
    "open_w":  ("file", W,     False),
    "listdir": ("dir",  R,     False),
    "chdir":   ("dir",  X,     False),
    "create":  ("dir",  W | X, True),
    "mkdir":   ("dir",  W | X, True),
}

CLASSES = ("EACCES", "ENOENT", "OK")


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
def perm_bits(entry, user):
    if entry["uid"] == user["uid"]:
        shift = 6
    elif entry["gid"] in user["groups"]:
        shift = 3
    else:
        shift = 0
    return (entry["mode"] >> shift) & 7


def can(entry, user, bit):
    if ROOT_BYPASSES and user["uid"] == 0:
        if bit == X and entry["type"] == "file":
            return bool(entry["mode"] & 0o111)
        return True
    return bool(perm_bits(entry, user) & bit)


def visible(entry, user, policy):
    if policy == "none" or (ROOT_BYPASSES and user["uid"] == 0):
        return True
    bits = perm_bits(entry, user)
    if policy == "read":
        return bool(bits & R)
    if policy == "any":
        return bits != 0
    if policy == "rx":
        return bool(bits & (R | X))
    raise ValueError(policy)


def expected_lookup(path, user, entries, policy, order):
    """errno the path walk should produce, or 0 if it resolves."""
    if path == ".":
        return 0
    cur = entries["."]
    prefix = []
    for part in path.split("/"):
        prefix.append(part)
        child = entries["/".join(prefix)]
        if order == "hide-first":
            if not visible(child, user, policy):
                return errno.ENOENT
            if not can(cur, user, X):
                return errno.EACCES
        else:
            if not can(cur, user, X):
                return errno.EACCES
            if not visible(child, user, policy):
                return errno.ENOENT
        cur = child
    return 0


def expected(op, path, user, entries, policy, order):
    err = expected_lookup(path, user, entries, policy, order)
    if err:
        return err
    need = OPS[op][1]
    for bit in (R, W, X):
        if need & bit and not can(entries[path], user, bit):
            return errno.EACCES
    return 0


# --------------------------------------------------------------------------
# actual operations (run as the target user)
# --------------------------------------------------------------------------
def execute(mount, plan):
    out = []
    for path, op in plan:
        p = mount if path == "." else os.path.join(mount, path)
        names = None
        try:
            if op == "stat":
                os.lstat(p)
            elif op == "open_r":
                os.close(os.open(p, os.O_RDONLY | os.O_NONBLOCK))
            elif op == "open_w":
                os.close(os.open(p, os.O_WRONLY | os.O_NONBLOCK))
            elif op == "listdir":
                names = sorted(os.listdir(p))
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
        out.append([err, names])
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
    ap.add_argument("--hide-policy", choices=["read", "any", "rx", "none"],
                    default="read")
    ap.add_argument("--order", choices=["access-first", "hide-first"],
                    default="access-first",
                    help="whether a missing x on the parent (EACCES) or hiding "
                         "of the child (ENOENT) takes precedence")
    ap.add_argument("--mutating", action="store_true",
                    help="also test create/mkdir (creates and removes temp "
                         "entries inside writable directories)")
    ap.add_argument("--show-mismatches", type=int, default=20,
                    help="max mismatches to print per user")
    ap.add_argument("--report", help="write full per-check results as JSON")
    args = ap.parse_args()

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
    leak_totals = {}

    for user in users:
        actual = run_as(user, lambda: execute(mount, plan))
        per_op = collections.defaultdict(Stat)
        mismatches = []
        records = []
        leaks = missing = 0

        for (path, op), (act, names) in zip(plan, actual):
            exp = expected(op, path, user, entries, args.hide_policy, args.order)
            s = per_op[op]
            s.n += 1
            s.act[klass(act)] += 1
            s.exp[klass(exp)] += 1
            if act != exp:
                s.mismatch += 1
                mismatches.append((path, op, exp, act))
            records.append({"path": path, "op": op,
                            "expected": ename(exp), "actual": ename(act)})

            if op == "listdir" and act == 0 and names is not None:
                want = {n for n in children.get(path, [])
                        if visible(entries[(path + "/" + n) if path != "." else n],
                                   user, args.hide_policy)}
                got = set(names)
                leaks += len(got - want)
                missing += len(want - got)
                for n in sorted(got - want):
                    mismatches.append((f"{path}/{n}", "readdir_leak", 0, 0))
                for n in sorted(want - got):
                    mismatches.append((f"{path}/{n}", "readdir_missing", 0, 0))

        label = f"{user['name']} (uid {user['uid']})"
        total = print_table(label, per_op)
        print(f"readdir: {leaks} entries listed that should be hidden, "
              f"{missing} visible entries missing")
        for path, op, exp, act in mismatches[:args.show_mismatches]:
            if op.startswith("readdir_"):
                print(f"  MISMATCH {op:<16} {path}")
            else:
                print(f"  MISMATCH {op:<8} {path}  expected={ename(exp)} actual={ename(act)}")
        if len(mismatches) > args.show_mismatches:
            print(f"  ... {len(mismatches) - args.show_mismatches} more")

        grand[label] = total
        leak_totals[label] = (leaks, missing)
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
    sys.exit(1 if exit_bad else 0)


if __name__ == "__main__":
    main()