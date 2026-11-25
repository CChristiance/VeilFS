#!/usr/bin/env python3
"""
gen_tree.py - generate a randomized file tree with mixed owners, groups and
permissions, plus a JSON manifest describing it.

Run this against the backing directory of the FUSE filesystem (or against the
mount as root, if root sees everything). Must run as root if you want more than
one owner.

Example:
    sudo ./gen_tree.py /srv/backing --depth 5 --max-files 200 \
         --users alice,bob,carol --seed 42 --manifest tree.json
"""
import argparse
import json
import os
import pwd
import random
import sys

# Duplicates are deliberate: they weight the common modes.
FILE_MODES = [0o600, 0o600, 0o644, 0o644, 0o640, 0o660, 0o664, 0o666, 0o700,
              0o750, 0o755, 0o777, 0o400, 0o444, 0o440, 0o000, 0o004, 0o070,
              0o007, 0o100]
DIR_MODES = [0o700, 0o700, 0o750, 0o755, 0o755, 0o770, 0o775, 0o777, 0o711,
             0o710, 0o555, 0o500, 0o000, 0o100, 0o111, 0o044]


def resolve_user(spec):
    try:
        uid = int(spec)
        try:
            pw = pwd.getpwuid(uid)
        except KeyError:
            return {"uid": uid, "name": str(uid), "gid": uid, "groups": [uid]}
    except ValueError:
        try:
            pw = pwd.getpwnam(spec)
        except KeyError:
            sys.exit(f"error: user '{spec}' does not exist on this system "
                     f"(create it, e.g. 'sudo useradd -M {spec}', or pass numeric uids)")
    groups = sorted(set(os.getgrouplist(pw.pw_name, pw.pw_gid)))
    return {"uid": pw.pw_uid, "name": pw.pw_name, "gid": pw.pw_gid,
            "groups": groups}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", help="directory to populate (backing dir)")
    ap.add_argument("--depth", type=int, default=4, help="max directory depth")
    ap.add_argument("--max-files", type=int, default=100)
    ap.add_argument("--max-dirs", type=int, default=None,
                    help="max directories (default: max(depth, max_files/3))")
    ap.add_argument("--max-branch", type=int, default=3,
                    help="max subdirectories per directory")
    ap.add_argument("--users", default="",
                    help="comma-separated usernames/uids to own entries "
                         "(default: current user)")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--manifest", default="tree_manifest.json")
    ap.add_argument("--force", action="store_true",
                    help="allow populating a non-empty directory")
    args = ap.parse_args()

    specs = [s for s in args.users.split(",") if s] or [str(os.geteuid())]
    users = [resolve_user(s) for s in specs]
    if os.geteuid() != 0 and any(u["uid"] != os.geteuid() for u in users):
        sys.exit("error: need root to create files owned by other users")

    seed = args.seed if args.seed is not None else random.SystemRandom().randrange(2**32)
    rng = random.Random(seed)
    max_dirs = args.max_dirs or max(args.depth, args.max_files // 3)
    all_gids = sorted({g for u in users for g in u["groups"]})

    root = os.path.abspath(args.root)
    os.makedirs(root, exist_ok=True)
    if os.listdir(root) and not args.force:
        sys.exit(f"error: {root} is not empty (use --force)")

    entries = []          # created entries, parents always before children
    stack = [(".", 0)]
    files_left = args.max_files
    dirs_left = max_dirs
    avg_files = max(1, round(args.max_files / max_dirs))
    counter = 0

    def pick_owner():
        owner = rng.choice(users)
        gid = owner["gid"] if rng.random() < 0.6 else rng.choice(all_gids)
        return owner["uid"], gid

    while stack:
        rel, level = stack.pop()
        absd = root if rel == "." else os.path.join(root, rel)

        for _ in range(min(files_left, rng.randint(0, 2 * avg_files))):
            counter += 1
            name = f"f{counter:04d}.dat"
            crel = name if rel == "." else f"{rel}/{name}"
            data = rng.randbytes(rng.randint(1, 256))
            with open(os.path.join(absd, name), "wb") as f:
                f.write(data)
            uid, gid = pick_owner()
            entries.append({"path": crel, "type": "file", "uid": uid,
                            "gid": gid, "mode": rng.choice(FILE_MODES),
                            "size": len(data)})
            files_left -= 1

        if level < args.depth:
            for _ in range(min(dirs_left, rng.randint(1, args.max_branch))):
                counter += 1
                name = f"d{counter:04d}"
                crel = name if rel == "." else f"{rel}/{name}"
                os.mkdir(os.path.join(root, crel))
                uid, gid = pick_owner()
                entries.append({"path": crel, "type": "dir", "uid": uid,
                                "gid": gid, "mode": rng.choice(DIR_MODES)})
                stack.append((crel, level + 1))
                dirs_left -= 1

    # Apply owners/modes last, children before parents, so restrictive parent
    # modes never get in the way of creation.
    for e in reversed(entries):
        p = os.path.join(root, e["path"])
        os.lchown(p, e["uid"], e["gid"])
        os.chmod(p, e["mode"])

    st = os.stat(root)
    manifest_entries = [{"path": ".", "type": "dir", "uid": st.st_uid,
                         "gid": st.st_gid, "mode": st.st_mode & 0o7777}] + entries
    for e in manifest_entries:
        e["mode_octal"] = oct(e["mode"])
    with open(args.manifest, "w") as f:
        json.dump({"version": 1, "seed": seed, "users": users,
                   "entries": manifest_entries}, f, indent=1)

    nfiles = sum(e["type"] == "file" for e in entries)
    ndirs = sum(e["type"] == "dir" for e in entries)
    print(f"seed={seed}: created {ndirs} dirs and {nfiles} files under {root}")
    print(f"owners: {', '.join(u['name'] for u in users)}")
    print(f"manifest written to {args.manifest}")


if __name__ == "__main__":
    main()