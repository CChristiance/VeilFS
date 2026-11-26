#!/bin/sh

# call with: ./scripts/repeat_test <iterations>

MNT=$(realpath ./mnt)

cleanup() {
    sudo fusermount3 -u "$MNT" 2>/dev/null
    if [ -n "$FUSE_PID" ]; then
        wait "$FUSE_PID" 2>/dev/null
    fi
}
trap cleanup EXIT

# Ensure the shared group exists
if ! getent group shared >/dev/null 2>&1; then
    echo "Creating group 'shared'..."
    if ! sudo groupadd shared; then
        echo "Failed to create group 'shared'." >&2
        exit 1
    fi
fi
if ! getent group shared >/dev/null 2>&1; then
    echo "Group 'shared' still does not exist, aborting." >&2
    exit 1
fi

# Ensure each user exists and belongs to the shared group
for user in alice bob carol; do
    if id -u "$user" >/dev/null 2>&1; then
        echo "$user exists, skipping creation."
    else
        if sudo useradd -m -s /bin/bash -G shared "$user"; then
            echo "Created $user and added to shared."
        else
            echo "Failed to create $user, aborting." >&2
            exit 1
        fi
    fi

    # Covers users that already existed but aren't in the group
    if ! id -nG "$user" | tr ' ' '\n' | grep -qx shared; then
        if ! sudo usermod -aG shared "$user"; then
            echo "Failed to add $user to shared, aborting." >&2
            exit 1
        fi
        echo "Added $user to shared."
    fi

    # Final check before moving on
    if ! id -nG "$user" | tr ' ' '\n' | grep -qx shared; then
        echo "$user is not in group 'shared', aborting." >&2
        exit 1
    fi
done

# use predictable seeds so VeilFS and the base filesystem run on the same trees
echo "Running control tests..."
for i in $(seq 1 $1); do
    python3 ./scripts/gen_tree.py tests/treetest/ --seed $i --depth 10 --max-files 1000 --users alice,bob,carol --manifest tests/tree.json
    python3 ./scripts/fuse_check.py tests/treetest/ --manifest tests/tree.json --users alice,bob,carol --mutating --spreadsheet tests/treetest_control.csv
    rm -rf tests/treetest/
    rm tests/tree.json
done

echo "Mounting VeilFS without logging..."
sudo ./src/veilfs -r . -f mnt &
FUSE_PID=$!
for i in $(seq 1 50); do
    mountpoint -q "$MNT" && break
    sleep 0.1
done
if ! mountpoint -q "$MNT"; then
    echo "veilfs failed to mount, ending testing early" >&2
    sudo kill "$FUSE_PID" 2>/dev/null
    exit 1
fi

echo "Running VeilFS tests without logging..."
for i in $(seq 1 $1); do
    python3 ./scripts/gen_tree.py tests/treetest/ --seed $i --depth 10 --max-files 1000 --users alice,bob,carol --manifest tests/tree.json
    (cd mnt && sudo python3 ./scripts/fuse_check.py tests/treetest/ --manifest tests/tree.json --users alice,bob,carol --mutating --spreadsheet tests/treetest_veilfs_no_logging.csv)
    # python3 ./scripts/fuse_check.py "$MNT/tests/treetest/" \
    #     --manifest "$PWD/tests/tree.json" \
    #     --users alice,bob,carol --mutating \
    #     --spreadsheet "$PWD/tests/treetest_veilfs_no_logging.csv"
    rm -rf tests/treetest/
    rm tests/tree.json
done

sudo fusermount3 -u "$MNT" 2>/dev/null
wait "$FUSE_PID" 2>/dev/null

echo "Mounting VeilFS with logging..."
sudo ./src/veilfs -lc log -r . -f mnt &
FUSE_PID=$!
for i in $(seq 1 50); do
    mountpoint -q "$MNT" && break
    sleep 0.1
done
if ! mountpoint -q "$MNT"; then
    echo "veilfs failed to mount, ending testing early" >&2
    sudo kill "$FUSE_PID" 2>/dev/null
    exit 1
fi

echo "Running VeilFS tests with logging..."
for i in $(seq 1 $1); do
    python3 scripts/gen_tree.py tests/treetest/ --seed $i --depth 10 --max-files 1000 --users alice,bob,carol --manifest tests/tree.json
    (cd mnt && sudo python3 ./scripts/fuse_check.py tests/treetest/ --manifest tests/tree.json --users alice,bob,carol --mutating --spreadsheet tests/treetest_veilfs_logging.csv)
    # python3 ./scripts/fuse_check.py "$MNT/tests/treetest/" \
    #     --manifest "$PWD/tests/tree.json" \
    #     --users alice,bob,carol --mutating \
    #     --spreadsheet "$PWD/tests/treetest_veilfs_logging.csv"
    rm -rf tests/treetest/
    rm tests/tree.json
done

sudo fusermount3 -u "$MNT" 2>/dev/null
wait "$FUSE_PID" 2>/dev/null

echo "Testing complete. Results are in .csv format in the tests folder."
