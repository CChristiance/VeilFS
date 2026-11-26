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
