# VeilFS
**OVERVIEW:** VeilFS is a FUSE filesystem that hides the existence of files and directories to users lacking read permissions for them. When attempting to access such a file, the filesystem will report that the file doesn't exist (as opposed to reporting that permission was denied).

## Code:
* veilfs.c was built upon code from libfuse's passthrough_fh.c, version 3.14.0.
    * Each callback function needed to be changed to implement VeilFS' functionality.
* I wrote logging.c, logging.h, params.h, and repeat_test.sh.
* I used Claude to generate the first versions of gen_tree.py and fuse_check.py; I made modifications to the latter later to align the oracle with VeilFS' ideal results.

## Dependencies:
This project requires fuse3 to be installed to run. To install, run:
```bash
sudo apt update && sudo apt install libfuse3-dev
```

## System:
Testing was performed on NCSU's VCL (XINU+QEMU (CSC 501 new)) running linux version 6.8.0-54-generic.

## Building:
While in the top-level project folder, run:
```bash
autoreconf -fi
./configure
make
```

## Automated Test:
The results for this automated test are already present in tests/*.csv. Running this test again will append extra rows onto each .csv. Testing was replicated on VM on NCSU's VCL running linux version 6.8.0-54-generic.

Before running the automated test, run this script:
```bash
sudo chmod o+x ./scripts/create_users.sh
sudo ./scripts/create_users.sh
```
* Rarely, this script will hang. If it does, kill it with ctrl+c and run it again. Repeat this process until all three users (alice, bob, carol) are added.

To perform the same tests used in the report, while in the top-level project folder (VeilFS), run:
```bash
sudo chmod o+x ./scripts/repeat_test.sh
sudo ./scripts/repeat_test.sh 10
```
This will perform the following test 10 times under the normal filesystem, VeilFS without logging, and VeilFS with logging:
1. Generate a randomized file tree (using the iteration # as the seed).
2. For each entry, attempt to:
    * stat
    * open for read
    * open for write
    * list directory
    * change directory
    * create temp files
    * create temp directories
3. Repeat step 2 for each defined user (alice, bob, carol). An oracle will check the output (OK, EACCES, ENOENT) against VeilFS' intended behavior and track mismatches.
4. Calculate the total time for each iteration (wall time). This time is used for calculating ops/sec.
5. Append the result of each test to its respective .csv within /tests.

## Running:
While in the top-level project folder, run:
```bash
sudo ./src/veilfs [-l | -lc PATH] [-r PATH] [FUSE options] MOUNTPOINT
```
Important notes:
* You need sudo access in both the location where VeilFS and mountpoint are located. For example, if either is on an NFS where you lack sudo access, execution will fail.
* MOUNTPOINT cannot be "/".

Optional flags:
* -l : Enable logging (logs will be stored in /var/log).
* -lc PATH : Enable logging; store logs under PATH.
* -r PATH : Set a custom root of the filesystem. When entering the VeilFS mountpoint, this is where filesystem information will be served from.
* FUSE options : This is where flags for libfuse should go, such as -f for running in the foreground or -d for debugging.

To enter VeilFS, change directory to under mountpoint you entered when starting the program. You can verify that VeilFS is functioning correctly with the following:
```bash
echo "hello world" > test.txt
sudo chmod 400 test.txt
cat test.txt
```
If the user lacks root permissions, "cat test.txt" should return "No such file or directory". If logging was enabled when starting VeilFS, this attempt to access the file will be logged.

## Unmounting:
Ensure that nothing is currently under VeilFS mountpoint, then run:
```bash
sudo fusermount3 -u \[mountpoint\]
```
This will forcefully unmount the filesystem. You can verify that the umounting was successful with:
```bash
mount | grep veilfs
```
If VeilFS is not present for that mount point, then the unmounting was successful.

## Figures and Tables:
All data was collected with fuse_check.py, which runs on a filetree produced by gen_tree.py. The script repeat_test.sh automates this process. The data used from these tests were used to create tables and charts in google sheets.
