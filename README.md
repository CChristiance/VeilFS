# VeilFS
VeilFS is a FUSE filesystem that hides the existence of files and directories to users lacking read permissions for them. When attempting to access such a file, the filesystem will report that the file doesn't exist (as opposed to reporting that permission was denied).

# TODO: mention *where* to load/build/ruin VeilFS (i.e. VCL)

# Building:
While in the top-level project folder, run:
```bash
autoreconf -fi
./configure
make
```

# Running:
While in the top-level project folder, run:
```bash
sudo ./src/veilfs \[mountpoint\]
```
Important notes:
* You need sudo access in both the location where VeilFS and mountpoint are located. For example, if either is on an NFS where you lack sudo access, execution will fail.
* VeilFS does not enforce execution with sudo, but it requires it for full functionality. Without sudo, the FUSE daemon is limited to the privileges of whoever ran VeilFS.

# Unmounting:
Under normal circumstances, VeilFS will unmount upon exiting. However, if the program ends unexpectedly, run:
```bash
sudo fusermount3 -u \[mountpoint\]
```
This will forcefully unmount the filesystem. You can verify that the umounting was successful with:
```bash
mount | grep veilfs
```
If VeilFS is not present for that mount point, then the unmounting was successful.
