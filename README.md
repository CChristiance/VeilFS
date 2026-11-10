# VeilFS
VeilFS is a FUSE filesystem that hides the existence of files and directories to users lacking read permissions for them. When attempting to access such a file, the filesystem will report that the file doesn't exist (as opposed to reporting that permission was denied).

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
