#!/usr/bin/env python

import sys, re
import os, os.path
import shutil
import subprocess

def main():
    # Ask for MMLEAK_DIR
    try:
        input = raw_input
    except NameError:
        pass

    mmleak_dir = input("Specify a directory for mmleak to store all its dumps: ")
    if not os.path.isdir(mmleak_dir):
        sys.exit("%s is not a directory!" % mmleak_dir)

    if not os.path.isfile("mmleak.so"):
        sys.exit("mmleak.so file not found in the current working directory")

    # /root is always expected to be there!
    if not shutil._samefile("mmleak.so", "/root/mmleak.so"):
        shutil.copyfile("mmleak.so", "/root/mmleak.so")

    # Create the NFS-Ganesha service file in /etc/systemd
    filename = "/usr/lib/systemd/system/nfs-ganesha.service"
    data = open(filename).read()
    data = data.replace("${NUMACTL}",
            "MMLEAK_DIR=%s LD_PRELOAD=/root/mmleak.so ${NUMACTL}" % mmleak_dir,
            1)
    filename = "/etc/systemd/system/nfs-ganesha.service"
    modify_file(filename, data)
    subprocess.check_call("systemctl daemon-reload", shell=True)
    print("\nSuccessfully created user modified nfs-ganesha service unit file "
          "'/etc/systemd/system/nfs-ganesha.service'. Remove this file to undo "
          "the changes done by this script!")

# Modify the file with the given data atomically
def modify_file(filename, data):
    from tempfile import NamedTemporaryFile
    f = NamedTemporaryFile(dir=os.path.dirname(filename), delete=False)
    f.write(data)
    f.flush()
    os.fsync(f.fileno())

    # If filename exists, get its stats and apply them to the temp file
    try:
        stat = os.stat(filename)
        os.chown(f.name, stat.st_uid, stat.st_gid)
        os.chmod(f.name, stat.st_mode)
    except:
        pass

    os.rename(f.name, filename)

main()
