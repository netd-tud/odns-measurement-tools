#!/bin/bash
set -e
if [ -z "$1" ]; then
    echo "specify build path"
    exit 1
fi

srcpath=$1
if [ ! -d "$srcpath" ]; then
    echo "$srcpath is not a directory or valid keyword"
exit 2
fi

cd $srcpath
binpath="run.elf"
if [ -n "$2" ]; then
    binpath=$2
fi

go build -o $binpath
sudo chmod 750 $binpath
if [ $(getent group pcap) ]; then
    sudo chgrp pcap $binpath
fi
sudo setcap cap_net_raw+ep $binpath
if [ -f "~/go/bin/dlv" ]; then
    sudo setcap cap_net_raw+ep ~/go/bin/dlv
fi
