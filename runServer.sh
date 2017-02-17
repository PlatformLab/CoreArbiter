#!/bin/bash

if [[ $(id -u) -ne 0 ]]; then
    echo "You must be root to run this script!"
    exit
fi

./removeCpusets.sh
rm -f testmem*
rm -f testsocket
./server
