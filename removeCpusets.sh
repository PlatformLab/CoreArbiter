#!/bin/bash

if [[ $(id -u) -ne 0 ]]; then
    echo "You must be root to run this script!"
    exit
fi

exec 2>/dev/null

CPU_DIR="/sys/fs/cgroup/cpuset"
ARBITER_DIR=$CPU_DIR/CoreArbiter
SHARED_DIR=$ARBITER_DIR/Shared

for i in $(cat $SHARED_DIR/cgroup.procs ); do echo $i > $CPU_DIR/cgroup.procs ; done
rmdir $SHARED_DIR

for i in {1..3}; do
    rmdir $ARBITER_DIR/Exclusive$i
done
rmdir $ARBITER_DIR