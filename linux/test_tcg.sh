#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo device not specified
    exit
fi

# test basic sedutil commands on selected device
DEV="$1"
set -x
set -e

sedutil-cli --isValidSED $DEV | grep 'SED -2'

PASSWORD=$(sedutil-cli --printDefaultPassword $DEV | awk '/MSID/ {print $2}')

sedutil-cli --takeOwnership $PASSWORD $DEV

function cleanup {
  sedutil-cli --revertTPer $PASSWORD $DEV
}
trap cleanup EXIT

sedutil-cli --activateLockingSP $PASSWORD $DEV
sedutil-cli --query $DEV | grep -o 'LockingEnabled = Y'

sedutil-cli --enableLockingRange 0 $PASSWORD $DEV
sedutil-cli --listLockingRange   0 $PASSWORD $DEV | grep -o 'RLKEna = Y  WLKEna = Y  RLocked = N  WLocked = N'

echo PASS
