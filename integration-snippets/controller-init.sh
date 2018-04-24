#!/bin/sh

# This script checks if upgrade is needed and returns 0 if no upgrade
# is needed.
#
# Requirements:
#  - calico-upgrade is available in the PATH


calico-upgrade $UPGRADE_OPTIONS needed $UPGRADE_ARGS
needed=$?
while [ $needed -eq 0 ]; do
    sleep 5
    calico-upgrade $UPGRADE_OPTIONS needed $UPGRADE_ARGS
    needed=$?
done

if [ $needed -eq 1 ]; then
	echo "No data migration is needed. Continuing on."
	exit 0
fi

# Will hit this if there is a problem accessing the datastore
exit 1
