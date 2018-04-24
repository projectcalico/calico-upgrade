#!/bin/sh

# Checks if upgrade is needed and starts/runs the upgrade
# if one is not already in progress.
#
# Requirements:
#  - calico-upgrade is available in the PATH

calico-upgrade $UPGRADE_OPTIONS needed $UPGRADE_ARGS
status=$?
if [ $status -eq 1 ]; then
    echo "No data migration is needed. Continuing on."
    exit 0
elif [ $status -gt 1 ]; then
    echo "Error checking if migration is needed"
    exit 1
fi

# Before starting the migration first check if one is already in progress
calico-upgrade $UPGRADE_OPTIONS inprogress $UPGRADE_ARGS
inprogress=$?
while [ $inprogress -eq 0 ]; do
    sleep 5
    calico-upgrade $UPGRADE_OPTIONS inprogress $UPGRADE_ARGS
    inprogress=$?
    if [ $inprogress -gt 1 ]; then
        echo "Error checking if migration is in progress"
        exit 1
    fi
done

# Check one more time before exiting
calico-upgrade $UPGRADE_OPTIONS needed $UPGRADE_ARGS
status=$?
if [ $status -eq 1 ]; then
    echo "No data migration is needed. Continuing on."
    exit 0
elif [ $status -gt 1 ]; then
    echo "Error checking if migration is needed"
    exit 1
fi

REPORT_DIR=${REPORT_DIR:-migration-output}
# Capture the output so we can dump other information before this output
# is printed so it is some of the last information presented.
calico-upgrade $UPGRADE_OPTIONS start --no-prompts --output-dir=$REPORT_DIR $UPGRADE_ARGS &> migration.out
status=$?

# Dump the migration files so they are in the log
find $REPORT_DIR -type f -print0 | xargs -0 -I {} sh -c 'echo "=== Contents of {} ==="; cat "{}"'

echo "=== Migration output ==="
# Dump the migration output so it does not get lost in the migration files output
cat migration.out

if [ $status -ne 0 ]; then
    echo "The status returned by the calico-upgrade command was $status"
    echo "indicating there was an error. Review the above output and the"
    echo "conversion results output for problems."
    echo "To recover from errors consult your integrations documentation"
    echo "for recovery help."
fi
exit $status
