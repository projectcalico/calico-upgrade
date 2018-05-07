#!/bin/sh

# Monitors the status of the rollout of the calico-node Daemonset, the script
# will poll until the Rollout is complete and verify it is the correct Rollout
# by checking the calico/node images is the expected version.
#
# Requirements:
#  - calico-upgrade is available in the PATH
#  - kubectl is available in the PATH


DS_NAME=${DS_NAME:-"calico-node"}
DS_SELECTOR=${DS_SELECTOR:-"k8s-app=$DS_NAME"}
DS_IMAGE_SELECTOR="{.items[?(@.metadata.name=='$DS_NAME')].spec.template.spec.containers[?(@.name=='calico-node')].image}"
EXPECTED_NODE_IMAGE=${EXPECTED_NODE_IMAGE:-"quay.io/calico/node:v3.1.1"}
NAMESPACE=${NAMESPACE:-"kube-system"}

echo "Ensure that the Daemonset $DS_NAME is rolled out, and the calico-node"
echo "container is running $EXPECTED_NODE_IMAGE before completing the upgrade"

IsDsImageCorrect()
{
	image=$(kubectl -n $NAMESPACE get daemonset --selector=$DS_SELECTOR \
		-o jsonpath="$DS_IMAGE_SELECTOR")
	if [ $? -ne 0 ]; then
		return 1
	fi
	echo "$image" | grep "$EXPECTED_NODE_IMAGE"
}

IsDsRollOutFinished()
{
	rollout_status=$(kubectl -n $NAMESPACE rollout status daemonset/$DS_NAME)
	if [ $? -ne 0 ]; then
		return 1
	fi
	echo "$rollout_status" | grep "successfully rolled out"
}

echo "=== Current $DS_NAME Daemonset ==="
kubectl -n $NAMESPACE get daemonset --selector=$DS_SELECTOR

# Wait for calico-node daemonset to have a v3 calico-node image
while ! IsDsImageCorrect; do
	echo "Waiting for the image $EXPECTED_NODE_IMAGE to be in the Daemonset $DS_NAME"
	sleep 5
done

echo "=== Current $DS_NAME Daemonset ==="
kubectl -n $NAMESPACE get daemonset --selector=$DS_SELECTOR

# Wait for daemonset to finish rollout
while ! IsDsRollOutFinished; do
    echo "Waiting for Daemonset $DS_NAME to finish rolling out"
	sleep 5
done

# Verify daemonset still has v3 calico-node image, in case they've done a rollback
if ! IsDsImageCorrect; then
    echo "=== Current $DS_NAME Daemonset ==="
    kubectl -n $NAMESPACE get daemonset --selector=$DS_SELECTOR \
		-o jsonpath="$DS_IMAGE_SELECTOR"
    echo ""
	echo "After waiting for $DS_NAME to finish rolling out it does not have the expected"
	echo "calico/node image version.  If a rollback was done on the calico/node daemonset"
	echo "this Job should be deleted?"
	exit 1
fi

# Complete upgrade
calico-upgrade $UPGRADE_OPTIONS complete --no-prompts $UPGRADE_ARGS
if [ $? -ne 0 ]; then
	echo "Completing the upgrade failed,"
	exit 1
fi
