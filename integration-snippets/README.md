# Purpose

The scripts and snippets here are intended to support automating the upgrade
of a cluster through the addition of two initContainers and a Job. The scripts
are added to the calico/upgrade container image so they can be ran as
containers.

# Configuration

Each of the scripts need some configuration, here are the common options
between the scripts.

## V3 datastore configuration
The following can be used to configure access to the V3 datastore.

  CALICO_ETCD_ENDPOINTS
  CALICO_ETCD_USERNAME
  CALCIO_ETCD_PASSWORD
  CALICO_ETCD_KEY_FILE
  CALICO_ETCD_CERT_FILE
  CALICO_ETCD_CA_CERT_FILE

## V1 datastore configuration
The following can be used to configure access to the V1 datastore.

  CALICO_APIV1_ETCD_SCHEME
  CALICO_APIV1_ETCD_AUTHORITY
  CALICO_APIV1_ETCD_ENDPOINTS
  CALICO_APIV1_ETCD_USERNAME
  CALICO_APIV1_ETCD_PASSWORD
  CALICO_APIV1_ETCD_KEY_FILE
  CALICO_APIV1_ETCD_CERT_FILE
  CALICO_APIV1_ETCD_CA_CERT_FILE

## calico-upgrade configuration

It may be useful to provide some additional options or args to calico-upgrade.
The following are provided for that purpose:
* `UPGRADE_OPTIONS` can be used to to pass log level to the commands.
* `UPGRADE_ARGS` could be used to to pass apiconfig if config files are
  available instead of environment variables.

# Node Daemonset initContainer

This container will be responsible for checking if the datastore needs to be
migrated and if needed will start the migration. If the datastore migration is
in progress this container will block startup until it is complete.
The [script](node-init-container.sh) which does the above can be added to the
calico-node Daemonset with something like
[this snippet](node-init-container.yaml).

# calico/kube-controller initContainer

This container will be responsible for checking if the datastore needs to be
migrated and block startup until the migration is finished.
The [script](controller-init.sh) which does the above can be added to the
calico-kube-controllers Deployment with something like
[this snippet](controller-init.yaml).

# Calico upgrade completion Job

This container will be responsible for checking if the calico-node Daemonset
has rolled out before completing the upgrade. It also checks that the Daemonset
has the correct calico/node image as a check that the proper Daemonset
rolled out.
The [script](completion-job.sh) which does the above can be deployed with
something like [this snippet](completion-job.yaml).

## Daemonset monitor configuration

The monitoring of the Daemonset has some values that may change in some
deployments so the following are exposed to allow their configuration.
* `DS_NAME`: This should be the name of the 'new' Calico Daemonset.
  (Default: "calico-node")
* `DS_SELECTOR`: This is the selector used select the rollout that is being
  monitored.  (Default: "k8s-app=$DS_NAME")
* `DS_IMAGE_SELECTOR`: This is the jsonpath used to select the name of the
  image for the calico-node container. (Default: "{.items[?(@.metadata.name=='$DS_NAME')].spec.template.spec.containers[?(@.name=='calico-node')].image}")
* `EXPECTED_NODE_IMAGE`: This is the image that is expected in the Daemonset,
  this is to ensure the correct Daemonset is rolled out.
  (Default: "quay.io/calico/node:v3.1.1")
