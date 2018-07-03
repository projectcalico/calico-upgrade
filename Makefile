.PHONY: all binary test clean help
default: help
test: test-containerized                             ## Run all the tests
all: build

ARCHES=$(patsubst Dockerfile.%,%,$(wildcard Dockerfile.*))

# BUILDARCH is the host architecture
# ARCH is the target architecture
# we need to keep track of them separately
BUILDARCH ?= $(shell uname -m)
BUILDOS ?= $(shell uname -s | tr A-Z a-z)

# canonicalized names for host architecture
ifeq ($(BUILDARCH),aarch64)
        BUILDARCH=arm64
endif
ifeq ($(BUILDARCH),x86_64)
        BUILDARCH=amd64
endif

# unless otherwise set, I am building for my own architecture, i.e. not cross-compiling
ARCH ?= $(BUILDARCH)

# canonicalized names for target architecture
ifeq ($(ARCH),aarch64)
        override ARCH=arm64
endif
ifeq ($(ARCH),x86_64)
    override ARCH=amd64
endif

###############################################################################
# Go Build versions
GO_BUILD_VER:=v0.16
CALICO_BUILD?=calico/go-build:$(GO_BUILD_VER)

# Figure out the user's UID.  This is needed to run docker containers
# as the current user and ensure that files built inside containers are
# owned by the current user.
LOCAL_USER_ID?=$(shell id -u $$USER)

PACKAGE_NAME?=github.com/projectcalico/calico-upgrade

DOCKER_GO_BUILD := mkdir -p .go-pkg-cache && \
                   docker run --rm \
                              --net=host \
                              $(EXTRA_DOCKER_ARGS) \
                              -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
                              -e GOOS=$(OS) \
                              -e GOARCH=$(ARCH) \
                              -v ${CURDIR}:/go/src/$(PACKAGE_NAME):rw \
                              -v ${CURDIR}/.go-pkg-cache:/go/pkg:rw \
                              -w /go/src/$(PACKAGE_NAME) \
                              $(CALICO_BUILD)

###############################################################################
# Version directory
CALICO_UPGRADE_DIR=$(dir $(realpath $(lastword $(MAKEFILE_LIST))))
VERSIONS_FILE?=$(CALICO_UPGRADE_DIR)../_data/versions.yml

# Now use ?= to allow the versions derived from versions.yml to be
# overriden (by the environment).
CALICOCTL_VER?=master
CALICOCTL_V2_VER?=v1.6.x-series
K8S_VERSION?=v1.10.4
ETCD_VER?=v3.3.7
ifneq ($(ARCH),amd64)
    ETCD_VER := $(ETCD_VER)-$(ARCH)
endif

# Construct the calico/ctl names we'll use to download calicoctl and extract the
# binaries.
$(info $(shell printf "%-21s = %-10s\n" "CALICOCTL_VER" $(CALICOCTL_VER)))
$(info $(shell printf "%-21s = %-10s\n" "CALICOCTL_V2_VER" $(CALICOCTL_V2_VER)))
CTL_CONTAINER_NAME?=calico/ctl:$(CALICOCTL_VER)
CTL_CONTAINER_V2_NAME?=calico/ctl:$(CALICOCTL_V2_VER)
KUBECTL_URL=https://dl.k8s.io/$(K8S_VERSION)/kubernetes-client-linux-$(ARCH).tar.gz

###############################################################################
# calico-upgrade build
# - Building the calico-upgrade binary in a container
# - Building the calico-upgrade binary outside a container ("simple-binary")
# - Building the calico/upgrade image
###############################################################################
# Determine which OS / ARCH.
OS ?= $(shell uname -s | tr A-Z a-z)

GIT_VERSION?=$(shell git describe --tags --dirty --always)
CALICO_UPGRADE_DIR=pkg
CONTAINER_NAME?=calico/upgrade
CALICO_UPGRADE_FILES=$(shell find $(CALICO_UPGRADE_DIR) -name '*.go')
CALICO_UPGRADE_CONTAINER_CREATED=$(CALICO_UPGRADE_DIR)/.calico_upgrade.created

CALICO_UPGRADE_BUILD_DATE?=$(shell date -u +'%FT%T%z')
CALICO_UPGRADE_GIT_REVISION?=$(shell git rev-parse --short HEAD)

CALICO_UPGRADE_VERSION ?= $(GIT_VERSION)
LDFLAGS=-ldflags "-X $(PACKAGE_NAME)/pkg/commands.VERSION=$(CALICO_UPGRADE_VERSION) \
	-X $(PACKAGE_NAME)/pkg/commands.BUILD_DATE=$(CALICO_UPGRADE_BUILD_DATE) \
	-X $(PACKAGE_NAME)/pkg/commands.GIT_REVISION=$(CALICO_UPGRADE_GIT_REVISION) -s -w"

LIBCALICOGO_PATH?=none

# curl should failed on 404
CURL=curl -sSf

###############################################################################
# Building the binary
###############################################################################
build: bin/calico-upgrade
build-all: $(addprefix sub-build-,$(ARCHES)) sub-build-amd64-darwin sub-build-amd64-windows
sub-build-%:
	$(MAKE) build ARCH=$* OS=linux

sub-build-amd64-darwin:
	$(MAKE) build ARCH=amd64 OS=darwin

sub-build-amd64-windows:
	$(MAKE) build ARCH=amd64 OS=windows

calico/upgrade: $(CALICO_UPGRADE_CONTAINER_CREATED)      ## Create the calico/upgrade image

.PHONY: clean-calico-upgrade
clean-calico-upgrade:
	docker rmi $(CONTAINER_NAME):latest || true

# Use this to populate the vendor directory after checking out the repository.
# To update upstream dependencies, delete the glide.lock file first.
vendor: glide.yaml
	# Ensure that the glide cache directory exists.
	mkdir -p $(HOME)/.glide

	# To build without Docker just run "glide install -strip-vendor"
	if [ "$(LIBCALICOGO_PATH)" != "none" ]; then \
          EXTRA_DOCKER_BIND="-v $(LIBCALICOGO_PATH):/go/src/github.com/projectcalico/libcalico-go:ro"; \
	fi; \
  docker run --rm \
    -v $(CURDIR):/go/src/$(PACKAGE_NAME):rw $$EXTRA_DOCKER_BIND \
    -v $(HOME)/.glide:/home/user/.glide:rw \
    -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
    $(CALICO_BUILD) /bin/sh -c ' \
		  cd /go/src/$(PACKAGE_NAME) && \
      glide install -strip-vendor'

dist/calico-upgrade-$(OS)-$(ARCH): vendor
	$(DOCKER_GO_BUILD) \
	    sh -c 'go build -v -o $@ $(LDFLAGS) "$(PACKAGE_NAME)/pkg" && \
		( ldd $@ 2>&1 | grep -q -e "Not a valid dynamic program" \
			-e "not a dynamic executable" || \
	             ( echo "Error: $@ was not statically linked"; false ) )'
ifeq ($(OS)/$(ARCH),linux/amd64)
	mv dist/calico-upgrade-linux-amd64 dist/calico-upgrade
endif
ifeq ($(OS)/$(ARCH),windows/amd64)
	mv dist/calico-upgrade-windows-amd64 dist/calico-upgrade-windows-amd64.exe
endif

bin/calico-upgrade: dist/calico-upgrade-$(OS)-$(ARCH)

###############################################################################
# Building the image
###############################################################################
image-all: $(addprefix sub-image-,$(ARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*
image: build dist/kubectl
	docker build -t $(CONTAINER_NAME):latest-$(ARCH) -f Dockerfile.$(ARCH) .
ifeq ($(ARCH),amd64)
	docker tag $(CONTAINER_NAME):latest-$(ARCH) $(CONTAINER_NAME):latest
endif

# ensure we have a real imagetag
imagetag:
ifndef IMAGETAG
	$(error IMAGETAG is undefined - run using make <target> IMAGETAG=X.Y.Z)
endif

## push one arch
push: imagetag
	docker push $(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)
	docker push quay.io/$(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)
ifeq ($(ARCH),amd64)
	docker push $(CONTAINER_NAME):$(IMAGETAG)
	docker push quay.io/$(CONTAINER_NAME):$(IMAGETAG)
endif

## push all archs
push-all: imagetag $(addprefix sub-push-,$(ARCHES))
sub-push-%:
	$(MAKE) push ARCH=$* IMAGETAG=$(IMAGETAG)


## tag images of one arch
tag-images: imagetag
	docker tag $(CONTAINER_NAME):latest-$(ARCH) $(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)
	docker tag $(CONTAINER_NAME):latest-$(ARCH) quay.io/$(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)
ifeq ($(ARCH),amd64)
	docker tag $(CONTAINER_NAME):latest-$(ARCH) $(CONTAINER_NAME):$(IMAGETAG)
	docker tag $(CONTAINER_NAME):latest-$(ARCH) quay.io/$(CONTAINER_NAME):$(IMAGETAG)
endif

## tag images of all archs
tag-images-all: imagetag $(addprefix sub-tag-images-,$(ARCHES))
sub-tag-images-%:
	$(MAKE) tag-images ARCH=$* IMAGETAG=$(IMAGETAG)

dist/kubectl: dist/kubectl-$(ARCH)

# Download kubectl instead of copying from hyperkube because it is 4x smaller
# this way
dist/kubectl-$(ARCH):
	$(CURL) -L $(KUBECTL_URL) -o - | tar -zxvf - --strip-components=3 -O kubernetes/client/bin/kubectl > $@
	chmod +x $@

## Build calico-upgrade
binary: $(CALICO_UPGRADE_FILES) vendor
	# Don't try to "install" the intermediate build files (.a .o) when not on linux
	# since there are no write permissions for them in our linux build container.
	if [ "$(BUILDOS)" == "linux" ]; then \
		INSTALL_FLAG=" -i "; \
	fi; \
	GOOS=$(BUILDOS) GOARCH=$(ARCH) CGO_ENABLED=0 go build -v $$INSTALL_FLAG -o dist/calico-upgrade-$(OS)-$(ARCH) $(LDFLAGS) "./pkg/calicoupgrade.go"

.PHONY: install
install:
	CGO_ENABLED=0 go install $(PACKAGE_NAME)/calico_upgrade

###############################################################################
# calico-upgrade UTs
###############################################################################
.PHONY: ut
## Run the Unit Tests locally
ut: bin/calico-upgrade
	# Run tests in random order find tests recursively (-r).
	ginkgo -cover -r --skipPackage vendor pkg/*

	@echo
	@echo '+==============+'
	@echo '| All coverage |'
	@echo '+==============+'
	@echo
	@find ./pkg/ -iname '*.coverprofile' | xargs -I _ go tool cover -func=_

	@echo
	@echo '+==================+'
	@echo '| Missing coverage |'
	@echo '+==================+'
	@echo
	@find ./pkg/ -iname '*.coverprofile' | xargs -I _ go tool cover -func=_ | grep -v '100.0%'

PHONY: test-containerized
## Run the tests in a container. Useful for CI, Mac dev.
test-containerized: bin/calico-upgrade
	docker run --rm -v $(CURDIR):/go/src/$(PACKAGE_NAME):rw \
    -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
    $(CALICO_BUILD) sh -c 'cd /go/src/$(PACKAGE_NAME) && make ut'

## Perform static checks on the code. The golint checks are allowed to fail, the others must pass.
.PHONY: static-checks
static-checks: vendor
	# vet and errcheck are disabled since they find problems...
	docker run --rm \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-v $(CURDIR):/go/src/$(PACKAGE_NAME) \
		$(CALICO_BUILD) sh -c '\
			cd /go/src/$(PACKAGE_NAME) && \
			gometalinter --deadline=300s --disable-all --enable=goimports --vendor ./...'


SOURCE_DIR?=$(dir $(lastword $(MAKEFILE_LIST)))
SOURCE_DIR:=$(abspath $(SOURCE_DIR))
LOCAL_IP_ENV?=$(shell ip route get 8.8.8.8 | head -1 | awk '{print $$7}')
ST_TO_RUN?=tests/st/calico_upgrade/test_calico_upgrade.py
# Can exclude the slower tests with "-a '!slow'"
ST_OPTIONS?=

## Run the STs in a container
.PHONY: st
st: bin/calico-upgrade dist/calicoctl dist/calicoctlv2 run-etcd
	# Use the host, PID and network namespaces from the host.
	# Privileged is needed since 'calico node' write to /proc (to enable ip_forwarding)
	# Map the docker socket in so docker can be used from inside the container
	# All of code under test is mounted into the container.
	#   - This also provides access to calico-upgrade and the docker client
	docker run --net=host --privileged \
	           --uts=host \
	           --pid=host \
	           -e MY_IP=$(LOCAL_IP_ENV) \
	           --rm -ti \
                   -v /var/run/docker.sock:/var/run/docker.sock \
	           -v $(SOURCE_DIR):/code \
	           calico/test \
	           sh -c 'nosetests $(ST_TO_RUN) -sv --nologcapture  --with-xunit --xunit-file="/code/nosetests.xml" --with-timer $(ST_OPTIONS)'

	$(MAKE) stop-etcd

## Run etcd and a container for testing the upgrade binaries.  The dist directory will
## contain calico-upgrade and a v2.x and current v3.x versions of calicoctl.
.PHONY: testenv
testenv: bin/calico-upgrade dist/calicoctl dist/calicoctlv2 run-etcd
	-docker run --net=host --privileged \
	           --uts=host \
	           --pid=host \
	           --rm -ti \
	           -v $(SOURCE_DIR):/code \
                   -v /var/run/docker.sock:/var/run/docker.sock \
	           --name=testenv \
	           calico/test \
	           sh

dist/calicoctl:
	-mkdir -p dist
	-docker rm -f calicoctl
	docker pull $(CTL_CONTAINER_NAME)
	docker create --name calicoctl $(CTL_CONTAINER_NAME)
	docker cp calicoctl:calicoctl dist/calicoctl && \
	  test -e dist/calicoctl && \
	  touch dist/calicoctl
	-docker rm -f calicoctl

dist/calicoctlv2:
	-mkdir -p dist
	-docker rm -f calicoctlv2
	docker pull $(CTL_CONTAINER_V2_NAME)
	docker create --name calicoctlv2 $(CTL_CONTAINER_V2_NAME)
	docker cp calicoctlv2:calicoctl dist/calicoctlv2 && \
	  test -e dist/calicoctlv2 && \
	  touch dist/calicoctlv2
	-docker rm -f calicoctlv2

## Run etcd as a container (calico-etcd)
run-etcd: stop-etcd
	docker run --detach \
	--net=host \
	--entrypoint=/usr/local/bin/etcd \
	--name calico-etcd quay.io/coreos/etcd:$(ETCD_VER) \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:2379,http://$(LOCAL_IP_ENV):4001,http://127.0.0.1:4001" \
	--listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001"


.PHONY: stop-etcd
stop-etcd:
	@-docker rm -f calico-etcd

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
## Run what CI runs
ci: clean static-checks build-all image st

## Deploys images to registry
cd:
ifndef CONFIRM
	$(error CONFIRM is undefined - run using make <target> CONFIRM=true)
endif
ifndef BRANCH_NAME
	$(error BRANCH_NAME is undefined - run using make <target> BRANCH_NAME=var or set an environment variable)
endif
	$(MAKE) tag-images push IMAGETAG=${BRANCH_NAME}
	$(MAKE) tag-images push IMAGETAG=$(shell git describe --tags --dirty --always --long)

# This depends on clean to ensure that dependent images get untagged and repulled
.PHONY: semaphore
semaphore: ci

release: clean
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif
	git tag $(VERSION)

	# Check to make sure the tag isn't "-dirty".
	if git describe --tags --dirty | grep dirty; \
	then echo current git working tree is "dirty". Make sure you do not have any uncommitted changes ;false; fi

	# Build the calico-upgrade binaries.
	$(MAKE) build-all
	$(MAKE) image

	# Check that the version output includes the version specified.
	# Tests that the "git tag" makes it into the binaries. Main point is to catch "-dirty" builds
	# Release is currently supported on darwin / linux only.
	if ! docker run $(CONTAINER_NAME) version | grep 'Version:\s*$(VERSION)$$'; then \
	  echo "Reported version:" `docker run $(CONTAINER_NAME) version` "\nExpected version: $(VERSION)"; \
	  false; \
	else \
	  echo "Version check passed\n"; \
	fi

	# Retag images with corect version and quay
	docker tag $(CONTAINER_NAME) $(CONTAINER_NAME):$(VERSION)
	docker tag $(CONTAINER_NAME) quay.io/$(CONTAINER_NAME):$(VERSION)
	docker tag $(CONTAINER_NAME) quay.io/$(CONTAINER_NAME):latest

	# Check that images were created recently and that the IDs of the versioned and latest images match
	@docker images --format "{{.CreatedAt}}\tID:{{.ID}}\t{{.Repository}}:{{.Tag}}" $(CONTAINER_NAME)
	@docker images --format "{{.CreatedAt}}\tID:{{.ID}}\t{{.Repository}}:{{.Tag}}" $(CONTAINER_NAME):$(VERSION)

	@echo ""
	@echo "# Push the created tag to GitHub"
	@echo "  git push origin $(VERSION)"
	@echo ""
	@echo "# Now, create a GitHub release from the tag, add release notes, and attach the following binaries:"
	@echo "- dist/calico-upgrade"
	@echo "- dist/calico-upgrade-darwin-amd64"
	@echo "- dist/calico-upgrade-windows-amd64.exe"
	@echo "# To find commit messages for the release notes:  git log --oneline <old_release_version>...$(VERSION)"
	@echo ""
	@echo "# Now push the newly created release images."
	@echo "  docker push calico/upgrade:$(VERSION)"
	@echo "  docker push quay.io/calico/upgrade:$(VERSION)"
	@echo ""
	@echo "# For the final release only, push the latest tag"
	@echo "# DO NOT PUSH THESE IMAGES FOR RELEASE CANDIDATES OR ALPHA RELEASES" 
	@echo "  docker push calico/upgrade:latest"
	@echo "  docker push quay.io/calico/upgrade:latest"
	@echo ""
	@echo "See RELEASING.md for detailed instructions."

## Clean enough that a new release build will be clean
clean: clean-calico-upgrade
	find . -name '*.created' -exec rm -f {} +
	rm -rf dist build certs *.tar vendor

.PHONY: help
###############################################################################
# Developer helper scripts (not used by build or test)
###############################################################################
help:
	@echo "calico-upgrade Makefile"
	@echo
	@echo "Dependencies: docker 1.12+; go 1.8+"
	@echo
	@echo "For any target, set ARCH=<target> to build for a given target."
	@echo "For example, to build for arm64:"
	@echo
	@echo "  make build ARCH=arm64"
	@echo
	@echo "Initial set-up:"
	@echo
	@echo "  make vendor          Update/install the go build dependencies."
	@echo
	@echo "Builds:"
	@echo
	@echo "  make build           Build the binary."
	@echo "  make image           Build $(CONTAINER_NAME) docker image."
	@echo
	@echo "Tests:"
	@echo
	@echo "  make test            Run all tests."
	@echo
	@echo "Maintenance:"
	@echo "  make clean           Remove binary files and docker images."
	@echo "-----------------------------------------"
	@echo "ARCH (target):          $(ARCH)"
	@echo "BUILDARCH (host):       $(BUILDARCH)"
	@echo "CALICO_BUILD:     $(CALICO_BUILD)"
	@echo "-----------------------------------------"
