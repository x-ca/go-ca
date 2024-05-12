# https://www.xiexianbin.cn/program/tools/2016-01-09-makefile/index.html
export SHELL:=bash
export SHELLOPTS:=$(if $(SHELLOPTS),$(SHELLOPTS):)pipefail:errexit

# https://stackoverflow.com/questions/4122831/disable-make-builtin-rules-and-variables-from-inside-the-make-file
MAKEFLAGS += --no-builtin-rules
.SUFFIXES:

VERSION        := latest
BUILD_DATE     := $(shell TZ=UTC-8 date +'%Y-%m-%dT%H:%M:%SZ+08:00')
GIT_COMMIT     := $(shell git rev-parse HEAD || echo unknown)
GIT_BRANCH     := $(shell git rev-parse --symbolic-full-name --verify --quiet --abbrev-ref HEAD)
GIT_TAG        := $(shell git describe --exact-match --tags --abbrev=0  2> /dev/null || echo untagged)
GIT_TREE_STATE := $(shell if [ -z "`git status --porcelain`" ]; then echo "clean" ; else echo "dirty"; fi)
RELEASE_TAG    := $(shell if [[ "$(GIT_TAG)" =~ ^v[0-9]+\.[0-9]+\.[0-9]+.*$$ ]]; then echo "true"; else echo "false"; fi)
DEV_BRANCH            := $(shell [ "$(GIT_BRANCH)" = master ] || [ `echo $(GIT_BRANCH) | cut -c -8` = release- ] || [ `echo $(GIT_BRANCH) | cut -c -4` = dev- ] || [ $(RELEASE_TAG) = true ] && echo false || echo true)

GOCMD   ?= go
GOBUILD ?= $(GOCMD) build -v
GOCLEAN ?= $(GOCMD) clean
GOTEST  ?= $(GOCMD) test -v -p 20

linux-amd64: GOARGS = GOOS=linux GOARCH=amd64
linux-arm64: GOARGS = GOOS=linux GOARCH=arm64
linux-ppc64le: GOARGS = GOOS=linux GOARCH=ppc64le
linux-s390x: GOARGS = GOOS=linux GOARCH=s390x
darwin-amd64: GOARGS = GOOS=darwin GOARCH=amd64
darwin-arm64: GOARGS = GOOS=darwin GOARCH=arm64
windows-amd64: GOARGS = GOOS=windows GOARCH=amd64

BINARY_NAME  ?= main
IMG          ?= xiexianbin/go-actions-demo:latest

ifeq ($(RELEASE_TAG),true)
VERSION        := $(GIT_TAG)
endif

# $(info GIT_COMMIT=$(GIT_COMMIT) GIT_BRANCH=$(GIT_BRANCH) GIT_TAG=$(GIT_TAG) GIT_TREE_STATE=$(GIT_TREE_STATE) RELEASE_TAG=$(RELEASE_TAG) DEV_BRANCH=$(DEV_BRANCH) VERSION=$(VERSION))
# $(info MAKEFILE_LIST=${MAKEFILE_LIST})

# -X github.com/xiexianbin/go-actions-demo.version=$(VERSION)
override LDFLAGS += \
  -X main.version=$(VERSION) \
  -X main.buildDate=$(BUILD_DATE) \
	-X main.gitCommit=$(GIT_COMMIT) \
  -X main.gitTreeState=$(GIT_TREE_STATE)

ifneq ($(GIT_TAG),)
override LDFLAGS += -X main.gitTag=${GIT_TAG}
endif

SUB_BUILD_CMD ?= $(GOBUILD)  -gcflags '${GCFLAGS}' -ldflags '${LDFLAGS}  -extldflags -static'

.PHONY: help
help:  ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {sub("\\\\n",sprintf("\n%22c"," "), $$2);printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: all
all: clean test build linux-amd64 linux-arm64 linux-ppc64le linux-s390x darwin-amd64 darwin-arm64 windows-amd64  ## Build all

.PHONY: test
test:  ## Run test
	$(GOTEST) -v ./...

.PHONY: clean
clean: ## Run clean bin files
	$(GOCLEAN)
	rm -f bin/*

.PHONY: build
build:  ## Build for current os
	${SUB_BUILD_CMD} -o bin/$(BINARY_NAME)

.PHONY: linux-amd64
linux-amd64:  ## Build linux amd64
	CGO_ENABLED=0 ${GOARGS} ${SUB_BUILD_CMD} -o bin/${BINARY_NAME}-$@

.PHONY: linux-arm64
linux-arm64:  ## Build linux arm64
	CGO_ENABLED=0 ${GOARGS} ${SUB_BUILD_CMD} -o bin/${BINARY_NAME}-$@

.PHONY: linux-ppc64le
linux-ppc64le:  ## Build linux ppc64le
	CGO_ENABLED=0 ${GOARGS} ${SUB_BUILD_CMD} -o bin/${BINARY_NAME}-$@

.PHONY: linux-s390x
linux-s390x:  ## Build linux s390x
	CGO_ENABLED=0 ${GOARGS} ${SUB_BUILD_CMD} -o bin/${BINARY_NAME}-$@

.PHONY: darwin-amd64
darwin-amd64:  ## Build darwin amd64
	CGO_ENABLED=0 ${GOARGS} ${SUB_BUILD_CMD} -o bin/${BINARY_NAME}-$@

.PHONY: darwin-arm64
darwin-arm64:  ## Build darwin arm64
	CGO_ENABLED=0 ${GOARGS} ${SUB_BUILD_CMD} -o bin/${BINARY_NAME}-$@

.PHONY: windows-amd64
windows-amd64:  ## Build windows amd64
	CGO_ENABLED=0 ${GOARGS} ${SUB_BUILD_CMD} -o bin/${BINARY_NAME}-$@.exe

.PHONY: docker-build
docker-build: test  ## Build docker image
	docker build -t ${IMG} .

.PHONY: docker-push
docker-push:  ## Push docker image
	docker push ${IMG}
