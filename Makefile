# https://www.xiexianbin.cn/program/tools/2016-01-09-makefile/index.html
.PHONY: all test clean build build-linux build-mac build-windows

GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
BINARY_NAME=xca
BINARY_LINUX=$(BINARY_NAME)-linux
BINARY_MAC=$(BINARY_NAME)-darwin
BINARY_WIN=$(BINARY_NAME)-windows

help:  ## Show this help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {sub("\\\\n",sprintf("\n%22c"," "), $$2);printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

all: clean test build build-linux build-mac build-windows  ## Build all
test:  ## run test
	$(GOTEST) -v ./...
clean: ## run clean bin files
	$(GOCLEAN)
	rm -f bin/$(BINARY_NAME)
build:  ## build for current os
	$(GOBUILD) -o bin/$(BINARY_NAME) -v

build-linux:  ## build linux amd64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -o bin/$(BINARY_LINUX) -v
build-mac:  ## build mac amd64
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GOBUILD) -o bin/$(BINARY_MAC) -v
build-windows:  ## build windows amd64
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOBUILD) -o bin/$(BINARY_WIN) -v
