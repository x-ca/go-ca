# go-ca

[![build](https://github.com/x-ca/go-ca/actions/workflows/workflow.yaml/badge.svg)](https://github.com/x-ca/go-ca/actions/workflows/workflow.yaml)
[![GoDoc](https://godoc.org/github.com/x-ca/go-ca?status.svg)](https://pkg.go.dev/github.com/x-ca/go-ca)
[![Go Report Card](https://goreportcard.com/badge/github.com/x-ca/go-ca)](https://goreportcard.com/report/github.com/x-ca/go-ca)

golang x-ca client, which can simple Sign Self Root/Second-Level CA, and sign for Domains and IPs.

- shell implement at [x-ca/x-ca](https://github.com/x-ca/x-ca)
- [import Self Sign CA To System](https://www.xiexianbin.cn/http/ssl/2017-02-15-openssl-self-sign-ca/#导出导入自签名证书) `x-ca/ca/root-ca.crt` and `x-ca/ca/tls-ca.crt` to trust Your CA.

## install

- binary

```
curl -Lfs -o xca https://github.com/x-ca/go-ca/releases/latest/download/xca-{linux|darwin|windows}-{amd64|arm64|s390x|ppc64le}-{amd64|arm64}
chmod +x xca
mv xca /usr/local/bin/
```

- source

```
go install go.xiexianbin.cn/xca/cmd@latest
```

## Help

```
xca --help
xca create-ca --help
xca sign --help
```

```
$ xca --help
XCA is a command-line tool for creating and managing Root/Second-Level Certificate Authorities (CAs)
and signing certificates for domains and IP addresses.

Available Commands:
  create-ca   Create root and TLS CA certificates
  info        Display information about Certificates
  sign        Sign a certificate for domains and/or IPs
  version     Show version information

Environment:
  XCA_ROOT_PATH  Which path to store Root/Second-Level/TLS cert, default is "$(pwd)/x-ca"

Examples:
  xca create-ca --key-type ec --curve P256
  xca sign example.com --domains "example.com,www.example.com"
  xca sign 192.168.1.1 --ips "192.168.1.1"

Source Code:
  https://github.com/x-ca/go-ca
```

## Usage Demo

You can specify the key type (`-key-type`) and curve (`-curve`) to create an EC root CA and TLS CA:

```
# Create EC CA
$ xca create-ca --key-type ec --curve P256

# default out `x-ca/...`
$ tree x-ca
x-ca
└── ca
    ├── root-ca
    │   └── private
    │       └── root-ca.key
    ├── root-ca.crt
    ├── tls-ca
    │   └── private
    │       └── tls-ca.key
    ├── tls-ca-chain.pem
    └── tls-ca.crt

6 directories, 5 files

# Show CA info
$ xca info ./x-ca/ca/root-ca.crt
$ xca info ./x-ca/ca/tls-ca.crt

# Sign Domains certificate
xca sign example.com --domains "example.com,www.example.com"

# Sign Domains and IPs certificate
$ xca sign xiexianbin.cn --ips "192.168.1.1,*.xiexianbin.cn,*.dev.xiexianbin.cn"

# Show TLS cert info
$ xca info ./x-ca/certs/xiexianbin.cn/xiexianbin.cn.crt
```

- test cert

```
docker run -it -d \
  -p 8443:443 \
  -v $(pwd)/examples/default.conf:/etc/nginx/conf.d/default.conf \
  -v $(pwd)/x-ca/certs/xiexianbin.cn/xiexianbin.cn.bundle.crt:/etc/pki/nginx/server.crt \
  -v $(pwd)/x-ca/certs/xiexianbin.cn/xiexianbin.cn.key:/etc/pki/nginx/private/server.key \
  nginx
```

- to verify, visit https://dev.xiexianbin.cn:8443/ in brower or run command:

```
curl -i -v -k https://dev.xiexianbin.cn:8443/ --resolve dev.xiexianbin.cn:8443:127.0.0.1
```

## Dev

- core file

```
go.mod - Added cobra dependency
ca/baseca.go - Common CA functionality
ca/common.go - Shared utilities
cmd/create.go - create-ca command
cmd/sign.go - sign command
cmd/root.go - root cobra command
cmd/xca.go - main entry point (refactored)
```

## FaQ

if CA Cert begin with `BEGIN ENCRYPTED PRIVATE KEY`(raise `Error: fromPEMBytes: x509: no DEK-Info header in block`),
Use `openssl rsa -in root-ca.key -des3` change cipher

## Ref

- [基于OpenSSL签署根CA、二级CA](https://www.xiexianbin.cn/s/ca/)
