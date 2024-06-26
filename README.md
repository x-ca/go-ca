# go-ca

[![build](https://github.com/x-ca/go-ca/actions/workflows/workflow.yaml/badge.svg)](https://github.com/x-ca/go-ca/actions/workflows/workflow.yaml)
[![GoDoc](https://godoc.org/github.com/x-ca/go-ca?status.svg)](https://pkg.go.dev/github.com/x-ca/go-ca)
[![Go Report Card](https://goreportcard.com/badge/github.com/x-ca/go-ca)](https://goreportcard.com/report/github.com/x-ca/go-ca)

golang x-ca client, which can simple Sign Self Root/Second-Level CA, and sign for Domains and IPs.

shell implement at [x-ca/x-ca](https://github.com/x-ca/x-ca)

## install

```
curl -Lfs -o xca https://github.com/x-ca/go-ca/releases/latest/download/xca-{linux|darwin|windows}-{amd64|arm64|s390x|ppc64le}
chmod +x xca
mv xca /usr/local/bin/
```

## Help

```
$ xca --help
Create Root CA and TLS CA:
xca -create-ca true \
  -root-cert x-ca/ca/root-ca.crt \
  -root-key x-ca/ca/root-ca/private/root-ca.key \
  -tls-cert x-ca/ca/tls-ca.crt \
  -tls-key x-ca/ca/tls-ca/private/tls-ca.key \
  -tls-chain x-ca/ca/tls-ca-chain.pem

Sign Domains or Ips:
xca -cn xxxx \
  --domains "xxx,xxx" --ips "xxx,xxx" \
  -tls-cert x-ca/ca/tls-ca.crt \
  -tls-key x-ca/ca/tls-ca/private/tls-ca.key \
  -tls-chain x-ca/ca/tls-ca-chain.pem

Usage:
  -cn string
    	sign cert common name.
  -create-ca
    	Create Root CA.
  -domains string
    	Comma-Separated domain names.
  -help
    	show help message
  -ips string
    	Comma-Separated IP addresses.
  -root-cert string
    	Root certificate file path, PEM format. (default "x-ca/ca/root-ca.crt")
  -root-key string
    	Root private key file path, PEM format. (default "x-ca/ca/root-ca/private/root-ca.key")
  -tls-cert string
    	Second-Level certificate file path, PEM format. (default "x-ca/ca/tls-ca.crt")
  -tls-chain string
    	Root/Second-Level CA Chain file path, PEM format. (default "x-ca/ca/tls-ca-chain.pem")
  -tls-key string
    	Second-Level private key file path, PEM format. (default "x-ca/ca/tls-ca/private/tls-ca.key")
  -tls-key-password string
    	tls key password, only work for load github.com/x-ca/x-ca.
  -version
    	show version info.

Source Code:
  https://github.com/x-ca/go-ca
```

## Usage Demo

- create ca

```
xca -create-ca true \
  -root-cert x-ca/ca/root-ca.crt \
  -root-key x-ca/ca/root-ca/private/root-ca.key \
  -tls-cert x-ca/ca/tls-ca.crt \
  -tls-key x-ca/ca/tls-ca/private/tls-ca.key
```

[install](https://www.xiexianbin.cn/http/ssl/2017-02-15-openssl-self-sign-ca/#导出导入自签名证书) `x-ca/ca/root-ca.crt` and `x-ca/ca/tls-ca.crt` to trust Your CA.

- or use x-ca

```
mkdir path
git clone git@github.com:x-ca/ca.git x-ca
```

- sign domain

```
xca -cn xiexianbin.cn \
  --domains "*.xiexianbin.cn,*.80.xyz" \
  --ips 100.80.0.128 \
  -tls-cert x-ca/ca/tls-ca.crt \
  -tls-key x-ca/ca/tls-ca/private/[tls-ca.key | tls-ca-des3.key]
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

visit https://dev.xiexianbin.cn:8443/

## FaQ

if CA Cert begin with `BEGIN ENCRYPTED PRIVATE KEY`(raise `Error: fromPEMBytes: x509: no DEK-Info header in block`),
Use `openssl rsa -in root-ca.key -des3` change cipher

## Ref

- [基于OpenSSL签署根CA、二级CA](https://www.xiexianbin.cn/s/ca/)
