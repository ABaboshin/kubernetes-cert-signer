#!/bin/bash

VERSION=20210401

docker build -t ababoshin/kubernetes-cert-signer:$VERSION .
docker push ababoshin/kubernetes-cert-signer:$VERSION
