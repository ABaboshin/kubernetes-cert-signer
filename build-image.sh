#!/bin/bash

VERSION=20210330

docker build -t ababoshin/kubernetes-cert-signer:$VERSION .
docker push ababoshin/kubernetes-cert-signer:$VERSION
