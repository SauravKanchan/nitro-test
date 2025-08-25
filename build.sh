#!/usr/bin/env bash
set -euxo pipefail
APP_NAME=sealed-hasher
IMG_TAG=$APP_NAME:latest
EIF=$APP_NAME.eif

docker build -t $IMG_TAG .
nitro-cli build-enclave --docker-uri $IMG_TAG --output-file $EIF
ls -lh $EIF
