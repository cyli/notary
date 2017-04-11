#!/bin/sh

docker secret create server-config.json fixtures/server-config.json
docker secret create signer-config.json fixtures/signer-config.json
docker secret create root-ca.crt fixtures/root-ca.crt
docker secret create notary-server.crt fixtures/notary-server.crt
docker secret create notary-server.key fixtures/notary-server.key
docker secret create notary-signer.crt fixtures/notary-signer.crt
docker secret create notary-signer.key fixtures/notary-signer.key