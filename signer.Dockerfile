FROM golang:1.7.3-alpine AS build-env

RUN apk add --update git gcc libc-dev

# Install SQL DB migration tool
RUN go get github.com/mattes/migrate

ENV NOTARYPKG github.com/docker/notary

# Copy the local repo to the expected go path
COPY . /go/src/${NOTARYPKG}

WORKDIR /go/src/${NOTARYPKG}

# Build notary-signer
RUN go install \
    -tags pkcs11 \
    -ldflags "-w -X ${NOTARYPKG}/version.GitCommit=`git rev-parse --short HEAD` -X ${NOTARYPKG}/version.NotaryVersion=`cat NOTARY_VERSION`" \
    ${NOTARYPKG}/cmd/notary-signer


FROM alpine:latest
MAINTAINER David Lawrence "david.lawrence@docker.com"

COPY --from=build-env /go/bin/notary-signer /usr/bin/notary-signer
COPY --from=build-env /go/bin/migrate /usr/bin/migrate
COPY --from=build-env /go/src/github.com/docker/notary/migrations/ /var/lib/notary/migrations

WORKDIR /var/lib/notary
ENV SERVICE_NAME=notary_signer
ENV NOTARY_SIGNER_DEFAULT_ALIAS="timestamp_1"
ENV NOTARY_SIGNER_TIMESTAMP_1="testpassword"

ENTRYPOINT [ "/usr/bin/notary-signer" ]
