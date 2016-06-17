FROM golang:1.6.3-alpine
MAINTAINER David Lawrence "david.lawrence@docker.com"

RUN apk add --update git gcc libc-dev openssl ca-certificates && rm -rf /var/cache/apk/*

# Install SQL DB migration tool
RUN go get github.com/mattes/migrate

ENV NOTARYPKG github.com/docker/notary

# Copy the local repo to the expected go path
COPY . /go/src/${NOTARYPKG}

WORKDIR /go/src/${NOTARYPKG}

ENV SERVICE_NAME=notary_server
EXPOSE 4443

# Install notary-server
RUN go install \
    -tags pkcs11 \
    -ldflags "-w -X ${NOTARYPKG}/version.GitCommit=`git rev-parse --short HEAD` -X ${NOTARYPKG}/version.NotaryVersion=`cat NOTARY_VERSION`" \
    ${NOTARYPKG}/cmd/notary-server && apk del git gcc libc-dev

# ensure that the docker cert is trusted
RUN mkdir -p /usr/local/share/ca-certificates && openssl s_client -host auth.docker.io -port 443 </dev/null 2>/dev/null | openssl x509 -CAform PEM > /usr/local/share/ca-certificates/ca.crt && update-ca-certificates
ENTRYPOINT [ "notary-server" ]
CMD [ "-config=fixtures/server-config-local.json" ]
