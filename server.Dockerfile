FROM golang:1.7.3-alpine AS build-env

RUN apk add --update git gcc libc-dev

# Install SQL DB migration tool
RUN go get github.com/mattes/migrate

ENV NOTARYPKG github.com/docker/notary

# Copy the local repo to the expected go path
COPY . /go/src/${NOTARYPKG}

WORKDIR /go/src/${NOTARYPKG}

# Build notary-server
RUN go install \
    -tags pkcs11 \
    -ldflags "-w -X ${NOTARYPKG}/version.GitCommit=`git rev-parse --short HEAD` -X ${NOTARYPKG}/version.NotaryVersion=`cat NOTARY_VERSION`" \
    ${NOTARYPKG}/cmd/notary-server


FROM busybox:latest
MAINTAINER David Lawrence "david.lawrence@docker.com"

# the ln is for compatibility with the docker-compose.yml, making these
# images a straight swap for the those built in the compose file.
RUN mkdir -p /usr/bin /var/lib && ln -s /bin/env /usr/bin/env

COPY --from=build-env /lib/ld-musl-x86_64.so.1 /lib/ld-musl-x86_64.so.1
COPY --from=build-env /go/bin/notary-server /usr/bin/notary-server
COPY --from=build-env /go/bin/migrate /usr/bin/migrate
COPY --from=build-env /go/src/github.com/docker/notary/migrations/ /var/lib/notary/migrations

WORKDIR /var/lib/notary
ENV SERVICE_NAME=notary_server
EXPOSE 4443

ENTRYPOINT [ "/usr/bin/notary-server" ]
