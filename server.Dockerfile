FROM golang:1.7.3-alpine AS build-env
RUN apk add --update git gcc libc-dev
RUN go get github.com/mattes/migrate
ENV NOTARYPKG github.com/docker/notary
COPY . /go/src/${NOTARYPKG}
WORKDIR /go/src/${NOTARYPKG}
RUN go install \
    -tags pkcs11 \
    -ldflags "-w -X ${NOTARYPKG}/version.GitCommit=`git rev-parse --short HEAD` -X ${NOTARYPKG}/version.NotaryVersion=`cat NOTARY_VERSION`" \
    ${NOTARYPKG}/cmd/notary-server


FROM alpine:latest
MAINTAINER David Lawrence "david.lawrence@docker.com"

COPY --from=build-env /go/bin/notary-server /usr/bin/notary-server
COPY --from=build-env /go/bin/migrate /usr/bin/migrate
COPY --from=build-env /go/src/github.com/docker/notary/migrations/ /var/lib/notary/migrations

WORKDIR /var/lib/notary
ENV SERVICE_NAME=notary_server
EXPOSE 4443
ENTRYPOINT [ "/usr/bin/notary-server" ]
