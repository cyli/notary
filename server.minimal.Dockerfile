FROM alpine:latest
MAINTAINER David Lawrence "david.lawrence@docker.com"

COPY ./bin/notary-server /usr/bin/notary-server
COPY ./bin/migrate /usr/bin/migrate
COPY ./fixtures /var/lib/notary/fixtures
COPY ./migrations /var/lib/notary/migrations

WORKDIR /var/lib/notary
ENV SERVICE_NAME=notary_server
EXPOSE 4443

ENTRYPOINT [ "/usr/bin/notary-server" ]
CMD [ "-config=/var/lib/notary/fixtures/server-config-local.json" ]
