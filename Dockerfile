FROM golang:1.6.1

RUN apt-get update && apt-get install -y \
	curl \
	clang \
	libltdl-dev \
	libsqlite3-dev \
	patch \
	tar \
	xz-utils \
	--no-install-recommends \
	&& rm -rf /var/lib/apt/lists/* \
	&& useradd -ms /bin/bash notary

RUN go get golang.org/x/tools/cmd/cover

ENV NOTARYDIR /go/src/github.com/docker/notary

COPY . ${NOTARYDIR}
RUN chmod -R a+rw /go

USER notary

WORKDIR ${NOTARYDIR}

# Note this cannot use alpine because of the MacOSX Cross SDK: the cctools there uses sys/cdefs.h and that cannot be used in alpine: http://wiki.musl-libc.org/wiki/FAQ#Q:_I.27m_trying_to_compile_something_against_musl_and_I_get_error_messages_about_sys.2Fcdefs.h
