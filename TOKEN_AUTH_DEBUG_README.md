#  Debugging jwt token issues


This branch is for trying to figure out what is broken about JWT auth.



It's been modified to stuff a bunch of printlns into some of the vendored registry auth code, as well as the location where notary calls the registry auth code (`utils/http.go` L64 or so).

I've also updated the server config to point to include an auth config - you will have to modify it to point to whatever JWT token service you want, but you should put the signing public key used to validate signed JWT tokens in the top level of this repo, named `jwttokencert.pem`.

After that, just `docker-compose up --build`.


Once it's running, do the following:

1.  Edit your `/etc/hosts` file so that `notary-server` is mapped to whatever IP your docker host is
1.  `export DOCKER_CONTENT_TRUST=1; export DOCKER_CONTENT_TRUST_SERVER=https://notary-server:4443`
1.  `docker pull <whatever>` - a docker pull will first try to contact notary before contacting the registry, so it should hit the notary auth.


To add more debug code:
1. `docker-compose down`
1. `docker-compose up --build`
