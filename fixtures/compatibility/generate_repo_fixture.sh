#!/usr/bin/env bash

# expects a single argument: the version
# this sets environment variables for the passphrases, so should be run in a subshell
function setup_repo() {
	repodir="/tmp/notary${1}"
	gun="docker.com/notary${1}/samplerepo"
	notary_cmd="bin/notary -c cmd/notary/config.json -d ${repodir}"

	rm -rf repodir

	export NOTARY_ROOT_PASSPHRASE="randompass"
	export NOTARY_TARGETS_PASSPHRASE="randompass"
	export NOTARY_SNAPSHOT_PASSPHRASE="randompass"

	${notary_cmd} init "${gun}"

	# all versions should be able to add a target
	${notary_cmd} add "${gun}" LICENSE LICENSE

	# publish
	${notary_cmd} publish "${gun}"

	# download to get the timestamp
	echo "\$ ${notary_cmd} list ${gun}" > "${repodir}/README.txt"
	${notary_cmd} list "${gun}" >> "${repodir}/README.txt"

	# produce more changelists, this time unpublished
	${notary_cmd} add "${gun}" .gitignore .gitignore
	echo >> "${repodir}/README.txt"
	echo >> "${repodir}/README.txt"
	echo "\$ ${notary_cmd} status ${gun}" >> "${repodir}/README.txt"


	${notary_cmd} status "${gun}" >> "${repodir}/README.txt"


	# remove what's there
	rm -rf "fixtures/compatibility/notary${1}"
	mv "${repodir}" fixtures/compatibility/
}

# expects a single argument: the version
function checkout_version() {
	# where were we?
	prev=$(git symbolic-ref HEAD)
	stashed=0
	if [[ "${?}" > 0 ]]; then
		prev=$(git show HEAD --pretty=format:%H)
	fi
	if [[ -z $(git status -s) ]]; then
		git stash
		stashed=1
	fi

	git co "${1}"

	# patch the default expiry times to be 100 years

}

_CWD="$(pwd)"

# directory of this file
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do # resolve $SOURCE until the file is no longer a symlink
  DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE" # if $SOURCE was a relative symlink, we need to resolve it relative to the path where the symlink file was located
done

# go to the root notary directory no matter where this script is run from
cd $(dirname $(dirname $(dirname $SOURCE)))

# set up the repo in subshell so the environment variables aren't persisted
echo "$(setup_repo "${1}")"

# return
cd "${_CWD}"
