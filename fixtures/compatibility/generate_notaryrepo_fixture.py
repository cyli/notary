"""
Generates the complete notary repository information for a particular version
of notary, and saves it as a fixture.  This includes metadata and keys.

Note: this is a python script because the multiline regex became too
comlicated to easily do/understand using sed
"""

from __future__ import print_function
import inspect
import os
import re
import shutil
import subprocess
import tempfile

def this_script_location():
    """
    Returns the absolute path to directory where this script lives, so that
    we don't depend on the CWD for looking for things.
    """
    script_filename = inspect.getfile(inspect.currentframe())
    return os.path.dirname(os.path.abspath(script_filename))


def setup_repo(notary_version, generate_published_repo, generate_changelists, get_info):
    """
    Runs all the commands necessary to generate the repo for one version
    """
    reponame = "notary%{0}".format(notary_version)
    tempdir = tempfile.mkdtemp()
    gun = "docker.com/%{0}/samplerepo".format(reponame)
    notary_cmd = "bin/notary -c cmd/notary/config.json -d " + tempdir

    print("creating repo in", tempdir)

    env = os.environ().copy()
    for role in ("ROOT", "TARGETS", "SNAPSHOT"):
        env["NOTARY_%{0}_PASSPHRASE".format(role)] = "randompass"

    subprocess.check_call(notary_cmd.split() + ["init", gun], env=env)

    generate_published_repo()

    # publish
    subprocess.check_call(notary_cmd.split() + ["publish", gun], env=env)

    # download to get the timestamp
    subprocess.check_call(notary_cmd.split() + ["list", gun], env=env)

    generate_changelists()

    with open(os.path.join(tempdir, "README.txt"), 'wb') as readme:
        get_info(readme)

    # remove the existing fixture
    final_loc = os.path.join(this_script_location(), reponame)
    shutil.rmtree(final_loc)
    os.rename(tempdir, final_loc)


def setup_git(git_tag):
    """
    Saves the existing HEAD in git, and any outstanding work.  Then checks out
    the version that we want.  It also patches the code so cert and signature
    expiries are 100 years from now.

    This returns a restore function that will reset git to where we were.
    """
    try:
        prev = subprocess.check_output("git symbolic-ref HEAD".split())
    except subprocess.CalledProcessError:
        prev = subprocess.check_output("git show HEAD --pretty=format:%H".split())

    stashed = False
    # stash our work if there is anything missing
    if subprocess.check_output("git status -s".split()):
        subprocess.check_call("git stash --all".split())
        stashed = True

    # now check out the right version
    subprocess.check_call("git checkout".split() + [git_tag])

    # find all non-test files and patch them to have a 100 year expiry
    notary_root = os.path.dirname( # notary-root
        os.path.dirname( # fixtures
            this_script_location())) # compatibility)
    for root, _, files in os.walk(notary_root):
        if os.path.basename(root) in ("docs", "fixtures"):
            continue

        for fname in files:
            if fname.endswith(".go") and not fname.endswith("_test.go"):
                patch_expiry(os.path.join(root, fname))

    def restore():
        """
        Restores the previous git repo changes and HEAD
        """
        subprocess.check_call("git co -- .")
        subprocess.check_call("git clean -fd")
        subprocess.check_call("git checkout".split() + [prev])
        if stashed:
            subprocess.check_call("git stash pop".split())

    return restore


CERT_REGEX = re.compile(
    r"(?P<allprev>x509\.Certificate\{(.*\n+){0,10}.*\s+NotAfter:\s+)(?P<notafter>[^\n]+,?)",
    re.M)

DEFAULT_EXPIRY_REGEX = re.compile(
    r"(?P<funcname>.+\bSetDefaultExpiryTimes)\(\s*map\[string\]int\s*\{([^\{\}]*\n?)+\},?\s*\)",
    re.M)


def patch_expiry(go_filename):
    """
	Patches all expiry times to be 100 years.
	"""
    with open(go_filename) as reader:
        text = reader.read()

    newtext = CERT_REGEX.sub(r"\g<allprev>time.Now().AddDate(100, 0, 0),", text)
    newtext = DEFAULT_EXPIRY_REGEX.sub(r"""\g<funcname>(
        map[string]int{
            data.CanonicalRootRole: 36500,
            data.CanonicalTimestampRole: 36500,
            data.CanonicalSnapshotRole: 36500,
            data.CanonicalTargetsRole: 36500,
        },
    )""", newtext)

    if newtext != text:
        print("Updating", go_filename)
        temp_fd, temp_fname = tempfile.mkstemp()
        with open(temp_fname, 'wb') as temp_file:
            temp_file.write(newtext)
        os.close(temp_fd)
        os.rename(temp_fname, go_filename)
        subprocess.check_call("gofmt -s -w".split() + [go_filename])


def build_and_run(notary_version, git_tag):
    """
    Actually checks out the right version, builds the binaries and the server,
    runs the repo setup, and returns.
    """




if __name__ == "__main__":
    setup_git("v0.1")


# _CWD="$(pwd)"

# # directory of this file
# SOURCE="${BASH_SOURCE[0]}"
# while [ -h "$SOURCE" ]; do # resolve $SOURCE until the file is no longer a symlink
#   DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
#   SOURCE="$(readlink "$SOURCE")"
#   [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE" # if $SOURCE was a relative symlink, we need to resolve it relative to the path where the symlink file was located
# done

# # go to the root notary directory no matter where this script is run from
# cd $(dirname $(dirname $(dirname $SOURCE)))

# # set up the repo in subshell so the environment variables aren't persisted
# echo "$(setup_repo "${1}")"

# # return
# cd "${_CWD}"
