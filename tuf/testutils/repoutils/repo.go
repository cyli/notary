package repoutils

import (
	"math/rand"
	"sort"
	"time"

	"github.com/docker/go/canonical/json"
	"github.com/docker/notary/cryptoservice"
	"github.com/docker/notary/passphrase"
	"github.com/docker/notary/trustmanager"
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/testutils"
	"github.com/docker/notary/tuf/utils"
	fuzz "github.com/google/gofuzz"

	tuf "github.com/docker/notary/tuf"
	"github.com/docker/notary/tuf/signed"
)

// EmptyRepo creates an in memory crypto service
// and initializes a repo with no targets.  Delegations are only created
// if delegation roles are passed in.
func EmptyRepo(gun string, delegationRoles ...string) (*tuf.Repo, signed.CryptoService, error) {
	cs := cryptoservice.NewCryptoService(trustmanager.NewKeyMemoryStore(passphrase.ConstantRetriever("")))
	r := tuf.NewRepo(cs)

	baseRoles := map[string]data.BaseRole{}
	for _, role := range data.BaseRoles {
		key, err := testutils.CreateKey(cs, gun, role)
		if err != nil {
			return nil, nil, err
		}
		baseRoles[role] = data.NewBaseRole(
			role,
			1,
			key,
		)
	}

	r.InitRoot(
		baseRoles[data.CanonicalRootRole],
		baseRoles[data.CanonicalTimestampRole],
		baseRoles[data.CanonicalSnapshotRole],
		baseRoles[data.CanonicalTargetsRole],
		false,
	)
	r.InitTargets(data.CanonicalTargetsRole)
	r.InitSnapshot()
	r.InitTimestamp()

	// sort the delegation roles so that we make sure to create the parents
	// first
	sort.Strings(delegationRoles)
	for _, delgName := range delegationRoles {
		// create a delegations key and a delegation in the tuf repo
		delgKey, err := testutils.CreateKey(cs, gun, delgName)
		if err != nil {
			return nil, nil, err
		}
		if err := r.UpdateDelegationKeys(delgName, []data.PublicKey{delgKey}, []string{}, 1); err != nil {
			return nil, nil, err
		}
		if err := r.UpdateDelegationPaths(delgName, []string{""}, []string{}, false); err != nil {
			return nil, nil, err
		}
	}

	return r, cs, nil
}

// NewRepoMetadata creates a TUF repo and returns the metadata
func NewRepoMetadata(gun string, delegationRoles ...string) (map[string][]byte, signed.CryptoService, error) {
	tufRepo, cs, err := EmptyRepo(gun, delegationRoles...)
	if err != nil {
		return nil, nil, err
	}

	meta, err := SignAndSerialize(tufRepo)
	if err != nil {
		return nil, nil, err
	}

	return meta, cs, nil
}

// AddTarget generates a fake target and adds it to a repo.
func AddTarget(role string, r *tuf.Repo) (name string, meta data.FileMeta, content []byte, err error) {
	randness := fuzz.Continue{}
	content = RandomByteSlice(1024)
	name = randness.RandString()
	t := data.FileMeta{
		Length: int64(len(content)),
		Hashes: data.Hashes{
			"sha256": utils.DoHash("sha256", content),
			"sha512": utils.DoHash("sha512", content),
		},
	}
	files := data.Files{name: t}
	_, err = r.AddTargets(role, files)
	return
}

// RandomByteSlice generates some random data to be used for testing only
func RandomByteSlice(maxSize int) []byte {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	contentSize := r.Intn(maxSize)
	content := make([]byte, contentSize)
	for i := range content {
		content[i] = byte(r.Int63() & 0xff)
	}
	return content
}

// SignAndSerialize calls Sign and then Serialize to get the repo metadata out
func SignAndSerialize(tufRepo *tuf.Repo) (map[string][]byte, error) {
	meta := make(map[string][]byte)

	for delgName := range tufRepo.Targets {
		// we'll sign targets later
		if delgName == data.CanonicalTargetsRole {
			continue
		}

		signedThing, err := tufRepo.SignTargets(delgName, data.DefaultExpires("targets"))
		if err != nil {
			return nil, err
		}
		metaBytes, err := json.MarshalCanonical(signedThing)
		if err != nil {
			return nil, err
		}

		meta[delgName] = metaBytes
	}

	// these need to be generated after the delegations are created and signed so
	// the snapshot will have the delegation metadata
	rs, tgs, ss, ts, err := Sign(tufRepo)
	if err != nil {
		return nil, err
	}

	rf, tgf, sf, tf, err := Serialize(rs, tgs, ss, ts)
	if err != nil {
		return nil, err
	}

	meta[data.CanonicalRootRole] = rf
	meta[data.CanonicalSnapshotRole] = sf
	meta[data.CanonicalTargetsRole] = tgf
	meta[data.CanonicalTimestampRole] = tf

	return meta, nil
}

// Sign signs all top level roles in a repo in the appropriate order
func Sign(repo *tuf.Repo) (root, targets, snapshot, timestamp *data.Signed, err error) {
	root, err = repo.SignRoot(data.DefaultExpires("root"))
	if _, ok := err.(data.ErrInvalidRole); err != nil && !ok {
		return nil, nil, nil, nil, err
	}
	targets, err = repo.SignTargets("targets", data.DefaultExpires("targets"))
	if _, ok := err.(data.ErrInvalidRole); err != nil && !ok {
		return nil, nil, nil, nil, err
	}
	snapshot, err = repo.SignSnapshot(data.DefaultExpires("snapshot"))
	if _, ok := err.(data.ErrInvalidRole); err != nil && !ok {
		return nil, nil, nil, nil, err
	}
	timestamp, err = repo.SignTimestamp(data.DefaultExpires("timestamp"))
	if _, ok := err.(data.ErrInvalidRole); err != nil && !ok {
		return nil, nil, nil, nil, err
	}
	return
}

// Serialize takes the Signed objects for the 4 top level roles and serializes them all to JSON
func Serialize(sRoot, sTargets, sSnapshot, sTimestamp *data.Signed) (root, targets, snapshot, timestamp []byte, err error) {
	root, err = json.Marshal(sRoot)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	targets, err = json.Marshal(sTargets)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	snapshot, err = json.Marshal(sSnapshot)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	timestamp, err = json.Marshal(sTimestamp)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return
}