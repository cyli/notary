package tuf

import (
	"encoding/json"
	"fmt"

	"github.com/Sirupsen/logrus"
	"github.com/docker/notary/certs"
	"github.com/docker/notary/trustmanager"
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/signed"
)

// ErrBuildDone is returned when any functions are called on RepoBuilder, and it
// is already finished building
type ErrBuildDone struct{}

func (e ErrBuildDone) Error() string {
	return "the builder is done building and cannot accept any more input or produce any more output"
}

// ErrBuildFailed is returned when any functions are called on RepoBuilder, and it
// is already failed building and will not accept any other data
type ErrBuildFailed struct{}

func (e ErrBuildFailed) Error() string {
	return "the builder has failed building and cannot accept any more input or produce any more output"
}

// ErrInvalidBuilderInput is returned when RepoBuilder.Load is called
// with the wrong type of metadata for thes tate that it's in
type ErrInvalidBuilderInput struct{ msg string }

func (e ErrInvalidBuilderInput) Error() string {
	return e.msg
}

// RepoBuilder is an interface for an object which builds a tuf.Repo
type RepoBuilder interface {
	Load(roleName string, content []byte, minVersion int) error
	Finish() (*Repo, error)
	BootstrapNewBuilder() RepoBuilder
	IsLoaded(roleName string) bool
	GetRepo() *Repo
}

// NewRepoBuilder is the only way to get a pre-built RepoBuilder
func NewRepoBuilder(certStore trustmanager.X509Store, gun string, cs signed.CryptoService) RepoBuilder {
	return &repoBuilder{
		repo:                 NewRepo(cs),
		gun:                  gun,
		certStore:            certStore,
		loadedNotChecksummed: make(map[string][]byte),
	}
}

type repoBuilder struct {
	finished bool
	failed   bool
	repo     *Repo

	// needed for root trust pininng verification
	gun       string
	certStore trustmanager.X509Store

	// in case we load root and/or targets before snapshot and timestamp (
	// or snapshot and not timestamp), so we know what to verify when the
	// data with checksums come in
	loadedNotChecksummed map[string][]byte

	// needed for bootstrapping a builder to validate a new root
	rootRole     *data.BaseRole
	rootChecksum *data.Hashes
}

func (rb *repoBuilder) GetRepo() *Repo {
	return rb.repo
}

func (rb *repoBuilder) Finish() (*Repo, error) {
	if rb.finished {
		return nil, ErrBuildDone{}
	}

	rb.finished = true
	return rb.repo, nil
}

func (rb *repoBuilder) BootstrapNewBuilder() RepoBuilder {
	var rootRole *data.BaseRole
	var rootChecksum *data.Hashes

	if rb.repo.Root != nil {
		roleObj, err := rb.repo.GetBaseRole(data.CanonicalRootRole)
		// this should always be true, since it was already validated, otherwise something
		// is very wrong and we should not bootstrap with this root
		if err == nil {
			rootRole = &roleObj
		}
	}
	if rb.repo.Snapshot != nil {
		hashes := rb.repo.Snapshot.Signed.Meta[data.CanonicalRootRole].Hashes
		rootChecksum = &hashes
	}

	return &repoBuilder{
		repo:                 NewRepo(rb.repo.cryptoService),
		gun:                  rb.gun,
		certStore:            rb.certStore,
		loadedNotChecksummed: make(map[string][]byte),

		rootRole:     rootRole,
		rootChecksum: rootChecksum,
	}
}

func (rb *repoBuilder) Load(roleName string, content []byte, minVersion int) error {
	if !data.ValidRole(roleName) {
		return ErrInvalidBuilderInput{msg: fmt.Sprintf("%s is an invalid role", roleName)}
	}

	if rb.IsLoaded(roleName) {
		return ErrInvalidBuilderInput{msg: fmt.Sprintf("%s has already been loaded", roleName)}
	}

	var err error
	switch roleName {
	case data.CanonicalRootRole:
		break
	case data.CanonicalTimestampRole, data.CanonicalSnapshotRole, data.CanonicalTargetsRole:
		err = rb.checkPrereqsLoaded([]string{data.CanonicalRootRole})
	default: // delegations
		err = rb.checkPrereqsLoaded([]string{data.CanonicalRootRole, data.CanonicalTargetsRole})
	}
	if err != nil {
		return err
	}

	switch roleName {
	case data.CanonicalRootRole:
		return rb.loadRoot(content, minVersion)
	case data.CanonicalSnapshotRole:
		return rb.loadSnapshot(content, minVersion)
	case data.CanonicalTimestampRole:
		return rb.loadTimestamp(content, minVersion)
	case data.CanonicalTargetsRole:
		return rb.loadTargets(content, minVersion)
	default:
		return rb.loadDelegation(roleName, content, minVersion)
	}
}

func (rb *repoBuilder) checkPrereqsLoaded(prereqRoles []string) error {
	for _, req := range prereqRoles {
		if !rb.IsLoaded(req) {
			return ErrInvalidBuilderInput{msg: fmt.Sprintf("%s must be loaded first", req)}
		}
	}
	return nil
}

// IsLoaded returns whether a particular role has already been loaded
func (rb *repoBuilder) IsLoaded(roleName string) bool {
	switch roleName {
	case data.CanonicalRootRole:
		return rb.repo.Root != nil
	case data.CanonicalSnapshotRole:
		return rb.repo.Snapshot != nil
	case data.CanonicalTimestampRole:
		return rb.repo.Timestamp != nil
	default:
		return rb.repo.Targets[roleName] != nil
	}
}

// loadRoot loads a root if one has not been loaded
func (rb *repoBuilder) loadRoot(content []byte, minVersion int) error {
	roleName := data.CanonicalRootRole

	signedObj, err := rb.bytesToSigned(content, data.CanonicalRootRole)
	if err != nil {
		return err
	}

	if err := rb.verifyPinnedTrust(signedObj); err != nil {
		return err
	}

	// verify that the metadata structure is correct - we need this in order to get
	// the root role to verify that signatures are self-consistent
	signedRoot, err := data.RootFromSigned(signedObj)
	if err != nil {
		return err
	}

	rootRole, err := signedRoot.BuildBaseRole(roleName)
	if err != nil { // this should never happen, since it's already been validated
		return err
	}
	// validate that the signatures for the root are consistent with its own definitions
	if err := signed.Verify(signedObj, rootRole, minVersion); err != nil {
		return err
	}

	rb.repo.SetRoot(signedRoot)
	return nil
}

// validate against old keys or pinned trust certs
func (rb *repoBuilder) verifyPinnedTrust(signedObj *data.Signed) error {
	// Old root takes precedence over the cert pinning, because presumably the
	// old root had been verified via cert pinning, and the new root might have
	// rotated keys which are not in the pinned certs yet
	if rb.rootRole != nil {
		// verify with existing keys rather than trust pinning
		err := signed.VerifySignatures(signedObj, *rb.rootRole)
		if err != nil {
			logrus.Debug("TUF repo builder: root failed validation against previous root keys")
		}
		return err
	}

	if rb.certStore != nil {
		// TODO: certs.ValidateRoot should only check the trust pinning - we will
		// validate that the root is self-consistent with itself later
		// it also calls RootToSigned, so there are some inefficiencies here
		err := certs.ValidateRoot(rb.certStore, signedObj, rb.gun)
		if err != nil {
			logrus.Debug("TUF repo builder: root failed validation against trust certificates")
		}
		return err
	}

	return nil
}

func (rb *repoBuilder) loadTimestamp(content []byte, minVersion int) error {
	roleName := data.CanonicalTimestampRole

	timestampRole, err := rb.repo.Root.BuildBaseRole(roleName)
	if err != nil { // this should never happen, since it's already been validated
		return err
	}

	signedObj, err := rb.bytesToSignedAndValidateSigs(timestampRole, content, minVersion)
	if err != nil {
		return err
	}

	signedTimestamp, err := data.TimestampFromSigned(signedObj)
	if err != nil {
		return err
	}

	rb.repo.SetTimestamp(signedTimestamp)
	return rb.validateCachedTimestampChecksums(signedTimestamp)
}

func (rb *repoBuilder) loadSnapshot(content []byte, minVersion int) error {
	roleName := data.CanonicalSnapshotRole

	snapshotRole, err := rb.repo.Root.BuildBaseRole(roleName)
	if err != nil { // this should never happen, since it's already been validated
		return err
	}

	signedObj, err := rb.bytesToSignedAndValidateSigs(snapshotRole, content, minVersion)
	if err != nil {
		return err
	}

	signedSnapshot, err := data.SnapshotFromSigned(signedObj)
	if err != nil {
		return err
	}

	rb.repo.SetSnapshot(signedSnapshot)
	return rb.validateCachedSnapshotChecksums(signedSnapshot)
}

func (rb *repoBuilder) loadTargets(content []byte, minVersion int) error {
	roleName := data.CanonicalTargetsRole

	targetsRole, err := rb.repo.Root.BuildBaseRole(roleName)
	if err != nil { // this should never happen, since it's already been validated
		return err
	}

	signedObj, err := rb.bytesToSignedAndValidateSigs(targetsRole, content, minVersion)
	if err != nil {
		return err
	}

	signedTargets, err := data.TargetsFromSigned(signedObj, roleName)
	if err != nil {
		return err
	}

	rb.repo.SetTargets(roleName, signedTargets)
	return nil
}

func (rb *repoBuilder) loadDelegation(roleName string, content []byte, minVersion int) error {
	delegationRole, err := rb.repo.GetDelegationRole(roleName)
	if err != nil {
		return err
	}

	signedObj, err := rb.bytesToSignedAndValidateSigs(delegationRole.BaseRole, content, minVersion)
	if err != nil {
		return err
	}

	signedTargets, err := data.TargetsFromSigned(signedObj, roleName)
	if err != nil {
		return err
	}

	rb.repo.SetTargets(roleName, signedTargets)
	return nil
}

func (rb *repoBuilder) validateCachedTimestampChecksums(ts *data.SignedTimestamp) error {
	var err error
	sn, ok := rb.loadedNotChecksummed[data.CanonicalSnapshotRole]
	if ok {
		delete(rb.loadedNotChecksummed, data.CanonicalSnapshotRole)
		err = data.CheckHashes(sn, data.CanonicalSnapshotRole, ts.Signed.Meta[data.CanonicalSnapshotRole].Hashes)
		if err != nil {
			rb.failed = true
		}
	}
	return err
}

func (rb *repoBuilder) validateCachedSnapshotChecksums(sn *data.SignedSnapshot) error {
	var goodRoles []string
	for roleName, loadedBytes := range rb.loadedNotChecksummed {
		if roleName != data.CanonicalSnapshotRole {
			if err := data.CheckHashes(loadedBytes, roleName, sn.Signed.Meta[roleName].Hashes); err != nil {
				rb.failed = true
				return err
			}
			goodRoles = append(goodRoles, roleName)
		}
	}
	for _, roleName := range goodRoles {
		delete(rb.loadedNotChecksummed, roleName)
	}
	return nil
}

func (rb *repoBuilder) validateChecksumFor(content []byte, roleName string) error {
	// validate the bootstrap checksum for root, if provided
	if roleName == data.CanonicalRootRole && rb.rootChecksum != nil {
		if err := data.CheckHashes(content, roleName, *rb.rootChecksum); err != nil {
			return err
		}
	}

	// but we also want to cache the root content, so that when the snapshot is
	// loaded it is validated (to make sure everything in the repo is self-consistent)
	checksums := rb.getChecksumsFor(roleName)
	if checksums != nil { // as opposed to empty, in which case hash check should fail
		if err := data.CheckHashes(content, roleName, *checksums); err != nil {
			return err
		}
	} else if roleName != data.CanonicalTimestampRole {
		// timestamp is the only role which does not need to be checksummed, but
		// for everything else, cache the contents in the list of roles that have
		// not been checksummed by the snapshot/timestamp yet
		rb.loadedNotChecksummed[roleName] = content
	}

	return nil
}

// Checksums the given bytes, and if they validate, convert to a data.Signed object.
// If a checksums are nil (as opposed to empty), adds the bytes to the list of roles that
// haven't been checksummed (unless it's a timestamp, which has no checksum reference).
func (rb *repoBuilder) bytesToSigned(content []byte, roleName string) (*data.Signed, error) {
	if err := rb.validateChecksumFor(content, roleName); err != nil {
		return nil, err
	}

	// unmarshal to signed
	signedObj := &data.Signed{}
	if err := json.Unmarshal(content, signedObj); err != nil {
		return nil, err
	}

	return signedObj, nil
}

func (rb *repoBuilder) bytesToSignedAndValidateSigs(role data.BaseRole, content []byte, minVersion int) (
	*data.Signed, error) {

	signedObj, err := rb.bytesToSigned(content, role.Name)
	if err != nil {
		return nil, err
	}

	// verify signature, version, and expiry
	if err := signed.Verify(signedObj, role, minVersion); err != nil {
		return nil, err
	}

	return signedObj, nil
}

// If the checksum reference (the loaded timestamp for the snapshot role, and
// the loaded snapshot for every other role except timestamp and snapshot) is nil,
// then return nil for the checksums, meaning that the checksum is not yet
// available.  If the checksum reference *is* loaded, then always returns the
// Hashes object for the given role - if it doesn't exist, returns an empty Hash
// object (against which any checksum validation would fail).
func (rb *repoBuilder) getChecksumsFor(role string) *data.Hashes {
	var hashes data.Hashes
	switch role {
	case data.CanonicalTimestampRole:
		return nil
	case data.CanonicalSnapshotRole:
		if rb.repo.Timestamp == nil {
			return nil
		}
		hashes = rb.repo.Timestamp.Signed.Meta[data.CanonicalSnapshotRole].Hashes
	default:
		if rb.repo.Snapshot == nil {
			return rb.rootChecksum
		}
		hashes = rb.repo.Snapshot.Signed.Meta[role].Hashes
	}
	return &hashes
}
