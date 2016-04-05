package handlers

import (
	"bytes"
	"path"
	"testing"
	"time"

	"github.com/docker/go/canonical/json"

	"github.com/docker/notary/cryptoservice"
	"github.com/docker/notary/passphrase"
	"github.com/docker/notary/server/storage"
	"github.com/docker/notary/trustmanager"
	"github.com/docker/notary/tuf"
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/signed"
	"github.com/docker/notary/tuf/testutils"
	"github.com/docker/notary/tuf/validation"
	"github.com/stretchr/testify/require"
)

// this is a fake storage that serves errors
type getFailStore struct {
	errsToReturn map[string]error
	storage.MetaStore
}

// GetCurrent returns the current metadata, or an error depending on whether
// getFailStore is configured to return an error for this role
func (f getFailStore) GetCurrent(gun, tufRole string) (*time.Time, []byte, error) {
	err := f.errsToReturn[tufRole]
	if err == nil {
		return f.MetaStore.GetCurrent(gun, tufRole)
	}
	return nil, nil, err
}

// GetChecksum returns the metadata with this checksum, or an error depending on
// whether getFailStore is configured to return an error for this role
func (f getFailStore) GetChecksum(gun, tufRole, checksum string) (*time.Time, []byte, error) {
	err := f.errsToReturn[tufRole]
	if err == nil {
		return f.MetaStore.GetChecksum(gun, tufRole, checksum)
	}
	return nil, nil, err
}

func copyKeys(t *testing.T, from signed.CryptoService, roles ...string) signed.CryptoService {
	memKeyStore := trustmanager.NewKeyMemoryStore(passphrase.ConstantRetriever("pass"))
	for _, role := range roles {
		for _, keyID := range from.ListKeys(role) {
			key, _, err := from.GetPrivateKey(keyID)
			require.NoError(t, err)
			memKeyStore.AddKey(trustmanager.KeyInfo{Role: role}, key)
		}
	}
	return cryptoservice.NewCryptoService(memKeyStore)
}

// Returns a mapping of role name to `MetaUpdate` objects
func getUpdates(r, tg, sn, ts *data.Signed) (
	root, targets, snapshot, timestamp storage.MetaUpdate, err error) {

	rs, tgs, sns, tss, err := testutils.Serialize(r, tg, sn, ts)
	if err != nil {
		return
	}

	root = storage.MetaUpdate{
		Role:    data.CanonicalRootRole,
		Version: 1,
		Data:    rs,
	}
	targets = storage.MetaUpdate{
		Role:    data.CanonicalTargetsRole,
		Version: 1,
		Data:    tgs,
	}
	snapshot = storage.MetaUpdate{
		Role:    data.CanonicalSnapshotRole,
		Version: 1,
		Data:    sns,
	}
	timestamp = storage.MetaUpdate{
		Role:    data.CanonicalTimestampRole,
		Version: 1,
		Data:    tss,
	}
	return
}

func TestValidateEmptyNew(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	store := storage.NewMemStorage()

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)
	root, targets, snapshot, timestamp, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	updates := []storage.MetaUpdate{root, targets, snapshot, timestamp}

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole)

	updates, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.NoError(t, err)

	// we generated our own timestamp, and did not take the other timestamp,
	// but all other metadata should come from updates
	founds := make(map[string]bool)
	for _, update := range updates {
		switch update.Role {
		case data.CanonicalRootRole:
			require.True(t, bytes.Equal(update.Data, root.Data))
			founds[data.CanonicalRootRole] = true
		case data.CanonicalSnapshotRole:
			require.True(t, bytes.Equal(update.Data, snapshot.Data))
			founds[data.CanonicalSnapshotRole] = true
		case data.CanonicalTargetsRole:
			require.True(t, bytes.Equal(update.Data, targets.Data))
			founds[data.CanonicalTargetsRole] = true
		case data.CanonicalTimestampRole:
			require.False(t, bytes.Equal(update.Data, timestamp.Data))
			founds[data.CanonicalTimestampRole] = true
		}
	}
	require.Len(t, founds, 4)
}

func TestValidatePrevTimestamp(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)
	root, targets, snapshot, timestamp, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	updates := []storage.MetaUpdate{root, targets, snapshot}

	store := storage.NewMemStorage()
	store.UpdateCurrent("testGUN", timestamp)

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole)
	updates, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.NoError(t, err)

	// we generated our own timestamp, and did not take the other timestamp,
	// but all other metadata should come from updates
	var foundTimestamp bool
	for _, update := range updates {
		if update.Role == data.CanonicalTimestampRole {
			foundTimestamp = true
			oldTimestamp, newTimestamp := &data.SignedTimestamp{}, &data.SignedTimestamp{}
			require.NoError(t, json.Unmarshal(timestamp.Data, oldTimestamp))
			require.NoError(t, json.Unmarshal(update.Data, newTimestamp))
			require.Equal(t, oldTimestamp.Signed.Version+1, newTimestamp.Signed.Version)
		}
	}
	require.True(t, foundTimestamp)
}

func TestValidatePreviousTimestampCorrupt(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)
	root, targets, snapshot, timestamp, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	updates := []storage.MetaUpdate{root, targets, snapshot}

	// have corrupt timestamp data in the storage already
	store := storage.NewMemStorage()
	timestamp.Data = timestamp.Data[1:]
	store.UpdateCurrent("testGUN", timestamp)

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole)
	_, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.Error(t, err)
	require.IsType(t, &json.SyntaxError{}, err)
}

func TestValidateGetCurrentTimestampBroken(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)
	root, targets, snapshot, _, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	updates := []storage.MetaUpdate{root, targets, snapshot}

	store := getFailStore{
		MetaStore:    storage.NewMemStorage(),
		errsToReturn: map[string]error{data.CanonicalTimestampRole: data.ErrNoSuchRole{}},
	}

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole)
	updates, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.Error(t, err)
	require.IsType(t, data.ErrNoSuchRole{}, err)
}

func TestValidateNoNewRoot(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	store := storage.NewMemStorage()

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)
	root, targets, snapshot, timestamp, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	store.UpdateCurrent("testGUN", root)
	updates := []storage.MetaUpdate{targets, snapshot, timestamp}

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole)
	_, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.NoError(t, err)
}

func TestValidateNoNewTargets(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	store := storage.NewMemStorage()

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)
	root, targets, snapshot, timestamp, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	store.UpdateCurrent("testGUN", targets)
	updates := []storage.MetaUpdate{root, snapshot, timestamp}

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole)
	_, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.NoError(t, err)
}

func TestValidateOnlySnapshot(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	store := storage.NewMemStorage()

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)
	root, targets, snapshot, _, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	store.UpdateCurrent("testGUN", root)
	store.UpdateCurrent("testGUN", targets)

	updates := []storage.MetaUpdate{snapshot}

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole)
	_, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.NoError(t, err)
}

func TestValidateOldRoot(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	store := storage.NewMemStorage()

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)
	root, targets, snapshot, timestamp, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	store.UpdateCurrent("testGUN", root)
	updates := []storage.MetaUpdate{root, targets, snapshot, timestamp}

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole)
	_, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.NoError(t, err)
}

func TestValidateOldRootCorrupt(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	store := storage.NewMemStorage()

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)
	root, targets, snapshot, timestamp, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	badRoot := storage.MetaUpdate{
		Version: root.Version,
		Role:    root.Role,
		Data:    root.Data[1:],
	}
	store.UpdateCurrent("testGUN", badRoot)
	updates := []storage.MetaUpdate{root, targets, snapshot, timestamp}

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole)
	_, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.Error(t, err)
	require.IsType(t, &json.SyntaxError{}, err)
}

// We cannot validate a new root if the old root is corrupt, because there might
// have been a root key rotation.
func TestValidateOldRootCorruptRootRole(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	store := storage.NewMemStorage()

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)
	root, targets, snapshot, timestamp, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	// so a valid root, but missing the root role
	signedRoot, err := data.RootFromSigned(r)
	require.NoError(t, err)
	delete(signedRoot.Signed.Roles, data.CanonicalRootRole)
	badRootJSON, err := json.Marshal(signedRoot)
	require.NoError(t, err)
	badRoot := storage.MetaUpdate{
		Version: root.Version,
		Role:    root.Role,
		Data:    badRootJSON,
	}
	store.UpdateCurrent("testGUN", badRoot)
	updates := []storage.MetaUpdate{root, targets, snapshot, timestamp}

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole)
	_, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.Error(t, err)
	require.IsType(t, data.ErrInvalidMetadata{}, err)
}

// We cannot validate a new root if we cannot get the old root from the DB (
// and cannot detect whether there was an old root or not), because there might
// have been an old root and we can't determine if the new root represents a
// root key rotation.
func TestValidateRootGetCurrentRootBroken(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	store := getFailStore{
		MetaStore:    storage.NewMemStorage(),
		errsToReturn: map[string]error{data.CanonicalRootRole: data.ErrNoSuchRole{}},
	}

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)
	root, targets, snapshot, timestamp, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	updates := []storage.MetaUpdate{root, targets, snapshot, timestamp}

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole)
	_, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.Error(t, err)
	require.IsType(t, data.ErrNoSuchRole{}, err)
}

// A valid root rotation requires that the new root be signed with both old and new keys.
func TestValidateRootRotation(t *testing.T) {
	repo, crypto, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	store := storage.NewMemStorage()

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)
	root, targets, snapshot, timestamp, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	store.UpdateCurrent("testGUN", root)

	oldRootRole := repo.Root.Signed.Roles["root"]
	oldRootKey := repo.Root.Signed.Keys[oldRootRole.KeyIDs[0]]

	rootKey, err := crypto.Create("root", "", data.ED25519Key)
	require.NoError(t, err)
	rootRole, err := data.NewRole("root", 1, []string{rootKey.ID()}, nil)
	require.NoError(t, err)

	delete(repo.Root.Signed.Keys, oldRootRole.KeyIDs[0])

	repo.Root.Signed.Roles["root"] = &rootRole.RootRole
	repo.Root.Signed.Keys[rootKey.ID()] = rootKey

	r, err = repo.SignRoot(data.DefaultExpires(data.CanonicalRootRole))
	require.NoError(t, err)
	err = signed.Sign(crypto, r, rootKey, oldRootKey)
	require.NoError(t, err)

	rt, err := data.RootFromSigned(r)
	require.NoError(t, err)
	repo.SetRoot(rt)

	sn, err = repo.SignSnapshot(data.DefaultExpires(data.CanonicalSnapshotRole))
	require.NoError(t, err)
	root, targets, snapshot, timestamp, err = getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	updates := []storage.MetaUpdate{root, targets, snapshot, timestamp}

	serverCrypto := copyKeys(t, crypto, data.CanonicalTimestampRole)
	_, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.NoError(t, err)
}

// A root rotation must be signed with old and new root keys, otherwise the
// new root fails to validate
func TestRootRotationNotSignedWithOldKeys(t *testing.T) {
	repo, crypto, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	store := storage.NewMemStorage()

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)
	root, targets, snapshot, timestamp, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	store.UpdateCurrent("testGUN", root)

	rootKey, err := crypto.Create("root", "testGUN", data.ED25519Key)
	require.NoError(t, err)
	rootRole, err := data.NewRole("root", 1, []string{rootKey.ID()}, nil)
	require.NoError(t, err)

	repo.Root.Signed.Roles["root"] = &rootRole.RootRole
	repo.Root.Signed.Keys[rootKey.ID()] = rootKey

	r, err = repo.SignRoot(data.DefaultExpires(data.CanonicalRootRole))
	require.NoError(t, err)
	err = signed.Sign(crypto, r, rootKey)
	require.NoError(t, err)

	rt, err := data.RootFromSigned(r)
	require.NoError(t, err)
	repo.SetRoot(rt)

	sn, err = repo.SignSnapshot(data.DefaultExpires(data.CanonicalSnapshotRole))
	require.NoError(t, err)
	root, targets, snapshot, timestamp, err = getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	updates := []storage.MetaUpdate{root, targets, snapshot, timestamp}

	serverCrypto := copyKeys(t, crypto, data.CanonicalTimestampRole)
	_, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.Error(t, err)
	require.Contains(t, err.Error(), "new root was not signed with at least 1 old keys")
}

// An update is not valid without the root metadata.
func TestValidateNoRoot(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	store := storage.NewMemStorage()

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)
	_, targets, snapshot, timestamp, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	updates := []storage.MetaUpdate{targets, snapshot, timestamp}

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole)
	_, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.Error(t, err)
	require.IsType(t, validation.ErrValidation{}, err)
}

func TestValidateSnapshotMissingNoSnapshotKey(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	store := storage.NewMemStorage()

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)
	root, targets, _, _, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	updates := []storage.MetaUpdate{root, targets}

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole)
	_, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.Error(t, err)
	require.IsType(t, validation.ErrBadHierarchy{}, err)
}

func TestValidateSnapshotGenerateNoPrev(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	store := storage.NewMemStorage()
	snapRole, err := repo.GetBaseRole(data.CanonicalSnapshotRole)
	require.NoError(t, err)

	for _, k := range snapRole.Keys {
		err := store.SetKey("testGUN", data.CanonicalSnapshotRole, k.Algorithm(), k.Public())
		require.NoError(t, err)
	}

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)
	root, targets, _, _, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	updates := []storage.MetaUpdate{root, targets}

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole, data.CanonicalSnapshotRole)
	_, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.NoError(t, err)
}

func TestValidateSnapshotGenerateWithPrev(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	store := storage.NewMemStorage()
	snapRole, err := repo.GetBaseRole(data.CanonicalSnapshotRole)
	require.NoError(t, err)

	for _, k := range snapRole.Keys {
		err := store.SetKey("testGUN", data.CanonicalSnapshotRole, k.Algorithm(), k.Public())
		require.NoError(t, err)
	}

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)
	root, targets, snapshot, _, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	updates := []storage.MetaUpdate{root, targets}

	// set the current snapshot in the store manually so we find it when generating
	// the next version
	store.UpdateCurrent("testGUN", snapshot)

	prev, err := data.SnapshotFromSigned(sn)
	require.NoError(t, err)

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole, data.CanonicalSnapshotRole)
	updates, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.NoError(t, err)

	for _, u := range updates {
		if u.Role == data.CanonicalSnapshotRole {
			curr := &data.SignedSnapshot{}
			err = json.Unmarshal(u.Data, curr)
			require.Equal(t, prev.Signed.Version+1, curr.Signed.Version)
			require.Equal(t, u.Version, curr.Signed.Version)
		}
	}
}

func TestValidateSnapshotGeneratePrevCorrupt(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	store := storage.NewMemStorage()
	snapRole, err := repo.GetBaseRole(data.CanonicalSnapshotRole)
	require.NoError(t, err)

	for _, k := range snapRole.Keys {
		err := store.SetKey("testGUN", data.CanonicalSnapshotRole, k.Algorithm(), k.Public())
		require.NoError(t, err)
	}

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)
	root, targets, snapshot, _, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	updates := []storage.MetaUpdate{root, targets}

	// corrupt the JSON structure of prev snapshot
	snapshot.Data = snapshot.Data[1:]
	// set the current snapshot in the store manually so we find it when generating
	// the next version
	store.UpdateCurrent("testGUN", snapshot)

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole, data.CanonicalSnapshotRole)
	updates, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.Error(t, err)
	require.IsType(t, &json.SyntaxError{}, err)
}

// Store is broken when getting the current snapshot
func TestValidateSnapshotGenerateStoreGetCurrentSnapshotBroken(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	store := getFailStore{
		MetaStore:    storage.NewMemStorage(),
		errsToReturn: map[string]error{data.CanonicalSnapshotRole: data.ErrNoSuchRole{}},
	}
	snapRole, err := repo.GetBaseRole(data.CanonicalSnapshotRole)
	require.NoError(t, err)

	for _, k := range snapRole.Keys {
		err := store.SetKey("testGUN", data.CanonicalSnapshotRole, k.Algorithm(), k.Public())
		require.NoError(t, err)
	}

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)
	root, targets, _, _, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	updates := []storage.MetaUpdate{root, targets}

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole, data.CanonicalSnapshotRole)
	_, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.Error(t, err)
	require.IsType(t, data.ErrNoSuchRole{}, err)
}

func TestValidateSnapshotGenerateNoTargets(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	store := storage.NewMemStorage()
	snapRole, err := repo.GetBaseRole(data.CanonicalSnapshotRole)
	require.NoError(t, err)

	for _, k := range snapRole.Keys {
		err := store.SetKey("testGUN", data.CanonicalSnapshotRole, k.Algorithm(), k.Public())
		require.NoError(t, err)
	}

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)
	root, _, _, _, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	updates := []storage.MetaUpdate{root}

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole, data.CanonicalSnapshotRole)
	updates, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.Error(t, err)
}

func TestValidateSnapshotGenerate(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	store := storage.NewMemStorage()
	snapRole, err := repo.GetBaseRole(data.CanonicalSnapshotRole)
	require.NoError(t, err)

	for _, k := range snapRole.Keys {
		err := store.SetKey("testGUN", data.CanonicalSnapshotRole, k.Algorithm(), k.Public())
		require.NoError(t, err)
	}

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)
	root, targets, _, _, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	updates := []storage.MetaUpdate{targets}

	store.UpdateCurrent("testGUN", root)

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole, data.CanonicalSnapshotRole)
	updates, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.NoError(t, err)
}

// If there is no timestamp key in the store, validation fails.  This could
// happen if pushing an existing repository from one server to another that
// does not have the repo.
func TestValidateRootNoTimestampKey(t *testing.T) {
	oldRepo, _, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	r, tg, sn, ts, err := testutils.Sign(oldRepo)
	require.NoError(t, err)
	root, targets, snapshot, _, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	store := storage.NewMemStorage()
	updates := []storage.MetaUpdate{root, targets, snapshot}

	// do not copy the targets key to the storage, and try to update the root
	serverCrypto := signed.NewEd25519()
	_, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.Error(t, err)
	require.IsType(t, validation.ErrBadRoot{}, err)

	// there should still be no timestamp keys - one should not have been
	// created
	require.Empty(t, serverCrypto.ListAllKeys())
}

// If the timestamp key in the store does not match the timestamp key in
// the root.json, validation fails.  This could happen if pushing an existing
// repository from one server to another that had already initialized the same
// repo.
func TestValidateRootInvalidTimestampKey(t *testing.T) {
	oldRepo, _, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	r, tg, sn, ts, err := testutils.Sign(oldRepo)
	require.NoError(t, err)
	root, targets, snapshot, _, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	store := storage.NewMemStorage()
	updates := []storage.MetaUpdate{root, targets, snapshot}

	serverCrypto := signed.NewEd25519()
	_, err = serverCrypto.Create(data.CanonicalTimestampRole, "testGUN", data.ED25519Key)
	require.NoError(t, err)

	_, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.Error(t, err)
	require.IsType(t, validation.ErrBadRoot{}, err)
}

// If the timestamp role has a threshold > 1, validation fails.
func TestValidateRootInvalidTimestampThreshold(t *testing.T) {
	oldRepo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	tsRole, ok := oldRepo.Root.Signed.Roles[data.CanonicalTimestampRole]
	require.True(t, ok)
	tsRole.Threshold = 2

	r, tg, sn, ts, err := testutils.Sign(oldRepo)
	require.NoError(t, err)
	root, targets, snapshot, _, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	store := storage.NewMemStorage()
	updates := []storage.MetaUpdate{root, targets, snapshot}

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole)
	_, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.Error(t, err)
	require.IsType(t, validation.ErrValidation{}, err)
}

// If any role has a threshold < 1, validation fails
func TestValidateRootInvalidZeroThreshold(t *testing.T) {
	for _, role := range data.BaseRoles {
		oldRepo, cs, err := testutils.EmptyRepo("docker.com/notary")
		require.NoError(t, err)
		tsRole, ok := oldRepo.Root.Signed.Roles[role]
		require.True(t, ok)
		tsRole.Threshold = 0

		r, tg, sn, ts, err := testutils.Sign(oldRepo)
		require.NoError(t, err)
		root, targets, snapshot, _, err := getUpdates(r, tg, sn, ts)
		require.NoError(t, err)

		store := storage.NewMemStorage()
		updates := []storage.MetaUpdate{root, targets, snapshot}

		serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole)
		_, err = validateUpdate(serverCrypto, "testGUN", updates, store)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid threshold")
	}
}

// ### Role missing negative tests ###
// These tests remove a role from the Root file and
// check for a validation.ErrBadRoot
func TestValidateRootRoleMissing(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	store := storage.NewMemStorage()

	delete(repo.Root.Signed.Roles, "root")

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)
	root, targets, snapshot, timestamp, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	updates := []storage.MetaUpdate{root, targets, snapshot, timestamp}

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole)
	_, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.Error(t, err)
	require.IsType(t, validation.ErrBadRoot{}, err)
}

func TestValidateTargetsRoleMissing(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	store := storage.NewMemStorage()

	delete(repo.Root.Signed.Roles, "targets")

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)
	root, targets, snapshot, timestamp, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	updates := []storage.MetaUpdate{root, targets, snapshot, timestamp}

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole)
	_, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.Error(t, err)
	require.IsType(t, validation.ErrBadRoot{}, err)
}

func TestValidateSnapshotRoleMissing(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	store := storage.NewMemStorage()

	delete(repo.Root.Signed.Roles, "snapshot")

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)
	root, targets, snapshot, timestamp, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	updates := []storage.MetaUpdate{root, targets, snapshot, timestamp}

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole)
	_, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.Error(t, err)
	require.IsType(t, validation.ErrBadRoot{}, err)
}

// ### End role missing negative tests ###

// ### Signature missing negative tests ###
func TestValidateRootSigMissing(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	store := storage.NewMemStorage()

	delete(repo.Root.Signed.Roles, "snapshot")

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)

	r.Signatures = nil

	root, targets, snapshot, timestamp, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	updates := []storage.MetaUpdate{root, targets, snapshot, timestamp}

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole)
	_, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.Error(t, err)
	require.IsType(t, validation.ErrBadRoot{}, err)
}

func TestValidateTargetsSigMissing(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	store := storage.NewMemStorage()

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)

	tg.Signatures = nil

	root, targets, snapshot, timestamp, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	updates := []storage.MetaUpdate{root, targets, snapshot, timestamp}

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole)
	_, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.Error(t, err)
	require.IsType(t, validation.ErrBadTargets{}, err)
}

func TestValidateSnapshotSigMissing(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	store := storage.NewMemStorage()

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)

	sn.Signatures = nil

	root, targets, snapshot, timestamp, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	updates := []storage.MetaUpdate{root, targets, snapshot, timestamp}

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole)
	_, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.Error(t, err)
	require.IsType(t, validation.ErrBadSnapshot{}, err)
}

// ### End signature missing negative tests ###

// ### Corrupted metadata negative tests ###
func TestValidateRootCorrupt(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	store := storage.NewMemStorage()

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)
	root, targets, snapshot, timestamp, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	// flip all the bits in the first byte
	root.Data[0] = root.Data[0] ^ 0xff

	updates := []storage.MetaUpdate{root, targets, snapshot, timestamp}

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole)
	_, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.Error(t, err)
	require.IsType(t, validation.ErrBadRoot{}, err)
}

func TestValidateTargetsCorrupt(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	store := storage.NewMemStorage()

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)
	root, targets, snapshot, timestamp, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	// flip all the bits in the first byte
	targets.Data[0] = targets.Data[0] ^ 0xff

	updates := []storage.MetaUpdate{root, targets, snapshot, timestamp}

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole)
	_, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.Error(t, err)
	require.IsType(t, validation.ErrBadTargets{}, err)
}

func TestValidateSnapshotCorrupt(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	store := storage.NewMemStorage()

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)
	root, targets, snapshot, timestamp, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	// flip all the bits in the first byte
	snapshot.Data[0] = snapshot.Data[0] ^ 0xff

	updates := []storage.MetaUpdate{root, targets, snapshot, timestamp}

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole)
	_, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.Error(t, err)
	require.IsType(t, validation.ErrBadSnapshot{}, err)
}

// ### End corrupted metadata negative tests ###

// ### Snapshot size mismatch negative tests ###
func TestValidateRootModifiedSize(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	store := storage.NewMemStorage()

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)

	// add another copy of the signature so the hash is different
	r.Signatures = append(r.Signatures, r.Signatures[0])

	root, targets, snapshot, timestamp, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	// flip all the bits in the first byte
	root.Data[0] = root.Data[0] ^ 0xff

	updates := []storage.MetaUpdate{root, targets, snapshot, timestamp}

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole)
	_, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.Error(t, err)
	require.IsType(t, validation.ErrBadRoot{}, err)
}

func TestValidateTargetsModifiedSize(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	store := storage.NewMemStorage()

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)

	// add another copy of the signature so the hash is different
	tg.Signatures = append(tg.Signatures, tg.Signatures[0])

	root, targets, snapshot, timestamp, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	updates := []storage.MetaUpdate{root, targets, snapshot, timestamp}

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole)
	_, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.Error(t, err)
	require.IsType(t, validation.ErrBadSnapshot{}, err)
}

// ### End snapshot size mismatch negative tests ###

// ### Snapshot hash mismatch negative tests ###
func TestValidateRootModifiedHash(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	store := storage.NewMemStorage()

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)

	snap, err := data.SnapshotFromSigned(sn)
	require.NoError(t, err)
	snap.Signed.Meta["root"].Hashes["sha256"][0] = snap.Signed.Meta["root"].Hashes["sha256"][0] ^ 0xff

	sn, err = snap.ToSigned()
	require.NoError(t, err)

	root, targets, snapshot, timestamp, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	updates := []storage.MetaUpdate{root, targets, snapshot, timestamp}

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole)
	_, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.Error(t, err)
	require.IsType(t, validation.ErrBadSnapshot{}, err)
}

func TestValidateTargetsModifiedHash(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	store := storage.NewMemStorage()

	r, tg, sn, ts, err := testutils.Sign(repo)
	require.NoError(t, err)

	snap, err := data.SnapshotFromSigned(sn)
	require.NoError(t, err)
	snap.Signed.Meta["targets"].Hashes["sha256"][0] = snap.Signed.Meta["targets"].Hashes["sha256"][0] ^ 0xff

	sn, err = snap.ToSigned()
	require.NoError(t, err)

	root, targets, snapshot, timestamp, err := getUpdates(r, tg, sn, ts)
	require.NoError(t, err)

	updates := []storage.MetaUpdate{root, targets, snapshot, timestamp}

	serverCrypto := copyKeys(t, cs, data.CanonicalTimestampRole)
	_, err = validateUpdate(serverCrypto, "testGUN", updates, store)
	require.Error(t, err)
	require.IsType(t, validation.ErrBadSnapshot{}, err)
}

// ### End snapshot hash mismatch negative tests ###

// ### generateSnapshot tests ###
func TestGenerateSnapshotRootNotLoaded(t *testing.T) {
	builder := tuf.NewRepoBuilder(nil, "gun", nil)
	_, err := generateSnapshot("gun", builder, storage.NewMemStorage())
	require.Error(t, err)
	require.IsType(t, validation.ErrValidation{}, err)
}

func TestGenerateSnapshotNoKey(t *testing.T) {
	metadata, cs, err := testutils.NewRepoMetadata("docker.com/notary")
	require.NoError(t, err)
	store := storage.NewMemStorage()

	// delete snapshot key in the cryptoservice
	for _, keyID := range cs.ListKeys(data.CanonicalSnapshotRole) {
		require.NoError(t, cs.RemoveKey(keyID))
	}

	builder := tuf.NewRepoBuilder(nil, "gun", cs)
	// only load root and targets
	require.NoError(t, builder.Load(data.CanonicalRootRole, metadata[data.CanonicalRootRole], 0))
	require.NoError(t, builder.Load(data.CanonicalTargetsRole, metadata[data.CanonicalTargetsRole], 0))

	_, err = generateSnapshot("gun", builder, store)
	require.Error(t, err)
	require.IsType(t, validation.ErrBadHierarchy{}, err)
}

// ### End generateSnapshot tests ###

// ### Target validation with delegations tests
func TestLoadTargetsLoadsNothingIfNoUpdates(t *testing.T) {
	gun := "docker.com/notary"
	metadata, _, err := testutils.NewRepoMetadata(gun)
	require.NoError(t, err)

	// load the root into the builder, else we can't load anything else
	builder := tuf.NewRepoBuilder(nil, gun, nil)
	require.NoError(t, builder.Load(data.CanonicalRootRole, metadata[data.CanonicalRootRole], 0))

	store := storage.NewMemStorage()
	store.UpdateCurrent(gun, storage.MetaUpdate{
		Role:    data.CanonicalTargetsRole,
		Version: 1,
		Data:    metadata[data.CanonicalTargetsRole],
	})

	// if no updates, nothing is loaded
	targetsToUpdate, err := loadAndValidateTargets(gun, builder, nil, store)
	require.Empty(t, targetsToUpdate)
	require.NoError(t, err)
	require.False(t, builder.IsLoaded(data.CanonicalTargetsRole))
}

// When a delegation role appears in the update and the parent does not, the
// parent is loaded from the DB if it can
func TestValidateTargetsRequiresStoredParent(t *testing.T) {
	delgName := "targets/level1"
	metadata, _, err := testutils.NewRepoMetadata("docker.com/notary",
		delgName, path.Join(delgName, "other"))
	require.NoError(t, err)

	// load the root into the builder, else we can't load anything else
	builder := tuf.NewRepoBuilder(nil, "gun", nil)
	require.NoError(t, builder.Load(data.CanonicalRootRole, metadata[data.CanonicalRootRole], 0))

	delUpdate := storage.MetaUpdate{
		Role:    delgName,
		Version: 1,
		Data:    metadata[delgName],
	}

	upload := map[string]storage.MetaUpdate{delgName: delUpdate}

	store := storage.NewMemStorage()

	// if the DB has no "targets" role
	_, err = loadAndValidateTargets("gun", builder, upload, store)
	require.Error(t, err)
	require.IsType(t, validation.ErrBadTargets{}, err)

	// ensure the "targets" (the parent) is in the "db"
	store.UpdateCurrent("gun", storage.MetaUpdate{
		Role:    data.CanonicalTargetsRole,
		Version: 1,
		Data:    metadata[data.CanonicalTargetsRole],
	})

	updates, err := loadAndValidateTargets("gun", builder, upload, store)
	require.NoError(t, err)
	require.Len(t, updates, 1)
	require.Equal(t, delgName, updates[0].Role)
	require.Equal(t, metadata[delgName], updates[0].Data)
}

// If the parent is not in the store, then the parent must be in the update else
// validation fails.
func TestValidateTargetsParentInUpdate(t *testing.T) {
	gun := "docker.com/notary"
	delgName := "targets/level1"
	metadata, _, err := testutils.NewRepoMetadata(gun, delgName, path.Join(delgName, "other"))
	require.NoError(t, err)
	store := storage.NewMemStorage()

	// load the root into the builder, else we can't load anything else
	builder := tuf.NewRepoBuilder(nil, gun, nil)
	require.NoError(t, builder.Load(data.CanonicalRootRole, metadata[data.CanonicalRootRole], 0))

	targetsUpdate := storage.MetaUpdate{
		Role:    data.CanonicalTargetsRole,
		Version: 1,
		Data:    []byte("Invalid metadata"),
	}

	delgUpdate := storage.MetaUpdate{
		Role:    delgName,
		Version: 1,
		Data:    metadata[delgName],
	}

	upload := map[string]storage.MetaUpdate{
		"targets/level1":          delgUpdate,
		data.CanonicalTargetsRole: targetsUpdate,
	}

	// parent update not readable - fail
	_, err = loadAndValidateTargets(gun, builder, upload, store)
	require.Error(t, err)
	require.IsType(t, validation.ErrBadTargets{}, err)

	// because we sort the roles, the list of returned updates
	// will contain shallower roles first, in this case "targets",
	// and then "targets/level1"
	targetsUpdate.Data = metadata[data.CanonicalTargetsRole]
	upload[data.CanonicalTargetsRole] = targetsUpdate
	updates, err := loadAndValidateTargets(gun, builder, upload, store)
	require.NoError(t, err)
	require.Equal(t, []storage.MetaUpdate{targetsUpdate, delgUpdate}, updates)
}

// If the parent, either from the DB or from an update, does not contain the role
// of the delegation update, validation fails
func TestValidateTargetsRoleNotInParent(t *testing.T) {
	// no delegation at first
	gun := "docker.com/notary"
	repo, cs, err := testutils.EmptyRepo(gun)
	require.NoError(t, err)

	meta, err := testutils.SignAndSerialize(repo)
	require.NoError(t, err)

	// load the root into the builder, else we can't load anything else
	builder := tuf.NewRepoBuilder(nil, gun, nil)
	require.NoError(t, builder.Load(data.CanonicalRootRole, meta[data.CanonicalRootRole], 0))

	// prepare the original targets file, without a delegation role, as an update
	origTargetsUpdate := storage.MetaUpdate{
		Role:    data.CanonicalTargetsRole,
		Version: 1,
		Data:    meta[data.CanonicalTargetsRole],
	}
	emptyStore := storage.NewMemStorage()
	storeWithParent := storage.NewMemStorage()
	storeWithParent.UpdateCurrent(gun, origTargetsUpdate)

	// add a delegation role now
	delgName := "targets/level1"
	level1Key, err := cs.Create(delgName, gun, data.ECDSAKey)
	require.NoError(t, err)
	require.NoError(t, repo.UpdateDelegationKeys(delgName, []data.PublicKey{level1Key}, []string{}, 1))
	// create the delegation metadata too
	repo.InitTargets(delgName)

	// re-serialize
	meta, err = testutils.SignAndSerialize(repo)
	require.NoError(t, err)
	delgMeta, ok := meta[delgName]
	require.True(t, ok)

	delgUpdate := storage.MetaUpdate{
		Role:    delgName,
		Version: 1,
		Data:    delgMeta,
	}

	// parent in update does not have this role, whether or not there's a parent in the store,
	// so validation fails
	roles := map[string]storage.MetaUpdate{
		delgName:                  delgUpdate,
		data.CanonicalTargetsRole: origTargetsUpdate,
	}
	for _, metaStore := range []storage.MetaStore{emptyStore, storeWithParent} {
		updates, err := loadAndValidateTargets("gun", builder, roles, metaStore)
		require.Error(t, err)
		require.Empty(t, updates)
		require.IsType(t, validation.ErrBadTargets{}, err)
	}

	// if the update is provided without the parent, then the parent from the
	// store is loaded - if it doesn't have the role, then the update fails
	updates, err := loadAndValidateTargets("gun", builder,
		map[string]storage.MetaUpdate{delgName: delgUpdate}, storeWithParent)
	require.Error(t, err)
	require.Empty(t, updates)
	require.IsType(t, validation.ErrBadTargets{}, err)
}

// ### End target validation with delegations tests
