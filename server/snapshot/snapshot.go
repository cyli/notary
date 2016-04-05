package snapshot

import (
	"time"

	"github.com/Sirupsen/logrus"

	"github.com/docker/go/canonical/json"
	"github.com/docker/notary/server/storage"
	"github.com/docker/notary/tuf"
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/signed"
)

// GetOrCreateSnapshotKey either creates a new snapshot key, or returns
// the existing one. Only the PublicKey is returned. The private part
// is held by the CryptoService.
func GetOrCreateSnapshotKey(gun string, store storage.KeyStore, crypto signed.CryptoService, createAlgorithm string) (data.PublicKey, error) {
	keyAlgorithm, public, err := store.GetKey(gun, data.CanonicalSnapshotRole)
	if err == nil {
		return data.NewPublicKey(keyAlgorithm, public), nil
	}

	if _, ok := err.(*storage.ErrNoKey); ok {
		key, err := crypto.Create(data.CanonicalSnapshotRole, gun, createAlgorithm)
		if err != nil {
			return nil, err
		}
		logrus.Debug("Creating new snapshot key for ", gun, ". With algo: ", key.Algorithm())
		err = store.SetKey(gun, data.CanonicalSnapshotRole, key.Algorithm(), key.Public())
		if err == nil {
			return key, nil
		}

		if _, ok := err.(*storage.ErrKeyExists); ok {
			keyAlgorithm, public, err = store.GetKey(gun, data.CanonicalSnapshotRole)
			if err != nil {
				return nil, err
			}
			return data.NewPublicKey(keyAlgorithm, public), nil
		}
		return nil, err
	}
	return nil, err
}

// GetOrCreateSnapshot either returns the exisiting latest snapshot, or uses
// whatever the most recent snapshot is to create the next one, only updating
// the expiry time and version.
func GetOrCreateSnapshot(gun string, store storage.MetaStore, cryptoService signed.CryptoService) (
	*time.Time, []byte, error) {

	lastModified, currentJSON, err := store.GetCurrent(gun, data.CanonicalSnapshotRole)
	if err != nil {
		return nil, nil, err
	}

	prev := new(data.SignedSnapshot)
	if err := json.Unmarshal(currentJSON, prev); err != nil {
		logrus.Error("Failed to unmarshal existing snapshot for GUN ", gun)
		return nil, nil, err
	}

	if !snapshotExpired(prev) {
		return lastModified, currentJSON, nil
	}

	builder := tuf.NewRepoBuilder(nil, gun, cryptoService)

	// load the current root to ensure we use the correct snapshot key.
	_, rootJSON, err := store.GetCurrent(gun, data.CanonicalRootRole)
	if err != nil {
		logrus.Debug("Previous snapshot, but no root for GUN ", gun)
		return nil, nil, err
	}
	if err := builder.Load(data.CanonicalRootRole, rootJSON, 0, false); err != nil {
		logrus.Debug("Could not load valid previous root for GUN ", gun)
		return nil, nil, err
	}

	meta, ver, err := builder.GenerateSnapshot(prev)
	if err != nil {
		return nil, nil, err
	}
	update := storage.MetaUpdate{
		Role:    data.CanonicalTimestampRole,
		Version: ver,
		Data:    meta,
	}

	c := time.Now()
	if err = store.UpdateCurrent(gun, update); err != nil {
		return nil, nil, err
	}

	return &c, meta, nil
}

// snapshotExpired simply checks if the snapshot is past its expiry time
func snapshotExpired(sn *data.SignedSnapshot) bool {
	return signed.IsExpired(sn.Signed.Expires)
}
