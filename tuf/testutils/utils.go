package testutils

import (
	"time"

	"github.com/docker/notary/cryptoservice"
	"github.com/docker/notary/trustmanager"
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/signed"
	// need to initialize sqlite for tests
	_ "github.com/mattn/go-sqlite3"
)

// CreateKey creates a new key inside the cryptoservice for the given role and gun,
// returning the public key.  If the role is a root role, create an x509 key.
func CreateKey(cs signed.CryptoService, gun, role string) (data.PublicKey, error) {
	key, err := cs.Create(role, gun, data.ECDSAKey)
	if err != nil {
		return nil, err
	}
	if role == data.CanonicalRootRole {
		start := time.Now().AddDate(0, 0, -1)
		privKey, _, err := cs.GetPrivateKey(key.ID())
		if err != nil {
			return nil, err
		}
		cert, err := cryptoservice.GenerateCertificate(
			privKey, gun, start, start.AddDate(1, 0, 0),
		)
		if err != nil {
			return nil, err
		}
		key = data.NewECDSAx509PublicKey(trustmanager.CertToPEM(cert))
	}
	return key, nil
}

// CopyMetadataMap makes a copy of a metadata->bytes mapping
func CopyMetadataMap(from map[string][]byte) map[string][]byte {
	copied := make(map[string][]byte)
	for roleName, metaBytes := range from {
		copied[roleName] = metaBytes
	}
	return copied
}
