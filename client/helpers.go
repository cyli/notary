package client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Sirupsen/logrus"
	store "github.com/docker/notary/storage"
	"github.com/docker/notary/tuf"
	"github.com/docker/notary/tuf/data"
)

// Use this to initialize remote HTTPStores from the config settings
func getRemoteStore(baseURL, gun string, rt http.RoundTripper) (store.RemoteStore, error) {
	s, err := store.NewHTTPStore(
		baseURL+"/v2/"+gun+"/_trust/tuf/",
		"",
		"json",
		"key",
		rt,
	)
	if err != nil {
		return store.OfflineStore{}, err
	}
	return s, err
}

func nearExpiry(r data.SignedCommon) bool {
	plus6mo := time.Now().AddDate(0, 6, 0)
	return r.Expires.Before(plus6mo)
}

func warnRolesNearExpiry(r *tuf.Repo) {
	//get every role and its respective signed common and call nearExpiry on it
	//Root check
	if nearExpiry(r.Root.Signed.SignedCommon) {
		logrus.Warn("root is nearing expiry, you should re-sign the role metadata")
	}
	//Targets and delegations check
	for role, signedTOrD := range r.Targets {
		//signedTOrD is of type *data.SignedTargets
		if nearExpiry(signedTOrD.Signed.SignedCommon) {
			logrus.Warn(role, " metadata is nearing expiry, you should re-sign the role metadata")
		}
	}
	//Snapshot check
	if nearExpiry(r.Snapshot.Signed.SignedCommon) {
		logrus.Warn("snapshot is nearing expiry, you should re-sign the role metadata")
	}
	//do not need to worry about Timestamp, notary signer will re-sign with the timestamp key
}

// Fetches a public key from a remote store, given a gun and role
func getRemoteKey(url, gun, role string, rt http.RoundTripper) (data.PublicKey, error) {
	remote, err := getRemoteStore(url, gun, rt)
	if err != nil {
		return nil, err
	}
	rawPubKey, err := remote.GetKey(role)
	if err != nil {
		return nil, err
	}

	pubKey, err := data.UnmarshalPublicKey(rawPubKey)
	if err != nil {
		return nil, err
	}

	return pubKey, nil
}

// Rotates a private key in a remote store and returns the public key component
func rotateRemoteKey(url, gun, role string, rt http.RoundTripper) (data.PublicKey, error) {
	remote, err := getRemoteStore(url, gun, rt)
	if err != nil {
		return nil, err
	}
	rawPubKey, err := remote.RotateKey(role)
	if err != nil {
		return nil, err
	}

	pubKey, err := data.UnmarshalPublicKey(rawPubKey)
	if err != nil {
		return nil, err
	}

	return pubKey, nil
}

// signs and serializes the metadata for a canonical role in a TUF repo to JSON
func serializeCanonicalRole(tufRepo *tuf.Repo, role string) (out []byte, err error) {
	var s *data.Signed
	switch {
	case role == data.CanonicalRootRole:
		s, err = tufRepo.SignRoot(data.DefaultExpires(role))
	case role == data.CanonicalSnapshotRole:
		s, err = tufRepo.SignSnapshot(data.DefaultExpires(role))
	case tufRepo.Targets[role] != nil:
		s, err = tufRepo.SignTargets(
			role, data.DefaultExpires(data.CanonicalTargetsRole))
	default:
		err = fmt.Errorf("%s not supported role to sign on the client", role)
	}

	if err != nil {
		return
	}

	return json.Marshal(s)
}
