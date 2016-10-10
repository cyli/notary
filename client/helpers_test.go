package client

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/testutils"
	"github.com/stretchr/testify/require"
)

func TestAllNearExpiry(t *testing.T) {
	repo, _, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	nearexpdate := time.Now().AddDate(0, 1, 0)
	repo.Root.Signed.SignedCommon.Expires = nearexpdate
	repo.Snapshot.Signed.SignedCommon.Expires = nearexpdate
	repo.Targets["targets"].Signed.Expires = nearexpdate
	_, err1 := repo.InitTargets("targets/exp")
	require.NoError(t, err1)
	repo.Targets["targets/exp"].Signed.Expires = nearexpdate
	//Reset levels to display warnings through logrus
	orgLevel := log.GetLevel()
	log.SetLevel(log.WarnLevel)
	defer log.SetLevel(orgLevel)
	b := bytes.NewBuffer(nil)
	log.SetOutput(b)
	warnRolesNearExpiry(repo)
	require.Contains(t, b.String(), "targets metadata is nearing expiry, you should re-sign the role metadata", "targets should show near expiry")
	require.Contains(t, b.String(), "targets/exp metadata is nearing expiry, you should re-sign the role metadata", "targets/exp should show near expiry")
	require.Contains(t, b.String(), "root is nearing expiry, you should re-sign the role metadata", "Root should show near expiry")
	require.Contains(t, b.String(), "snapshot is nearing expiry, you should re-sign the role metadata", "Snapshot should show near expiry")
	require.NotContains(t, b.String(), "timestamp", "there should be no logrus warnings pertaining to timestamp")
}

func TestAllNotNearExpiry(t *testing.T) {
	repo, _, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	notnearexpdate := time.Now().AddDate(0, 10, 0)
	repo.Root.Signed.SignedCommon.Expires = notnearexpdate
	repo.Snapshot.Signed.SignedCommon.Expires = notnearexpdate
	repo.Targets["targets"].Signed.Expires = notnearexpdate
	_, err1 := repo.InitTargets("targets/noexp")
	require.NoError(t, err1)
	repo.Targets["targets/noexp"].Signed.Expires = notnearexpdate
	//Reset levels to display warnings through logrus
	orgLevel := log.GetLevel()
	log.SetLevel(log.WarnLevel)
	defer log.SetLevel(orgLevel)
	a := bytes.NewBuffer(nil)
	log.SetOutput(a)
	warnRolesNearExpiry(repo)
	require.NotContains(t, a.String(), "targets metadata is nearing expiry, you should re-sign the role metadata", "targets should not show near expiry")
	require.NotContains(t, a.String(), "targets/noexp metadata is nearing expiry, you should re-sign the role metadata", "targets/noexp should not show near expiry")
	require.NotContains(t, a.String(), "root is nearing expiry, you should re-sign the role metadata", "Root should not show near expiry")
	require.NotContains(t, a.String(), "snapshot is nearing expiry, you should re-sign the role metadata", "Snapshot should not show near expiry")
	require.NotContains(t, a.String(), "timestamp", "there should be no logrus warnings pertaining to timestamp")
}

func TestRotateRemoteKeyOffline(t *testing.T) {
	// without a valid roundtripper, rotation should fail since we cannot initialize a HTTPStore
	key, err := rotateRemoteKey("invalidURL", "gun", data.CanonicalSnapshotRole, nil)
	require.Error(t, err)
	require.Nil(t, key)

	// if the underlying remote store is faulty and cannot rotate keys, we should get back the error
	key, err = rotateRemoteKey("https://notary-server", "gun", data.CanonicalSnapshotRole, http.DefaultTransport)
	require.Error(t, err)
	require.Nil(t, key)
}
