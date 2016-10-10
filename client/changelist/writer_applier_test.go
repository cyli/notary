package changelist

import (
	"crypto/sha256"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/testutils"
	"github.com/stretchr/testify/require"
)

var emptyHash = sha256.Sum256([]byte{})
var fakeMeta = data.FileMeta{
	Length: 1,
	Hashes: map[string][]byte{
		"sha256": emptyHash[:],
	},
}

// An empty changelist can be applied to the repo without changing anything
func TestApplyEmptyChangelist(t *testing.T) {
	repo, _, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	// copy the data
	root := *repo.Root
	snapshot := *repo.Snapshot
	timestamp := *repo.Timestamp
	targets := *repo.Targets["targets"]

	err = ApplyChangelist(repo, nil, NewMemChangelist())
	require.NoError(t, err)
	require.Equal(t, root, *repo.Root)
	require.Equal(t, snapshot, *repo.Snapshot)
	require.Equal(t, timestamp, *repo.Timestamp)
	require.Equal(t, targets, *repo.Targets["targets"])
}

func TestApplyTargetsChange(t *testing.T) {
	repo, _, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	cl := NewMemChangelist()
	w := NewWriter(cl, nil)

	// no role is specified - defaults to targets
	require.NoError(t, w.AddTarget("latest", fakeMeta))

	require.Empty(t, repo.Targets["targets"].Signed.Targets)

	err = ApplyChangelist(repo, nil, cl)
	require.NoError(t, err)
	require.NotNil(t, repo.Targets["targets"].Signed.Targets["latest"])

	require.NoError(t, cl.Clear(""))
	// no role is specified - defaults to targets
	require.NoError(t, w.RemoveTarget("latest"))

	err = ApplyChangelist(repo, nil, cl)
	require.NoError(t, err)
	require.Empty(t, repo.Targets["targets"].Signed.Targets)
}

// Adding the same target any number of times is idempotent
func TestApplyAddTargetTwice(t *testing.T) {
	repo, _, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	cl := NewMemChangelist()
	w := NewWriter(cl, nil)

	// adding the same thing twice doesn't error
	require.NoError(t, w.AddTarget("latest", fakeMeta))
	require.NoError(t, w.AddTarget("latest", fakeMeta))

	require.NoError(t, ApplyChangelist(repo, nil, cl))
	require.Len(t, repo.Targets["targets"].Signed.Targets, 1)
	require.NotEmpty(t, repo.Targets["targets"].Signed.Targets["latest"])

	// apply the changes again even though the target is already on the repo
	require.NoError(t, ApplyChangelist(repo, nil, cl))
	require.Len(t, repo.Targets["targets"].Signed.Targets, 1)
	require.NotEmpty(t, repo.Targets["targets"].Signed.Targets["latest"])
}

// This adds and removes the target, then applies the changelist, which should
// result in a noop
func TestApplyAddRemoveTarget(t *testing.T) {
	repo, _, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	cl := NewMemChangelist()
	w := NewWriter(cl, nil)

	require.Empty(t, repo.Targets["targets"].Signed.Targets)

	require.NoError(t, w.AddTarget("latest", fakeMeta))
	require.NoError(t, w.RemoveTarget("latest"))

	err = ApplyChangelist(repo, nil, cl)
	require.NoError(t, err)

	require.Empty(t, repo.Targets["targets"].Signed.Targets)
}

func TestApplyTargetsDelegationCreateDelete(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	cl := NewMemChangelist()
	w := NewWriter(cl, nil)

	newKey, err := cs.Create("targets/level1", "docker.com/notary", data.ED25519Key)
	require.NoError(t, err)

	// create delegation
	require.NoError(t, w.AddDelegation("targets/level1", []data.PublicKey{newKey}, []string{"level1"}))

	err = ApplyChangelist(repo, nil, cl)
	require.NoError(t, err)

	tgts := repo.Targets[data.CanonicalTargetsRole]
	require.Len(t, tgts.Signed.Delegations.Roles, 1)
	require.Len(t, tgts.Signed.Delegations.Keys, 1)

	_, ok := tgts.Signed.Delegations.Keys[newKey.ID()]
	require.True(t, ok)

	role := tgts.Signed.Delegations.Roles[0]
	require.Len(t, role.KeyIDs, 1)
	require.Equal(t, newKey.ID(), role.KeyIDs[0])
	require.Equal(t, "targets/level1", role.Name)
	require.Equal(t, "level1", role.Paths[0])

	// delete delegation
	require.NoError(t, cl.Clear(""))
	require.NoError(t, w.RemoveDelegationRole("targets/level1"))

	err = ApplyChangelist(repo, nil, cl)
	require.NoError(t, err)

	require.Len(t, tgts.Signed.Delegations.Roles, 0)
	require.Len(t, tgts.Signed.Delegations.Keys, 0)
}

func TestApplyTargetsDelegationCreate2SharedKey(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	cl := NewMemChangelist()
	w := NewWriter(cl, nil)

	newKey, err := cs.Create("targets/level1", "docker.com/notary", data.ED25519Key)
	require.NoError(t, err)

	require.NoError(t, w.AddDelegation("targets/level1", []data.PublicKey{newKey}, []string{"level1"}))
	require.NoError(t, w.AddDelegation("targets/level2", []data.PublicKey{newKey}, []string{"level2"}))

	err = ApplyChangelist(repo, nil, cl)
	require.NoError(t, err)

	tgts := repo.Targets[data.CanonicalTargetsRole]
	require.Len(t, tgts.Signed.Delegations.Roles, 2)
	require.Len(t, tgts.Signed.Delegations.Keys, 1)

	role1 := tgts.Signed.Delegations.Roles[0]
	require.Len(t, role1.KeyIDs, 1)
	require.Equal(t, newKey.ID(), role1.KeyIDs[0])
	require.Equal(t, "targets/level1", role1.Name)
	require.Equal(t, "level1", role1.Paths[0])

	role2 := tgts.Signed.Delegations.Roles[1]
	require.Len(t, role2.KeyIDs, 1)
	require.Equal(t, newKey.ID(), role2.KeyIDs[0])
	require.Equal(t, "targets/level2", role2.Name)
	require.Equal(t, "level2", role2.Paths[0])

	// delete one delegation, ensure shared key remains
	require.NoError(t, cl.Clear(""))
	require.NoError(t, w.RemoveDelegationRole("targets/level1"))
	err = ApplyChangelist(repo, nil, cl)
	require.NoError(t, err)

	require.Len(t, tgts.Signed.Delegations.Roles, 1)
	require.Len(t, tgts.Signed.Delegations.Keys, 1)

	// delete other delegation, ensure key cleaned up
	require.NoError(t, cl.Clear(""))
	require.NoError(t, w.RemoveDelegationRole("targets/level2"))
	err = ApplyChangelist(repo, nil, cl)
	require.NoError(t, err)

	require.Len(t, tgts.Signed.Delegations.Roles, 0)
	require.Len(t, tgts.Signed.Delegations.Keys, 0)
}

func TestApplyTargetsDelegationCreateEdit(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	cl := NewMemChangelist()
	w := NewWriter(cl, nil)

	newKey, err := cs.Create("targets/level1", "docker.com/notary", data.ED25519Key)
	require.NoError(t, err)

	// create delegation
	require.NoError(t, w.AddDelegation("targets/level1", []data.PublicKey{newKey}, []string{"level1"}))

	err = ApplyChangelist(repo, nil, cl)
	require.NoError(t, err)

	newKey2, err := cs.Create("targets/level1", "docker.com/notary", data.ED25519Key)
	require.NoError(t, err)

	// edit delegation
	require.NoError(t, cl.Clear(""))
	require.NoError(t, w.AddDelegationRoleAndKeys("targets/level1", []data.PublicKey{newKey2}))
	require.NoError(t, w.RemoveDelegationKeys("targets/level1", []string{newKey.ID()}))

	err = ApplyChangelist(repo, nil, cl)
	require.NoError(t, err)

	tgts := repo.Targets[data.CanonicalTargetsRole]
	require.Len(t, tgts.Signed.Delegations.Roles, 1)
	require.Len(t, tgts.Signed.Delegations.Keys, 1)

	_, ok := tgts.Signed.Delegations.Keys[newKey2.ID()]
	require.True(t, ok)

	role := tgts.Signed.Delegations.Roles[0]
	require.Len(t, role.KeyIDs, 1)
	require.Equal(t, newKey2.ID(), role.KeyIDs[0])
	require.Equal(t, "targets/level1", role.Name)
	require.Equal(t, "level1", role.Paths[0])
}

func TestApplyTargetsDelegationEditNonExisting(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	cl := NewMemChangelist()
	w := NewWriter(cl, nil)

	newKey, err := cs.Create("targets/level1", "docker.com/notary", data.ED25519Key)
	require.NoError(t, err)

	// have to create a change, because `AddDelegation*` makes a create
	// delegation change
	kl := data.KeyList{newKey}
	td := &TUFDelegation{
		NewThreshold: 1,
		AddKeys:      kl,
		AddPaths:     []string{"level1"},
	}

	tdJSON, err := json.Marshal(td)
	require.NoError(t, err)

	require.NoError(t, cl.Add(newUpdateDelegationChange("targets/level1", tdJSON)))

	err = ApplyChangelist(repo, nil, cl)
	require.Error(t, err)
	require.IsType(t, data.ErrInvalidRole{}, err)

	require.NoError(t, cl.Clear(""))
	require.NoError(t, w.RemoveDelegationKeys("targets/level1", []string{newKey.ID()}))

	err = ApplyChangelist(repo, nil, cl)
	require.Error(t, err)
	require.IsType(t, data.ErrInvalidRole{}, err)
}

func TestApplyTargetsDelegationCreateAlreadyExisting(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	cl := NewMemChangelist()
	w := NewWriter(cl, nil)

	newKey, err := cs.Create("targets/level1", "docker.com/notary", data.ED25519Key)
	require.NoError(t, err)

	// create delegation
	require.NoError(t, w.AddDelegation("targets/level1", []data.PublicKey{newKey}, []string{"level1"}))

	err = ApplyChangelist(repo, nil, cl)
	require.NoError(t, err)
	require.NoError(t, cl.Clear(""))

	// we have sufficient checks elsewhere we don't need to confirm that
	// creating fresh works here via more requires.
	extraKey, err := cs.Create("targets/level1", "docker.com/notary", data.ED25519Key)
	require.NoError(t, err)

	// create delegation again
	require.NoError(t, w.AddDelegation("targets/level1", []data.PublicKey{extraKey}, []string{"level1"}))

	// when attempting to create the same role again, check that we added a key
	err = ApplyChangelist(repo, nil, cl)
	require.NoError(t, err)
	delegation, err := repo.GetDelegationRole("targets/level1")
	require.NoError(t, err)
	require.Contains(t, delegation.Paths, "level1")
	require.Equal(t, len(delegation.ListKeyIDs()), 2)
}

func TestApplyTargetsDelegationAlreadyExistingMergePaths(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	cl := NewMemChangelist()
	w := NewWriter(cl, nil)

	newKey, err := cs.Create("targets/level1", "docker.com/notary", data.ED25519Key)
	require.NoError(t, err)

	// create delegation
	require.NoError(t, w.AddDelegation("targets/level1", []data.PublicKey{newKey}, []string{"level1"}))

	err = ApplyChangelist(repo, nil, cl)
	require.NoError(t, err)
	require.NoError(t, cl.Clear(""))

	// we have sufficient checks elsewhere we don't need to confirm that
	// creating fresh works here via more requires.

	// Use different path for this changelist
	require.NoError(t, w.AddDelegation("targets/level1", []data.PublicKey{newKey}, []string{"level2"}))

	// when attempting to create the same role again, check that we
	// merged with previous details
	err = ApplyChangelist(repo, nil, cl)
	require.NoError(t, err)
	delegation, err := repo.GetDelegationRole("targets/level1")
	require.NoError(t, err)
	// Assert we have both paths
	require.Contains(t, delegation.Paths, "level2")
	require.Contains(t, delegation.Paths, "level1")
	// keys have not changed
	require.Equal(t, len(delegation.ListKeyIDs()), 1)
}

func TestAddRemoveDelegationInvalidRole(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	cl := NewMemChangelist()
	w := NewWriter(cl, nil)

	newKey, err := cs.Create("targets/level1", "docker.com/notary", data.ED25519Key)
	require.NoError(t, err)

	invalidRoles := []string{
		data.CanonicalRootRole,
		data.CanonicalSnapshotRole,
		data.CanonicalTimestampRole,
		"target/otherrole",
		"otherrole",
		"TARGETS/ALLCAPSROLE",
	}

	for _, role := range invalidRoles {
		require.NoError(t, cl.Clear(""))

		// writer won't let you create the delegation, edit the delegation, or remove the delegation
		for _, err := range []error{
			w.AddDelegation(role, []data.PublicKey{newKey}, []string{"level1"}),
			w.AddDelegationPaths(role, []string{"level1"}),
			w.AddDelegationRoleAndKeys(role, []data.PublicKey{newKey}),
			w.RemoveDelegationRole(role),
			w.RemoveDelegationPaths(role, []string{"level1"}),
			w.RemoveDelegationKeys(role, []string{newKey.ID()}),
			w.RemoveDelegationKeysAndPaths(role, []string{newKey.ID()}, []string{"level1"}),
		} {
			require.Error(t, err)
			require.IsType(t, data.ErrInvalidRole{}, err)
			require.Empty(t, cl.List())
		}

		// create delegation manually to apply, to ensure that application will also fail
		kl := data.KeyList{newKey}
		td := &TUFDelegation{
			NewThreshold: 1,
			AddKeys:      kl,
			AddPaths:     []string{"level1"},
		}

		tdJSON, err := json.Marshal(td)
		require.NoError(t, err)

		require.NoError(t, cl.Add(newCreateDelegationChange(role, tdJSON)))

		err = ApplyChangelist(repo, nil, cl)
		require.Error(t, err)

		require.NoError(t, cl.Clear(""))

		require.NoError(t, cl.Add(newDeleteDelegationChange(role, nil)))

		err = ApplyChangelist(repo, nil, cl)
		require.Error(t, err)
	}
}

func TestApplyTargetsDelegationInvalidJSONContent(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	cl := NewMemChangelist()

	newKey, err := cs.Create("targets/level1", "docker.com/notary", data.ED25519Key)
	require.NoError(t, err)

	// create delegation
	kl := data.KeyList{newKey}
	td := &TUFDelegation{
		NewThreshold: 1,
		AddKeys:      kl,
		AddPaths:     []string{"level1"},
	}

	tdJSON, err := json.Marshal(td)
	require.NoError(t, err)

	require.NoError(t, cl.Add(newCreateDelegationChange("targets/level1", tdJSON[1:])))

	err = ApplyChangelist(repo, nil, cl)
	require.Error(t, err)
	require.IsType(t, &json.SyntaxError{}, err)
}

func TestApplyTargetsDelegationInvalidAction(t *testing.T) {
	repo, _, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	cl := NewMemChangelist()
	ch := NewTUFChange(
		"bad action",
		"targets/level1",
		TypeTargetsDelegation,
		"",
		nil,
	)

	require.NoError(t, cl.Add(ch))

	err = ApplyChangelist(repo, nil, cl)
	require.Error(t, err)
}

func TestApplyTargetsChangeInvalidType(t *testing.T) {
	repo, _, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	cl := NewMemChangelist()
	ch := NewTUFChange(
		ActionCreate,
		"targets/level1",
		"badType",
		"",
		nil,
	)

	require.NoError(t, cl.Add(ch))

	err = ApplyChangelist(repo, nil, cl)
	require.Error(t, err)
}

func TestApplyTargetsDelegationCreate2Deep(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	cl := NewMemChangelist()
	w := NewWriter(cl, nil)

	newKey, err := cs.Create("targets/level1", "docker.com/notary", data.ED25519Key)
	require.NoError(t, err)

	// create delegation
	require.NoError(t, w.AddDelegation("targets/level1", []data.PublicKey{newKey}, []string{"level1"}))

	err = ApplyChangelist(repo, nil, cl)
	require.NoError(t, err)
	require.NoError(t, cl.Clear(""))

	tgts := repo.Targets[data.CanonicalTargetsRole]
	require.Len(t, tgts.Signed.Delegations.Roles, 1)
	require.Len(t, tgts.Signed.Delegations.Keys, 1)

	_, ok := tgts.Signed.Delegations.Keys[newKey.ID()]
	require.True(t, ok)

	role := tgts.Signed.Delegations.Roles[0]
	require.Len(t, role.KeyIDs, 1)
	require.Equal(t, newKey.ID(), role.KeyIDs[0])
	require.Equal(t, "targets/level1", role.Name)
	require.Equal(t, "level1", role.Paths[0])

	// init delegations targets file. This would be done as part of a publish
	// operation
	repo.InitTargets("targets/level1")

	require.NoError(t, w.AddDelegation("targets/level1/level2", []data.PublicKey{newKey}, []string{"level1/level2"}))

	err = ApplyChangelist(repo, nil, cl)
	require.NoError(t, err)

	tgts = repo.Targets["targets/level1"]
	require.Len(t, tgts.Signed.Delegations.Roles, 1)
	require.Len(t, tgts.Signed.Delegations.Keys, 1)

	_, ok = tgts.Signed.Delegations.Keys[newKey.ID()]
	require.True(t, ok)

	role = tgts.Signed.Delegations.Roles[0]
	require.Len(t, role.KeyIDs, 1)
	require.Equal(t, newKey.ID(), role.KeyIDs[0])
	require.Equal(t, "targets/level1/level2", role.Name)
	require.Equal(t, "level1/level2", role.Paths[0])
}

// Applying a delegation whose parent doesn't exist fails.
func TestApplyTargetsDelegationParentDoesntExist(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	cl := NewMemChangelist()
	w := NewWriter(cl, nil)

	// make sure a key exists for the previous level, so it's not a missing
	// key error, but we don't care about this key
	_, err = cs.Create("targets/level1", "docker.com/notary", data.ED25519Key)
	require.NoError(t, err)

	newKey, err := cs.Create("targets/level1/level2", "docker.com/notary", data.ED25519Key)
	require.NoError(t, err)

	// create delegation
	require.NoError(t, w.AddDelegation("targets/level1/level2", []data.PublicKey{newKey}, nil))

	err = ApplyChangelist(repo, nil, cl)
	require.Error(t, err)
	require.IsType(t, data.ErrInvalidRole{}, err)
}

// If there is no delegation target, ApplyTargets creates it
func TestApplyChangelistCreatesDelegation(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	cl := NewMemChangelist()
	w := NewWriter(cl, nil)

	newKey, err := cs.Create("targets/level1", "docker.com/notary", data.ED25519Key)
	require.NoError(t, err)

	err = repo.UpdateDelegationKeys("targets/level1", []data.PublicKey{newKey}, []string{}, 1)
	require.NoError(t, err)
	err = repo.UpdateDelegationPaths("targets/level1", []string{""}, []string{}, false)
	require.NoError(t, err)
	delete(repo.Targets, "targets/level1")

	require.NoError(t, w.AddTarget("latest", fakeMeta, "targets/level1"))

	err = ApplyChangelist(repo, nil, cl)
	require.NoError(t, err)

	_, ok := repo.Targets["targets/level1"]
	require.True(t, ok, "Failed to create the delegation target")
	_, ok = repo.Targets["targets/level1"].Signed.Targets["latest"]
	require.True(t, ok, "Failed to write change to delegation target")
}

// Each change applies only to the role specified
func TestApplyChangelistTargetsToMultipleRoles(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	cl := NewMemChangelist()
	w := NewWriter(cl, nil)

	newKey, err := cs.Create("targets/level1", "docker.com/notary", data.ED25519Key)
	require.NoError(t, err)

	err = repo.UpdateDelegationKeys("targets/level1", []data.PublicKey{newKey}, []string{}, 1)
	require.NoError(t, err)
	err = repo.UpdateDelegationPaths("targets/level1", []string{""}, []string{}, false)
	require.NoError(t, err)

	err = repo.UpdateDelegationKeys("targets/level2", []data.PublicKey{newKey}, []string{}, 1)
	require.NoError(t, err)
	err = repo.UpdateDelegationPaths("targets/level2", []string{""}, []string{}, false)
	require.NoError(t, err)

	require.NoError(t, w.AddTarget("latest", fakeMeta, "targets/level1"))
	require.NoError(t, w.RemoveTarget("latest", "targets/level2"))

	err = ApplyChangelist(repo, nil, cl)
	require.NoError(t, err)

	_, ok := repo.Targets["targets/level1"].Signed.Targets["latest"]
	require.True(t, ok)
	_, ok = repo.Targets["targets/level2"]
	require.False(t, ok, "no change to targets/level2, so metadata not created")

	require.NoError(t, w.AddTarget("latest", fakeMeta, "targets/level2"))
	err = ApplyChangelist(repo, nil, cl)
	require.NoError(t, err)
	for _, role := range []string{"targets/level1", "targets/level2"} {
		_, ok := repo.Targets[role].Signed.Targets["latest"]
		require.True(t, ok)
	}

	require.NoError(t, w.RemoveTarget("latest", "targets/level1"))
	err = ApplyChangelist(repo, nil, cl)
	require.NoError(t, err)

	_, ok = repo.Targets["targets/level1"].Signed.Targets["latest"]
	require.False(t, ok, "level 1 was removed")
	_, ok = repo.Targets["targets/level2"]
	require.True(t, ok, "no change to targets/level2")
}

// RemoveDelegationKeys produces a change that will actually remove
// the delegation from the repo.
func TestRemoveDelegationChangefileApplicable(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	cl := NewMemChangelist()
	w := NewWriter(cl, nil)

	newKey, err := cs.Create("targets/a", "docker.com/notary", data.ED25519Key)
	require.NoError(t, err)

	// add a delegation first so it can be removed
	require.NoError(t, w.AddDelegation("targets/a", []data.PublicKey{newKey}, []string{""}))

	err = ApplyChangelist(repo, nil, cl)
	require.NoError(t, err)
	require.NoError(t, cl.Clear(""))

	targetRole := repo.Targets[data.CanonicalTargetsRole]
	require.Len(t, targetRole.Signed.Delegations.Roles, 1)
	require.Len(t, targetRole.Signed.Delegations.Keys, 1)

	// now remove it
	require.NoError(t, w.RemoveDelegationKeys("targets/a", []string{newKey.ID()}))

	err = ApplyChangelist(repo, nil, cl)
	require.NoError(t, err)

	targetRole = repo.Targets[data.CanonicalTargetsRole]
	require.Len(t, targetRole.Signed.Delegations.Roles, 1)
	require.Empty(t, targetRole.Signed.Delegations.Keys)
}

// ApplyTargets fails when adding or deleting a change to a nonexistent, but valid, delegation
func TestApplyChangelistTargetsFailsNonexistentValidRole(t *testing.T) {
	repo, _, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	cl := NewMemChangelist()
	w := NewWriter(cl, nil)

	require.NoError(t, w.AddTarget("latest", fakeMeta, "targets/level1/level2/level3/level4"))

	err = ApplyChangelist(repo, nil, cl)
	require.Error(t, err)
	require.IsType(t, data.ErrInvalidRole{}, err)
	require.NoError(t, cl.Clear(""))

	// now try a delete and assert the same error
	require.NoError(t, w.RemoveTarget("latest", "targets/level1/level2/level3/level4"))

	err = ApplyChangelist(repo, nil, cl)
	require.Error(t, err)
	require.IsType(t, data.ErrInvalidRole{}, err)
}

// AddTarget/RemoveTarget fails with ErrInvalidRole if role is invalid
func TestAddRemoveTargetMetaFailsInvalidRole(t *testing.T) {
	repo, _, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	invalidRoles := []string{
		data.CanonicalRootRole,
		data.CanonicalSnapshotRole,
		data.CanonicalTimestampRole,
		"target/otherrole",
		"otherrole",
		"TARGETS/ALLCAPSROLE",
	}

	cl := NewMemChangelist()
	w := NewWriter(cl, nil)

	for _, role := range invalidRoles {
		cl.Clear("")

		// AddTarget won't even let you add to an invalid role
		err = w.AddTarget("latest", fakeMeta, role)
		require.Error(t, err)
		require.IsType(t, data.ErrInvalidRole{}, err)
		require.Empty(t, cl.List())

		// Neither will remove target
		err = w.RemoveTarget("latest", role)
		require.Error(t, err)
		require.IsType(t, data.ErrInvalidRole{}, err)
		require.Empty(t, cl.List())

		fjson, err := json.Marshal(fakeMeta)
		require.NoError(t, err)

		// manually create an invalid AddTarget and RemoveTarget to prove they fail to apply
		require.NoError(t, cl.Add(&TUFChange{
			Actn:       ActionCreate,
			Role:       role,
			ChangeType: "target",
			ChangePath: "latest",
			Data:       fjson,
		}))

		require.Error(t, ApplyChangelist(repo, nil, cl))
		require.NoError(t, cl.Clear(""))

		// manually create an invalid AddTarget and RemoveTarget to prove they fail to apply
		require.NoError(t, cl.Add(&TUFChange{
			Actn:       ActionDelete,
			Role:       role,
			ChangeType: "target",
			ChangePath: "latest",
		}))

		require.Error(t, ApplyChangelist(repo, nil, cl))
	}
}

// If applying a change fails due to a prefix error, AddTarget fails outright
func TestAddTargetMetaFailsIfPrefixError(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	cl := NewMemChangelist()
	w := NewWriter(cl, nil)

	newKey, err := cs.Create("targets/level1", "docker.com/notary", data.ED25519Key)
	require.NoError(t, err)

	err = repo.UpdateDelegationKeys("targets/level1", []data.PublicKey{newKey}, []string{}, 1)
	require.NoError(t, err)
	err = repo.UpdateDelegationPaths("targets/level1", []string{"pathprefix"}, []string{}, false)
	require.NoError(t, err)

	require.NoError(t, w.AddTarget("notPathPrefix", fakeMeta, "targets/level1"))

	err = ApplyChangelist(repo, nil, cl)
	require.Error(t, err)

	// no target in targets or targets/latest
	require.Empty(t, repo.Targets[data.CanonicalTargetsRole].Signed.Targets)
	require.Empty(t, repo.Targets["targets/level1"].Signed.Targets)
}

func TestWriterErrorsPropagated(t *testing.T) {
	changeDir, err := ioutil.TempDir("", "changlist-tests")
	require.NoError(t, err)
	defer os.RemoveAll(changeDir)

	pubKey := data.NewED25519PublicKey([]byte("fake"))

	cl, err := NewFileChangelist(changeDir)
	require.NoError(t, err)
	w := NewWriter(cl, nil)

	// make changedir unwritable
	require.NoError(t, os.Chmod(changeDir, 0600))

	require.Error(t, w.AddTarget("latest", fakeMeta))
	require.Error(t, w.RemoveTarget("latest"))
	require.Error(t, w.AddDelegation("targets/level1", []data.PublicKey{pubKey}, []string{""}))
	require.Error(t, w.AddDelegationPaths("targets/level1", []string{"level1"}))
	require.Error(t, w.AddDelegationRoleAndKeys("targets/level1", []data.PublicKey{pubKey}))
	require.Error(t, w.RemoveDelegationKeysAndPaths("targets/level1", []string{pubKey.ID()}, []string{""}))
	require.Error(t, w.RemoveDelegationKeys("targets/level1", []string{pubKey.ID()}))
	require.Error(t, w.RemoveDelegationPaths("targets/level1", []string{"level1"}))
	require.Error(t, w.RemoveDelegationRole("targets/level1"))
	require.Error(t, w.ClearDelegationPaths("targets/level1"))
}

// ClearAllPaths removes all paths from the specified delegation in the repo
func TestClearAllPathsDelegationChangefileApplicable(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	cl := NewMemChangelist()
	w := NewWriter(cl, nil)

	newKey, err := cs.Create("targets/a", "docker.com/notary", data.ED25519Key)
	require.NoError(t, err)

	// create delegation
	require.NoError(t, w.AddDelegation("targets/a", []data.PublicKey{newKey}, []string{"level1", "level2", "level3"}))

	err = ApplyChangelist(repo, nil, cl)
	require.NoError(t, err)
	require.NoError(t, cl.Clear(""))

	// now clear paths it
	require.NoError(t, w.ClearDelegationPaths("targets/a"))

	err = ApplyChangelist(repo, nil, cl)
	require.NoError(t, err)

	delgRoles := repo.Targets[data.CanonicalTargetsRole].Signed.Delegations.Roles
	require.Len(t, delgRoles, 1)
	require.Len(t, delgRoles[0].Paths, 0)
}
