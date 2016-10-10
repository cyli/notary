package changelist

import (
	"encoding/json"
	"fmt"

	"github.com/Sirupsen/logrus"
	"github.com/docker/notary"
	"github.com/docker/notary/tuf/data"
)

// Writer adds new changes to a changelist
type Writer struct {
	cl     Changelist
	logger logrus.FieldLogger
}

// NewWriter makes a writer that writes to the givne changelist and logs to the given logger,
// or logrus if no logger is provided
func NewWriter(cl Changelist, logger logrus.FieldLogger) Writer {
	if logger == nil {
		logger = logrus.StandardLogger()
	}
	return Writer{cl: cl, logger: logger}
}

// adds a TUF Change template to the given roles
func (w Writer) addChange(c Change, roles ...string) error {
	if len(roles) == 0 {
		roles = []string{data.CanonicalTargetsRole}
	}

	var changes []Change
	for _, role := range roles {
		// Ensure we can only add targets to the CanonicalTargetsRole,
		// or a Delegation role (which is <CanonicalTargetsRole>/something else)
		if role != data.CanonicalTargetsRole && !data.IsDelegation(role) && !data.IsWildDelegation(role) {
			return data.ErrInvalidRole{
				Role:   role,
				Reason: "cannot add targets to this role",
			}
		}

		changes = append(changes, NewTUFChange(
			c.Action(),
			role,
			c.Type(),
			c.Path(),
			c.Content(),
		))
	}

	for _, c := range changes {
		if err := w.cl.Add(c); err != nil {
			return err
		}
	}
	return nil
}

// AddTarget creates new changelist entries to add a target to the given roles
// in the repository when the changelist gets applied at publish time.
// If roles are unspecified, the default role is "targets"
func (w Writer) AddTarget(name string, meta data.FileMeta, roles ...string) error {
	if len(meta.Hashes) == 0 {
		return fmt.Errorf("no hashes specified for target \"%s\"", name)
	}
	w.logger.Debugf("Adding target \"%s\" with sha256 \"%x\" and size %d bytes.\n", name, meta.Hashes["sha256"], meta.Length)

	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return err
	}

	template := NewTUFChange(ActionCreate, "", TypeTargetsTarget, name, metaJSON)
	return w.addChange(template, roles...)
}

// RemoveTarget creates new changelist entries to remove a target from the given
// roles in the repository when the changelist gets applied at publish time.
// If roles are unspecified, the default role is "target".
func (w Writer) RemoveTarget(targetName string, roles ...string) error {
	w.logger.Debugf("Removing target \"%s\"", targetName)
	template := NewTUFChange(ActionDelete, "",
		TypeTargetsTarget, targetName, nil)
	return w.addChange(template, roles...)
}

// AddDelegation creates changelist entries to add provided delegation public keys and paths.
// This method composes AddDelegationRoleAndKeys and AddDelegationPaths (each creates one changelist if called).
func (w Writer) AddDelegation(name string, delegationKeys []data.PublicKey, paths []string) error {
	if len(delegationKeys) > 0 {
		if err := w.AddDelegationRoleAndKeys(name, delegationKeys); err != nil {
			return err
		}
	}
	if len(paths) > 0 {
		if err := w.AddDelegationPaths(name, paths); err != nil {
			return err
		}
	}
	return nil
}

// AddDelegationRoleAndKeys creates a changelist entry to add provided delegation public keys.
// This method is the simplest way to create a new delegation, because the delegation must have at least
// one key upon creation to be valid since we will reject the changelist while validating the threshold.
func (w Writer) AddDelegationRoleAndKeys(name string, delegationKeys []data.PublicKey) error {
	if !data.IsDelegation(name) {
		return data.ErrInvalidRole{Role: name, Reason: "invalid delegation role name"}
	}

	w.logger.Debugf(`Adding delegation "%s" with threshold %d, and %d keys\n`,
		name, notary.MinThreshold, len(delegationKeys))

	// Defaulting to threshold of 1, since we don't allow for larger thresholds at the moment.
	tdJSON, err := json.Marshal(&TUFDelegation{
		NewThreshold: notary.MinThreshold,
		AddKeys:      data.KeyList(delegationKeys),
	})
	if err != nil {
		return err
	}

	template := newCreateDelegationChange(name, tdJSON)
	return w.addChange(template, name)
}

// AddDelegationPaths creates a changelist entry to add provided paths to an existing delegation.
// This method cannot create a new delegation itself because the role must meet the key threshold upon creation.
func (w Writer) AddDelegationPaths(name string, paths []string) error {
	if !data.IsDelegation(name) {
		return data.ErrInvalidRole{Role: name, Reason: "invalid delegation role name"}
	}

	w.logger.Debugf(`Adding %s paths to delegation %s\n`, paths, name)

	tdJSON, err := json.Marshal(&TUFDelegation{
		AddPaths: paths,
	})
	if err != nil {
		return err
	}

	template := newCreateDelegationChange(name, tdJSON)
	return w.addChange(template, name)
}

// RemoveDelegationKeysAndPaths creates changelist entries to remove provided delegation key IDs and paths.
// This method composes RemoveDelegationPaths and RemoveDelegationKeys (each creates one changelist if called).
func (w Writer) RemoveDelegationKeysAndPaths(name string, keyIDs, paths []string) error {
	if len(paths) > 0 {
		err := w.RemoveDelegationPaths(name, paths)
		if err != nil {
			return err
		}
	}
	if len(keyIDs) > 0 {
		err := w.RemoveDelegationKeys(name, keyIDs)
		if err != nil {
			return err
		}
	}
	return nil
}

// RemoveDelegationRole creates a changelist to remove all paths and keys from a role, and delete the role in its entirety.
func (w Writer) RemoveDelegationRole(name string) error {
	if !data.IsDelegation(name) {
		return data.ErrInvalidRole{Role: name, Reason: "invalid delegation role name"}
	}

	w.logger.Debugf(`Removing delegation "%s"\n`, name)

	template := newDeleteDelegationChange(name, nil)
	return w.addChange(template, name)
}

// RemoveDelegationPaths creates a changelist entry to remove provided paths from an existing delegation.
func (w Writer) RemoveDelegationPaths(name string, paths []string) error {
	if !data.IsDelegation(name) {
		return data.ErrInvalidRole{Role: name, Reason: "invalid delegation role name"}
	}

	w.logger.Debugf(`Removing %s paths from delegation "%s"\n`, paths, name)

	tdJSON, err := json.Marshal(&TUFDelegation{
		RemovePaths: paths,
	})
	if err != nil {
		return err
	}

	template := newUpdateDelegationChange(name, tdJSON)
	return w.addChange(template, name)
}

// RemoveDelegationKeys creates a changelist entry to remove provided keys from an existing delegation.
// When this changelist is applied, if the specified keys are the only keys left in the role,
// the role itself will be deleted in its entirety.
// It can also delete a key from all delegations under a parent using a name
// with a wildcard at the end.
func (w Writer) RemoveDelegationKeys(name string, keyIDs []string) error {
	if !data.IsDelegation(name) && !data.IsWildDelegation(name) {
		return data.ErrInvalidRole{Role: name, Reason: "invalid delegation role name"}
	}

	w.logger.Debugf(`Removing %s keys from delegation "%s"\n`, keyIDs, name)

	tdJSON, err := json.Marshal(&TUFDelegation{
		RemoveKeys: keyIDs,
	})
	if err != nil {
		return err
	}

	template := newUpdateDelegationChange(name, tdJSON)
	return w.addChange(template, name)
}

// ClearDelegationPaths creates a changelist entry to remove all paths from an existing delegation.
func (w Writer) ClearDelegationPaths(name string) error {
	if !data.IsDelegation(name) {
		return data.ErrInvalidRole{Role: name, Reason: "invalid delegation role name"}
	}

	w.logger.Debugf(`Removing all paths from delegation "%s"\n`, name)

	tdJSON, err := json.Marshal(&TUFDelegation{
		ClearAllPaths: true,
	})
	if err != nil {
		return err
	}

	template := newUpdateDelegationChange(name, tdJSON)
	return w.addChange(template, name)
}

// Witness creates change objects to witness (i.e. re-sign) the given
// roles on the next publish. One change is created per role
func (w Writer) Witness(roles ...string) ([]string, error) {
	successful := make([]string, 0, len(roles))
	var err error
	for _, role := range roles {
		// scope is role
		c := NewTUFChange(
			ActionUpdate,
			role,
			TypeWitness,
			"",
			nil,
		)
		if err = w.cl.Add(c); err != nil {
			break
		}
		successful = append(successful, role)
	}
	return successful, err
}

func newUpdateDelegationChange(name string, content []byte) *TUFChange {
	return NewTUFChange(
		ActionUpdate,
		name,
		TypeTargetsDelegation,
		"", // no path for delegations
		content,
	)
}

func newCreateDelegationChange(name string, content []byte) *TUFChange {
	return NewTUFChange(
		ActionCreate,
		name,
		TypeTargetsDelegation,
		"", // no path for delegations
		content,
	)
}

func newDeleteDelegationChange(name string, content []byte) *TUFChange {
	return NewTUFChange(
		ActionDelete,
		name,
		TypeTargetsDelegation,
		"", // no path for delegations
		content,
	)
}
