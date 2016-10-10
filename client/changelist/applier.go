package changelist

import (
	"encoding/json"
	"fmt"

	"github.com/Sirupsen/logrus"
	"github.com/docker/notary/tuf"
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/utils"
)

// ApplyChangelist applies a changelist to a tuf.Repo
func ApplyChangelist(repo *tuf.Repo, invalid *tuf.Repo, cl Changelist) error {
	it, err := cl.NewIterator()
	if err != nil {
		return err
	}
	index := 0
	for it.HasNext() {
		c, err := it.Next()
		if err != nil {
			return err
		}
		isDel := data.IsDelegation(c.Scope()) || data.IsWildDelegation(c.Scope())
		switch {
		case c.Scope() == ScopeTargets || isDel:
			err = applyTargetsChange(repo, invalid, c)
		case c.Scope() == ScopeRoot:
			err = applyRootChange(repo, c)
		default:
			return fmt.Errorf("scope not supported: %s", c.Scope())
		}
		if err != nil {
			logrus.Debugf("error attempting to apply change #%d: %s, on scope: %s path: %s type: %s", index, c.Action(), c.Scope(), c.Path(), c.Type())
			return err
		}
		index++
	}
	logrus.Debugf("applied %d change(s)", index)
	return nil
}

func applyTargetsChange(repo *tuf.Repo, invalid *tuf.Repo, c Change) error {
	switch c.Type() {
	case TypeTargetsTarget:
		return changeTargetMeta(repo, c)
	case TypeTargetsDelegation:
		return changeTargetsDelegation(repo, c)
	case TypeWitness:
		return witnessTargets(repo, invalid, c.Scope())
	default:
		return fmt.Errorf("only target meta and delegations changes supported")
	}
}

func changeTargetsDelegation(repo *tuf.Repo, c Change) error {
	switch c.Action() {
	case ActionCreate:
		td := TUFDelegation{}
		err := json.Unmarshal(c.Content(), &td)
		if err != nil {
			return err
		}

		// Try to create brand new role or update one
		// First add the keys, then the paths.  We can only add keys and paths in this scenario
		err = repo.UpdateDelegationKeys(c.Scope(), td.AddKeys, []string{}, td.NewThreshold)
		if err != nil {
			return err
		}
		return repo.UpdateDelegationPaths(c.Scope(), td.AddPaths, []string{}, false)
	case ActionUpdate:
		td := TUFDelegation{}
		err := json.Unmarshal(c.Content(), &td)
		if err != nil {
			return err
		}
		if data.IsWildDelegation(c.Scope()) {
			return repo.PurgeDelegationKeys(c.Scope(), td.RemoveKeys)
		}

		delgRole, err := repo.GetDelegationRole(c.Scope())
		if err != nil {
			return err
		}

		// We need to translate the keys from canonical ID to TUF ID for compatibility
		canonicalToTUFID := make(map[string]string)
		for tufID, pubKey := range delgRole.Keys {
			canonicalID, err := utils.CanonicalKeyID(pubKey)
			if err != nil {
				return err
			}
			canonicalToTUFID[canonicalID] = tufID
		}

		removeTUFKeyIDs := []string{}
		for _, canonID := range td.RemoveKeys {
			removeTUFKeyIDs = append(removeTUFKeyIDs, canonicalToTUFID[canonID])
		}

		err = repo.UpdateDelegationKeys(c.Scope(), td.AddKeys, removeTUFKeyIDs, td.NewThreshold)
		if err != nil {
			return err
		}
		return repo.UpdateDelegationPaths(c.Scope(), td.AddPaths, td.RemovePaths, td.ClearAllPaths)
	case ActionDelete:
		return repo.DeleteDelegation(c.Scope())
	default:
		return fmt.Errorf("unsupported action against delegations: %s", c.Action())
	}

}

func changeTargetMeta(repo *tuf.Repo, c Change) error {
	var err error
	switch c.Action() {
	case ActionCreate:
		logrus.Debug("changelist add: ", c.Path())
		meta := &data.FileMeta{}
		err = json.Unmarshal(c.Content(), meta)
		if err != nil {
			return err
		}
		files := data.Files{c.Path(): *meta}

		// Attempt to add the target to this role
		if _, err = repo.AddTargets(c.Scope(), files); err != nil {
			logrus.Errorf("couldn't add target to %s: %s", c.Scope(), err.Error())
		}

	case ActionDelete:
		logrus.Debug("changelist remove: ", c.Path())

		// Attempt to remove the target from this role
		if err = repo.RemoveTargets(c.Scope(), c.Path()); err != nil {
			logrus.Errorf("couldn't remove target from %s: %s", c.Scope(), err.Error())
		}

	default:
		err = fmt.Errorf("action not yet supported: %s", c.Action())
	}
	return err
}

func applyRootChange(repo *tuf.Repo, c Change) error {
	var err error
	switch c.Type() {
	case TypeBaseRole:
		err = applyRootRoleChange(repo, c)
	default:
		err = fmt.Errorf("type of root change not yet supported: %s", c.Type())
	}
	return err // might be nil
}

func applyRootRoleChange(repo *tuf.Repo, c Change) error {
	switch c.Action() {
	case ActionCreate:
		// replaces all keys for a role
		d := &TUFRootData{}
		err := json.Unmarshal(c.Content(), d)
		if err != nil {
			return err
		}
		err = repo.ReplaceBaseKeys(d.RoleName, d.Keys...)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("action not yet supported for root: %s", c.Action())
	}
	return nil
}

func witnessTargets(repo *tuf.Repo, invalid *tuf.Repo, role string) error {
	if r, ok := repo.Targets[role]; ok {
		// role is already valid, mark for re-signing/updating
		r.Dirty = true
		return nil
	}

	if roleObj, err := repo.GetDelegationRole(role); err == nil && invalid != nil {
		// A role with a threshold > len(keys) is technically invalid, but we let it build in the builder because
		// we want to be able to download the role (which may still have targets on it), add more keys, and then
		// witness the role, thus bringing it back to valid.  However, if no keys have been added before witnessing,
		// then it is still an invalid role, and can't be witnessed because nothing can bring it back to valid.
		if roleObj.Threshold > len(roleObj.Keys) {
			return data.ErrInvalidRole{
				Role:   role,
				Reason: "role does not specify enough valid signing keys to meet its required threshold",
			}
		}
		if r, ok := invalid.Targets[role]; ok {
			// role is recognized but invalid, move to valid data and mark for re-signing
			repo.Targets[role] = r
			r.Dirty = true
			return nil
		}
	}
	// role isn't recognized, even as invalid
	return data.ErrInvalidRole{
		Role:   role,
		Reason: "this role is not known",
	}
}
