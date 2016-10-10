package client

import (
	"fmt"

	store "github.com/docker/notary/storage"
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/utils"
)

// GetDelegationRoles returns the keys and roles of the repository's delegations
// Also converts key IDs to canonical key IDs to keep consistent with signing prompts
func (r *NotaryRepository) GetDelegationRoles() ([]data.Role, error) {
	// Update state of the repo to latest
	if err := r.Update(false); err != nil {
		return nil, err
	}

	// All top level delegations (ex: targets/level1) are stored exclusively in targets.json
	_, ok := r.tufRepo.Targets[data.CanonicalTargetsRole]
	if !ok {
		return nil, store.ErrMetaNotFound{Resource: data.CanonicalTargetsRole}
	}

	// make a copy for traversing nested delegations
	allDelegations := []data.Role{}

	// Define a visitor function to populate the delegations list and translate their key IDs to canonical IDs
	delegationCanonicalListVisitor := func(tgt *data.SignedTargets, validRole data.DelegationRole) interface{} {
		// For the return list, update with a copy that includes canonicalKeyIDs
		// These aren't validated by the validRole
		canonicalDelegations, err := translateDelegationsToCanonicalIDs(tgt.Signed.Delegations)
		if err != nil {
			return err
		}
		allDelegations = append(allDelegations, canonicalDelegations...)
		return nil
	}
	err := r.tufRepo.WalkTargets("", "", delegationCanonicalListVisitor)
	if err != nil {
		return nil, err
	}
	return allDelegations, nil
}

func translateDelegationsToCanonicalIDs(delegationInfo data.Delegations) ([]data.Role, error) {
	canonicalDelegations := make([]data.Role, len(delegationInfo.Roles))
	// Do a copy by value to ensure local delegation metadata is untouched
	for idx, origRole := range delegationInfo.Roles {
		canonicalDelegations[idx] = *origRole
	}
	delegationKeys := delegationInfo.Keys
	for i, delegation := range canonicalDelegations {
		canonicalKeyIDs := []string{}
		for _, keyID := range delegation.KeyIDs {
			pubKey, ok := delegationKeys[keyID]
			if !ok {
				return []data.Role{}, fmt.Errorf("Could not translate canonical key IDs for %s", delegation.Name)
			}
			canonicalKeyID, err := utils.CanonicalKeyID(pubKey)
			if err != nil {
				return []data.Role{}, fmt.Errorf("Could not translate canonical key IDs for %s: %v", delegation.Name, err)
			}
			canonicalKeyIDs = append(canonicalKeyIDs, canonicalKeyID)
		}
		canonicalDelegations[i].KeyIDs = canonicalKeyIDs
	}
	return canonicalDelegations, nil
}
