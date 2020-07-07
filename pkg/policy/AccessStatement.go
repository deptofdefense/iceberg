// =================================================================
//
// Work of the U.S. Department of Defense, Defense Digital Service.
// Released as open source under the MIT License.  See LICENSE file.
//
// =================================================================

package policy

import (
	"errors"
	"fmt"
)

type AccessStatement struct {
	ID       string   `json:"id" yaml:"id"`
	Effect   string   `json:"effect" yaml:"effect"`
	Paths    []string `json:"paths" yaml:"paths"`
	Users    []string `json:"users,omitempty" yaml:"users,omitempty"`
	NotUsers []string `json:"not_users,omitempty" yaml:"not_users,omitempty"`
}

func (s AccessStatement) Clone() AccessStatement {
	return AccessStatement{
		ID:       s.ID,
		Effect:   s.Effect,
		Paths:    append([]string{}, s.Paths...),
		Users:    append([]string{}, s.Users...),
		NotUsers: append([]string{}, s.NotUsers...),
	}
}

func (s AccessStatement) Validate() error {
	if s.Effect != Allow && s.Effect != Deny {
		return fmt.Errorf("invalid effect %q, expecting %q or %q", s.Effect, Allow, Deny)
	}
	if len(s.Paths) == 0 {
		return errors.New("missing paths, expecting at least one path")
	}
	if len(s.Users) == 0 && len(s.NotUsers) == 0 {
		return errors.New("missing users and not users, only one of either users or not users must be set")
	}
	if len(s.Users) > 0 && len(s.NotUsers) > 0 {
		return errors.New("users and not users are both set, only one of either users or not users must be set")
	}
	return nil
}

func (s AccessStatement) MatchPath(path string) bool {
	for _, candidate := range s.Paths {
		if Match(candidate, path) {
			return true
		}
	}
	return false
}

func (s AccessStatement) MatchUser(user *User) bool {
	dn := user.DistinguishedName()
	for _, candidate := range s.Users {
		if Match(candidate, dn) {
			return true
		}
	}
	return false
}

func (s AccessStatement) MatchNotUser(user *User) bool {
	dn := user.DistinguishedName()
	for _, candidate := range s.NotUsers {
		if Match(candidate, dn) {
			return false
		}
	}
	return true
}
