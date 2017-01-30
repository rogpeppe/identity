// Copyright 2015 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package idmclient

import (
	"log"
	"strings"
	"time"

	"gopkg.in/errgo.v1"
)

// TODO unexport this type - it's best exposed as part of the client API only.

// PermChecker provides a way to query ACLs using the identity client.
type PermChecker struct {
	cache *GroupCache
}

// NewPermChecker returns a permission checker that uses the given
// identity client to check permissions. The following rules apply when
// checking if a user is a member of a name in an ACL. The PermChecker
// chooses whether to authorize the user u with respect to the ACL name n
// by following these rules:
//
// - If u is identical to n, authorization is granted.
// - If n is "everyone", authorization is granted.
// - If n is "everyone-local", authorization is granted if u does not have a domain.
// - If n is "everyone@$domain", authorization is granted if u has the domain $domain.
// - If n is "everyone-local@$domain", authorization is granted if if u is of the form
// "$username@$domain" where $username contains no @ characters.
// - Otherwise the identity server is consulted to find out whether authorization
// should be granted.
//
// It will cache results for at most cacheTime.
func NewPermChecker(c *Client, cacheTime time.Duration) *PermChecker {
	return &PermChecker{
		cache: NewGroupCache(c, cacheTime),
	}
}

// NewPermCheckerWithCache returns a new PermChecker using
// the given cache for its group queries.
func NewPermCheckerWithCache(cache *GroupCache) *PermChecker {
	return &PermChecker{
		cache: cache,
	}
}

// trivialAllow reports whether the username should be allowed
// access to the given ACL based on a superficial inspection
// of the ACL. If there is a definite answer, it will return
// a true isTrivial; otherwise it will return (false, false).
func trivialAllow(username string, acl []string) (allow, isTrivial bool) {
	if len(acl) == 0 {
		return false, true
	}
	allEveryone := true
	for _, name := range acl {
		if name == username {
			return true, true
		}
		suffix := strings.TrimPrefix(name, "everyone")
		if len(suffix) == len(name) {
			allEveryone = false
			continue
		}
		isLocal := false
		if s := strings.TrimPrefix(suffix, "-local"); len(s) != len(suffix) {
			isLocal = true
			suffix = s
		}
		if len(suffix) != 0 && suffix[0] != '@' {
			allEveryone = false
			// The special word doesn't end at a domain boundary or end of string.
			continue
		}
		domainPrefix := strings.TrimSuffix(username, suffix)
		if len(suffix) != 0 && len(domainPrefix) == len(username) {
			// The username doesn't have the required domain suffix.
			continue
		}
		if isLocal && strings.Contains(domainPrefix, "@") {
			// The username contains a domain but @no-domain has been specified.
			continue
		}
		return true, true
	}
	// Note that if all the ACL members are of the form everyone...,
	// the result counts as trivial.
	return false, allEveryone
}

// Allow reports whether the given ACL admits the user with the given
// name. If the user does not exist and the ACL does not allow username
// or everyone, it will return (false, nil).
func (c *PermChecker) Allow(username string, acl []string) (bool, error) {
	if ok, isTrivial := trivialAllow(username, acl); isTrivial {
		return ok, nil
	}
	groups, err := c.cache.groupMap(username)
	if err != nil {
		return false, errgo.Mask(err)
	}
	for _, a := range acl {
		if groups[a] {
			return true, nil
		}
	}
	return false, nil
}

// CacheEvict evicts username from the cache.
func (c *PermChecker) CacheEvict(username string) {
	c.cache.CacheEvict(username)
}

// CacheEvictAll evicts everything from the cache.
func (c *PermChecker) CacheEvictAll() {
	c.cache.CacheEvictAll()
}
