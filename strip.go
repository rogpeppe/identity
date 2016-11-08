package idmclient

import (
	"strings"

	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"
)

// StripDomain wraps the given identity client and strips the given
// domain name off any user and group names returned from it. It also
// adds it as an @ suffix when querying for ACL membership for names
// that don't already contain a domain.
//
// If the users returned from idmClient implement ACLUser, the users
// returned from the returned client will too.
//
// This is useful when an existing user of the identity manager needs to
// obtain backwardly compatible usernames when an identity manager is
// changed to add a domain suffix.
func StripDomain(idmClient IdentityClient, domain string) IdentityClient {
	return &domainStrippingClient{
		domain: "@" + domain,
		c:      idmClient,
	}
}

// ACLUser represents a user that can be queried for group information.
type ACLUser interface {
	Identity

	// Username returns the user name of the user.
	Username() (string, error)

	// Groups returns all the groups that the user
	// is a member of.
	//
	// Note: use of this method should be avoided if
	// possible, as a user may potentially be in huge
	// numbers of groups.
	Groups() ([]string, error)

	// Allow reports whether the user should be allowed to access
	// any of the users or groups in the given ACL slice.
	Allow(acl []string) (bool, error)
}

// domainStrippingClient implements IdentityClient by stripping a given
// domain off any declared users.
type domainStrippingClient struct {
	domain string
	c      IdentityClient
}

// DeclaredIdentity implements IdentityClient.DeclaredIdentity.
func (c *domainStrippingClient) DeclaredIdentity(attrs map[string]string) (Identity, error) {
	ident, err := c.c.DeclaredIdentity(attrs)
	if err != nil {
		return nil, err
	}
	u, ok := ident.(ACLUser)
	if !ok {
		return ident, nil
	}
	return &domainStrippingIdentity{
		ACLUser: u,
		domain:  c.domain,
	}, nil
}

// DeclaredIdentity implements IdentityClient.IdentityCaveats.
func (c *domainStrippingClient) IdentityCaveats() []checkers.Caveat {
	return c.c.IdentityCaveats()
}

type domainStrippingIdentity struct {
	domain string
	ACLUser
}

// Username implements ACLUser.IdentityCaveats.
func (u *domainStrippingIdentity) Username() (string, error) {
	name, err := u.ACLUser.Username()
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(name, u.domain), nil
}

// Groups implements ACLUser.Groups.
func (u *domainStrippingIdentity) Groups() ([]string, error) {
	groups, err := u.ACLUser.Groups()
	if err != nil {
		return nil, err
	}
	for i, g := range groups {
		groups[i] = strings.TrimSuffix(g, u.domain)
	}
	return groups, nil
}

// Allow implements ACLUser.Allow by adding stripped
// domain to all names in acl that don't have a domain
// before calling the underlying Allow method.
func (u *domainStrippingIdentity) Allow(acl []string) (bool, error) {
	acl1 := make([]string, len(acl))
	for i, name := range acl {
		if !strings.Contains(name, "@") {
			acl1[i] = name + u.domain
		} else {
			acl1[i] = name
		}
	}
	ok, err := u.ACLUser.Allow(acl1)
	if err != nil {
		return false, errgo.Mask(err)
	}
	if ok {
		return true, nil
	}
	// We were denied access with @usso suffix, but perhaps
	// the identity manager isn't yet adding suffixes - we still
	// want it to work in that case, so try without the added
	// suffixes.
	ok, err = u.ACLUser.Allow(acl)
	if err != nil {
		return false, errgo.Mask(err)
	}
	return ok, nil
}
