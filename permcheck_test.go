// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package idmclient_test

import (
	"time"

	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"

	"github.com/juju/idmclient"
	"github.com/juju/idmclient/idmtest"
)

type permCheckerSuite struct {
}

var _ = gc.Suite(&permCheckerSuite{})

var permCheckerTests = []struct {
	about    string
	username string
	acl      []string
	expect   bool
}{{
	about:    "No permissions always yields false",
	username: "joe",
	acl:      nil,
	expect:   false,
}, {
	about:    "If the user isn't found, it's not an error",
	username: "joe",
	acl:      []string{"beatles"},
	expect:   false,
}, {
	about:    "If the perms allow everyone, it's ok",
	username: "joe",
	acl:      []string{"noone", "everyone"},
	expect:   true,
}, {
	about:    "if the user is part of a required group, it's ok",
	username: "bob",
	acl:      []string{"noone", "beatles"},
}, {
	about:    "if the perms allow the user itself, it's ok",
	username: "joe",
	acl:      []string{"noone", "joe"},
	expect:   true,
}, {
	about:    "If the perms allow everyone@somewhere, it's ok",
	username: "joe@somewhere",
	acl:      []string{"everyone@somewhere"},
	expect:   true,
}, {
	about:    "Check that the everyone@x logic works with multiple @s",
	username: "joe@foo@somewhere@else",
	acl:      []string{"everyone@somewhere@else"},
	expect:   true,
}, {
	about:    "check that we're careful enough about 'everyone' as a prefix to a user name",
	username: "joex",
	acl:      []string{"everyonex"},
	expect:   false,
}, {
	about:    "a user with no domain is allowed by everyone@no-domain",
	username: "joe",
	acl:      []string{"everyone-local"},
	expect:   true,
}, {
	about:    "a user with a domain is not allowed by everyone@no-domain",
	username: "joe@somewhere",
	acl:      []string{"everyone-local"},
	expect:   false,
}, {
	about:    "a user with a domain can be matched by everyone@no-domain@domain",
	username: "joe@somewhere",
	acl:      []string{"everyone-local@somewhere"},
	expect:   true,
}, {
	about:    "a user with a domain can be matched by everyone@no-domain@domain",
	username: "joe@somewhere@foo",
	acl:      []string{"everyone-local@somewhere@foo"},
	expect:   true,
}, {
	about:    "a user with with extra domains is not matched by everyone@no-domain@domain",
	username: "joe@xxx@somewhere@foo",
	acl:      []string{"everyone-local@somewhere@foo"},
	expect:   false,
}, {
	about:    "if the user itself has a @no-domain suffix, it doesn't match",
	username: "joe@no-domain",
	acl:      []string{"everyone-local"},
	expect:   false,
}, {
	about:    "check that we're careful enough with 'everyone-local' as a prefix",
	username: "joex",
	acl:      []string{"everyone-localx"},
	expect:   false,
}}

func (s *permCheckerSuite) TestPermChecker(c *gc.C) {
	srv := idmtest.NewServer()
	client, err := idmclient.New(idmclient.NewParams{
		BaseURL: srv.URL.String(),
		Client:  srv.Client("alice"),
	})
	c.Assert(err, gc.IsNil)
	pc := idmclient.NewPermChecker(client, time.Hour)

	for i, test := range permCheckerTests {
		c.Logf("test %d: %v", i, test.about)
		ok, err := pc.Allow(test.username, test.acl)
		c.Assert(err, gc.IsNil)
		c.Assert(ok, gc.Equals, test.expect)
	}
}

func (s *permCheckerSuite) TestPermCheckerCache(c *gc.C) {
	srv := idmtest.NewServer()
	client, err := idmclient.New(idmclient.NewParams{
		BaseURL: srv.URL.String(),
		Client:  srv.Client("alice"),
	})
	c.Assert(err, gc.IsNil)
	pc := idmclient.NewPermChecker(client, time.Hour)

	ok, err := pc.Allow("bob", []string{"beatles"})
	c.Assert(err, gc.IsNil)
	c.Assert(ok, gc.Equals, false)

	srv.AddUser("bob", "beatles")

	// The group details are currently cached by the client,
	// so the original request will still fail even though we've
	// just added bob to the required group.
	ok, err = pc.Allow("bob", []string{"beatles"})
	c.Assert(err, gc.IsNil)
	c.Assert(ok, gc.Equals, false)

	// Clearing the cache allows it to succeed.
	pc.CacheEvictAll()
	ok, err = pc.Allow("bob", []string{"beatles"})
	c.Assert(err, gc.IsNil)
	c.Assert(ok, gc.Equals, true)
}

func (s *permCheckerSuite) TestError(c *gc.C) {
	client, err := idmclient.New(idmclient.NewParams{
		BaseURL: "http://0.1.2.3/",
		Client:  httpbakery.NewClient(),
	})
	c.Assert(err, gc.IsNil)
	pc := idmclient.NewPermChecker(client, time.Hour)

	ok, err := pc.Allow("bob", []string{"beatles"})
	c.Assert(err, gc.ErrorMatches, `cannot fetch groups: .*`)
	c.Assert(ok, gc.Equals, false)
}

func (s *permCheckerSuite) TestAllEveryoneIsTrivial(c *gc.C) {
	client, err := idmclient.New(idmclient.NewParams{
		BaseURL: "http://0.1.2.3/",
		Client:  httpbakery.NewClient(),
	})
	c.Assert(err, gc.IsNil)
	pc := idmclient.NewPermChecker(client, time.Hour)

	ok, err := pc.Allow("bob@foo", []string{"everyone@no-domain", "everyone@bar"})
	c.Assert(err, gc.IsNil)
	c.Assert(ok, gc.Equals, false)
}

func (s *permCheckerSuite) TestGroupCache(c *gc.C) {
	srv := idmtest.NewServer()
	srv.AddUser("alice", "somegroup", "othergroup")

	client, err := idmclient.New(idmclient.NewParams{
		BaseURL: srv.URL.String(),
		Client:  srv.Client("alice"),
	})
	c.Assert(err, gc.IsNil)

	cache := idmclient.NewGroupCache(client, time.Hour)

	// If the user isn't found, we retturn no groups.
	g, err := cache.Groups("bob")
	c.Assert(err, gc.IsNil)
	c.Assert(g, gc.HasLen, 0)

	g, err = cache.Groups("alice")
	c.Assert(err, gc.IsNil)
	c.Assert(g, jc.DeepEquals, []string{"othergroup", "somegroup"})

	srv.AddUser("bob", "beatles")

	// The group details are currently cached by the client,
	// so we'll still see the original group membership.
	g, err = cache.Groups("bob")
	c.Assert(err, gc.IsNil)
	c.Assert(g, gc.HasLen, 0)

	// Clearing the cache allows it to succeed.
	cache.CacheEvictAll()
	g, err = cache.Groups("bob")
	c.Assert(err, gc.IsNil)
	c.Assert(g, jc.DeepEquals, []string{"beatles"})
}
