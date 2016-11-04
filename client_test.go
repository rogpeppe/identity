package idmclient_test

import (
	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"
	"gopkg.in/macaroon.v2-unstable"
	"sort"

	"github.com/juju/idmclient"
	"github.com/juju/idmclient/idmtest"
)

type clientSuite struct{}

var _ = gc.Suite(&clientSuite{})

func (*clientSuite) TestIdentityCaveat(c *gc.C) {
	srv := idmtest.NewServer()
	srv.AddUser("bob", "alice", "charlie")
	client := srv.Client("bob")
	idmClient := srv.IDMClient("bob")

	bsvc, err := bakery.NewService(bakery.NewServiceParams{
		Locator: srv,
	})
	c.Assert(err, gc.IsNil)
	m, err := bsvc.NewMacaroon(idmClient.IdentityCaveats())
	c.Assert(err, gc.IsNil)

	ms, err := client.DischargeAll(m)
	c.Assert(err, gc.IsNil)

	// Make sure that the macaroon discharged correctly and that it
	// has the right declared caveats.
	attrs, err := bsvc.CheckAny([]macaroon.Slice{ms}, nil, checkers.New())
	c.Assert(err, gc.IsNil)

	ident, err := idmClient.DeclaredIdentity(attrs)
	c.Assert(err, gc.IsNil)

	c.Assert(ident.Id(), gc.Equals, "bob")
	c.Assert(ident.Domain(), gc.Equals, "")

	user := ident.(*idmclient.User)

	u, err := user.Username()
	c.Assert(err, gc.IsNil)
	c.Assert(u, gc.Equals, "bob")
	ok, err := user.Allow([]string{"alice"})
	c.Assert(err, gc.IsNil)
	c.Assert(ok, gc.Equals, true)

	groups, err := user.Groups()
	c.Assert(err, gc.IsNil)
	sort.Strings(groups)
	c.Assert(groups, jc.DeepEquals, []string{"alice", "charlie"})
}
