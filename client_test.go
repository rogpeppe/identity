package idmclient_test

import (
	"sort"

	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"
	"gopkg.in/macaroon.v2-unstable"

	"github.com/juju/idmclient"
	"github.com/juju/idmclient/idmtest"
)

type clientSuite struct{}

var _ = gc.Suite(&clientSuite{})

func (*clientSuite) TestIdentityClient(c *gc.C) {
	srv := idmtest.NewServer()
	srv.AddUser("bob", "alice", "charlie")
	testIdentityClient(c,
		srv.IDMClient("bob"),
		srv.Client("bob"),
		"bob", "bob", []string{"alice", "charlie"},
	)
}

func (*clientSuite) TestIdentityClientWithDomainStrip(c *gc.C) {
	srv := idmtest.NewServer()
	srv.AddUser("bob@usso", "alice@usso", "charlie@elsewhere")
	testIdentityClient(c,
		idmclient.StripDomain(srv.IDMClient("bob@usso"), "usso"),
		srv.Client("bob@usso"),
		"bob@usso", "bob", []string{"alice", "charlie@elsewhere"},
	)
}

func (*clientSuite) TestIdentityClientWithDomainStripNoDomains(c *gc.C) {
	srv := idmtest.NewServer()
	srv.AddUser("bob", "alice", "charlie")
	testIdentityClient(c,
		idmclient.StripDomain(srv.IDMClient("bob"), "usso"),
		srv.Client("bob"),
		"bob", "bob", []string{"alice", "charlie"},
	)
}

// testIdentityClient tests that the given identity client can be used to
// create a third party caveat that when discharged provides
// an Identity with the given id, user name and groups.
func testIdentityClient(c *gc.C, idmClient idmclient.IdentityClient, bclient *httpbakery.Client, expectId, expectUser string, expectGroups []string) {
	kr := httpbakery.NewThirdPartyLocator(nil, nil)
	kr.AllowInsecure()
	bsvc, err := bakery.NewService(bakery.NewServiceParams{
		Locator: kr,
	})
	c.Assert(err, gc.IsNil)
	m, err := bsvc.NewMacaroon(bakery.LatestVersion, idmClient.IdentityCaveats())
	c.Assert(err, gc.IsNil)

	ms, err := bclient.DischargeAll(m)
	c.Assert(err, gc.IsNil)

	// Make sure that the macaroon discharged correctly and that it
	// has the right declared caveats.
	attrs, _, err := bsvc.CheckAny([]macaroon.Slice{ms}, nil, checkers.New())
	c.Assert(err, gc.IsNil)

	ident, err := idmClient.DeclaredIdentity(attrs)
	c.Assert(err, gc.IsNil)

	c.Assert(ident.Id(), gc.Equals, expectId)
	c.Assert(ident.Domain(), gc.Equals, "")

	user := ident.(idmclient.ACLUser)

	u, err := user.Username()
	c.Assert(err, gc.IsNil)
	c.Assert(u, gc.Equals, expectUser)
	ok, err := user.Allow([]string{expectGroups[0]})
	c.Assert(err, gc.IsNil)
	c.Assert(ok, gc.Equals, true)

	groups, err := user.Groups()
	c.Assert(err, gc.IsNil)
	sort.Strings(groups)
	c.Assert(groups, jc.DeepEquals, expectGroups)
}
