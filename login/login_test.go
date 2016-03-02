package login_test

import (
	"bytes"
	"fmt"
	"io/ioutil"

	"github.com/juju/cmd/cmdtesting"
	jc "github.com/juju/testing/checkers"
	"github.com/juju/usso"
	gc "gopkg.in/check.v1"

	"github.com/juju/identity/login"
)

type cliSuite struct {
}

var _ = gc.Suite(&cliSuite{})

func (s *cliSuite) TestReadUssoParamsWithTwoFactor(c *gc.C) {
	ctx := cmdtesting.Context(c)
	ctx.Stdin = bytes.NewBufferString("foobar\npass\n1234\n")
	email, password, otp, err := login.ReadUSSOParams(ctx, true)
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(email, gc.Equals, "foobar")
	c.Assert(password, gc.Equals, "pass")
	c.Assert(otp, gc.Equals, "1234")
	c.Assert(cmdtesting.Stderr(ctx), gc.Equals,
		`Login to https://jujucharms.com:
Username: Password: 
Two-factor auth (Enter for none): `)
}

func (s *cliSuite) TestReadUssoParamsNoTwoFactor(c *gc.C) {
	ctx := cmdtesting.Context(c)
	ctx.Stdin = bytes.NewBufferString("foobar\npass\n\n")
	email, password, otp, err := login.ReadUSSOParams(ctx, true)
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(email, gc.Equals, "foobar")
	c.Assert(password, gc.Equals, "pass")
	c.Assert(otp, gc.Equals, "")
	c.Assert(cmdtesting.Stderr(ctx), gc.Equals,
		`Login to https://jujucharms.com:
Username: Password: 
Two-factor auth (Enter for none): `)
}

func (s *cliSuite) TestSaveReadToken(c *gc.C) {
	token := &usso.SSOData{
		ConsumerKey:    "consumerkey",
		ConsumerSecret: "consumersecret",
		Realm:          "realm",
		TokenKey:       "tokenkey",
		TokenName:      "tokenname",
		TokenSecret:    "tokensecret",
	}
	path := fmt.Sprintf("%s/tokenFile", c.MkDir())
	err := login.SaveToken(path, token)
	c.Assert(err, jc.ErrorIsNil)

	tok, err := login.ReadToken(path)
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(tok, gc.DeepEquals, token)
}

func (s *cliSuite) TestReadInvalidToken(c *gc.C) {
	path := fmt.Sprintf("%s/tokenFile", c.MkDir())
	err := ioutil.WriteFile(path, []byte("foobar"), 0700)
	c.Assert(err, jc.ErrorIsNil)

	_, err = login.ReadToken(path)
	c.Assert(err, gc.ErrorMatches, `cannot unmarshal token: invalid character 'o' in literal false \(expecting 'a'\)`)
}
