// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package login_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/juju/cmd/cmdtesting"
	"github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	"github.com/juju/usso"
	gc "gopkg.in/check.v1"

	"github.com/juju/idmclient/login"
	"github.com/juju/idmclient/params"
)

type visitWebPageSuite struct {
	testing.CleanupSuite
	server *httptest.Server
}

var _ = gc.Suite(&visitWebPageSuite{})

func (s *visitWebPageSuite) SetUpTest(c *gc.C) {
	s.server = httptest.NewServer(&loginMethodsHandler{"http://example.com"})
}

func (s *visitWebPageSuite) TearDownTest(c *gc.C) {
	s.server.Close()
}

func (s *visitWebPageSuite) TestCorrectUserPasswordSentToUSSOServer(c *gc.C) {
	ussoStub := &ussoServerStub{}
	s.PatchValue(login.USSOServer, ussoStub)
	ctx := cmdtesting.Context(c)
	ctx.Stdin = bytes.NewBufferString("foobar\npass\n1234\n")
	f := login.VisitWebPage(ctx, &http.Client{}, &testTokenStore{})
	u, err := url.Parse(s.server.URL)
	c.Assert(err, jc.ErrorIsNil)
	err = f(u)
	c.Assert(err, jc.ErrorIsNil)
	ussoStub.CheckCall(c, 0, "GetTokenWithOTP", "foobar", "pass", "1234", "charm")
}

func (s *visitWebPageSuite) TestLoginFailsToGetToken(c *gc.C) {
	ussoStub := &ussoServerStub{}
	ussoStub.SetErrors(errors.New("something failed"))
	s.PatchValue(login.USSOServer, ussoStub)
	ctx := cmdtesting.Context(c)
	ctx.Stdin = bytes.NewBufferString("foobar\npass\n1234\n")
	f := login.VisitWebPage(ctx, &http.Client{}, &testTokenStore{})
	u, err := url.Parse(s.server.URL)
	c.Assert(err, jc.ErrorIsNil)
	err = f(u)
	c.Assert(err, gc.ErrorMatches, "cannot get token: something failed")
}

func (s *visitWebPageSuite) TestLoginWithExistingToken(c *gc.C) {
	ussoStub := &ussoServerStub{}
	s.PatchValue(login.USSOServer, ussoStub)
	f := login.VisitWebPage(cmdtesting.Context(c), &http.Client{}, &testTokenStore{tok: &usso.SSOData{}})
	u, err := url.Parse(s.server.URL)
	c.Assert(err, jc.ErrorIsNil)
	err = f(u)
	c.Assert(err, jc.ErrorIsNil)
	ussoStub.CheckNoCalls(c) //If we have a token we shouldn't call the ussoServer
}

func (s *visitWebPageSuite) TestLoginWithExistingMalformedToken(c *gc.C) {
	ctx := cmdtesting.Context(c)
	ctx.Stdin = bytes.NewBufferString("foobar\npass\n1234\n")
	ussoStub := &ussoServerStub{}
	s.PatchValue(login.USSOServer, ussoStub)
	tokenPath := fmt.Sprintf("%s/token", c.MkDir())
	err := ioutil.WriteFile(tokenPath, []byte("foobar"), 0600) // Write a malformed token
	c.Assert(err, jc.ErrorIsNil)
	f := login.VisitWebPage(ctx, &http.Client{}, login.NewFileTokenStore(tokenPath))
	u, err := url.Parse(s.server.URL)
	c.Assert(err, jc.ErrorIsNil)
	err = f(u)
	c.Assert(err, jc.ErrorIsNil)
	ussoStub.CheckCall(c, 0, "GetTokenWithOTP", "foobar", "pass", "1234", "charm")
}

func (s *visitWebPageSuite) TestVisitWebPageWorksIfNilStoreGiven(c *gc.C) {
	ussoStub := &ussoServerStub{}
	s.PatchValue(login.USSOServer, ussoStub)
	ctx := cmdtesting.Context(c)
	ctx.Stdin = bytes.NewBufferString("foobar\npass\n1234\n")
	f := login.VisitWebPage(ctx, &http.Client{}, nil)
	u, err := url.Parse(s.server.URL)
	c.Assert(err, jc.ErrorIsNil)
	err = f(u)
	c.Assert(err, jc.ErrorIsNil)
	ussoStub.CheckCall(c, 0, "GetTokenWithOTP", "foobar", "pass", "1234", "charm")
}

type ussoServerStub struct {
	testing.Stub
}

func (u *ussoServerStub) GetTokenWithOTP(email, password, otp, tokenName string) (*usso.SSOData, error) {
	u.AddCall("GetTokenWithOTP", email, password, otp, tokenName)
	return &usso.SSOData{}, u.NextErr()
}

type loginMethodsHandler struct {
	responseURL string
}

func (l *loginMethodsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	lm := params.LoginMethods{
		UbuntuSSOOAuth: l.responseURL,
	}
	writer := json.NewEncoder(w)
	err := writer.Encode(&lm)
	if err != nil {
		panic(err)
	}
}
