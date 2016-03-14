// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package ussologin_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	"github.com/juju/usso"
	gc "gopkg.in/check.v1"
	"gopkg.in/juju/environschema.v1/form"

	"github.com/juju/idmclient/params"
	"github.com/juju/idmclient/ussologin"
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
	s.PatchValue(ussologin.Server, ussoStub)
	filler := &testFiller{
		map[string]interface{}{
			ussologin.UserKey: "foobar",
			ussologin.PassKey: "pass",
			ussologin.OTPKey:  "1234",
		}}
	store := &testTokenStore{}
	f := ussologin.VisitWebPage(filler, &http.Client{}, store)
	u, err := url.Parse(s.server.URL)
	c.Assert(err, jc.ErrorIsNil)
	err = f(u)
	c.Assert(err, jc.ErrorIsNil)
	ussoStub.CheckCall(c, 0, "GetTokenWithOTP", "foobar", "pass", "1234", "charm")
	store.CheckCallNames(c, "Get", "Put")
}

func (s *visitWebPageSuite) TestLoginFailsToGetToken(c *gc.C) {
	ussoStub := &ussoServerStub{}
	ussoStub.SetErrors(errors.New("something failed"))
	s.PatchValue(ussologin.Server, ussoStub)
	filler := &testFiller{
		map[string]interface{}{
			ussologin.UserKey: "foobar",
			ussologin.PassKey: "pass",
			ussologin.OTPKey:  "1234",
		}}
	f := ussologin.VisitWebPage(filler, &http.Client{}, &testTokenStore{})
	u, err := url.Parse(s.server.URL)
	c.Assert(err, jc.ErrorIsNil)
	err = f(u)
	c.Assert(err, gc.ErrorMatches, "cannot get token: something failed")
}

func (s *visitWebPageSuite) TestLoginWithExistingToken(c *gc.C) {
	ussoStub := &ussoServerStub{}
	s.PatchValue(ussologin.Server, ussoStub)
	f := ussologin.VisitWebPage(&testFiller{}, &http.Client{}, &testTokenStore{tok: &usso.SSOData{}})
	u, err := url.Parse(s.server.URL)
	c.Assert(err, jc.ErrorIsNil)
	err = f(u)
	c.Assert(err, jc.ErrorIsNil)
	ussoStub.CheckNoCalls(c) //If we have a token we shouldn't call the ussoServer
}

func (s *visitWebPageSuite) TestLoginWithExistingMalformedToken(c *gc.C) {
	ussoStub := &ussoServerStub{}
	s.PatchValue(ussologin.Server, ussoStub)
	filler := &testFiller{
		map[string]interface{}{
			ussologin.UserKey: "foobar",
			ussologin.PassKey: "pass",
			ussologin.OTPKey:  "1234",
		}}
	tokenPath := fmt.Sprintf("%s/token", c.MkDir())
	err := ioutil.WriteFile(tokenPath, []byte("foobar"), 0600) // Write a malformed token
	c.Assert(err, jc.ErrorIsNil)
	f := ussologin.VisitWebPage(filler, &http.Client{}, ussologin.NewFileTokenStore(tokenPath))
	u, err := url.Parse(s.server.URL)
	c.Assert(err, jc.ErrorIsNil)
	err = f(u)
	c.Assert(err, jc.ErrorIsNil)
	ussoStub.CheckCall(c, 0, "GetTokenWithOTP", "foobar", "pass", "1234", "charm")
}

func (s *visitWebPageSuite) TestVisitWebPageWorksIfNilStoreGiven(c *gc.C) {
	ussoStub := &ussoServerStub{}
	s.PatchValue(ussologin.Server, ussoStub)
	filler := &testFiller{
		map[string]interface{}{
			ussologin.UserKey: "foobar",
			ussologin.PassKey: "pass",
			ussologin.OTPKey:  "1234",
		}}
	f := ussologin.VisitWebPage(filler, &http.Client{}, nil)
	u, err := url.Parse(s.server.URL)
	c.Assert(err, jc.ErrorIsNil)
	err = f(u)
	c.Assert(err, jc.ErrorIsNil)
	ussoStub.CheckCall(c, 0, "GetTokenWithOTP", "foobar", "pass", "1234", "charm")
}

func (s *visitWebPageSuite) TestFailedToReadLoginParameters(c *gc.C) {
	ussoStub := &ussoServerStub{}
	s.PatchValue(ussologin.Server, ussoStub)
	filler := &errFiller{}
	f := ussologin.VisitWebPage(filler, &http.Client{}, &testTokenStore{})
	u, err := url.Parse(s.server.URL)
	c.Assert(err, jc.ErrorIsNil)
	err = f(u)
	c.Assert(err, gc.ErrorMatches, "cannot read login parameters: something failed")
	ussoStub.CheckNoCalls(c)
}

type testFiller struct {
	form map[string]interface{}
}

func (t *testFiller) Fill(f form.Form) (map[string]interface{}, error) {
	return t.form, nil
}

type errFiller struct{}

func (t *errFiller) Fill(f form.Form) (map[string]interface{}, error) {
	return nil, errors.New("something failed")
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
