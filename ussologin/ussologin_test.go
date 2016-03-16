// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package ussologin_test

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	"github.com/juju/usso"
	gc "gopkg.in/check.v1"

	"github.com/juju/idmclient/ussologin"
)

type loginSuite struct {
}

var _ = gc.Suite(&loginSuite{})

func (s *loginSuite) TestPutGetToken(c *gc.C) {
	token := &usso.SSOData{
		ConsumerKey:    "consumerkey",
		ConsumerSecret: "consumersecret",
		Realm:          "realm",
		TokenKey:       "tokenkey",
		TokenName:      "tokenname",
		TokenSecret:    "tokensecret",
	}
	path := filepath.Join(c.MkDir(), "subdir", "tokenFile")
	store := ussologin.NewFileTokenStore(path)
	err := store.Put(token)
	c.Assert(err, jc.ErrorIsNil)

	tok, err := store.Get()
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(tok, gc.DeepEquals, token)
	data, err := ioutil.ReadFile(path)
	c.Assert(err, jc.ErrorIsNil)
	var storedToken *usso.SSOData
	err = json.Unmarshal(data, &storedToken)
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(token, gc.DeepEquals, storedToken)
}

func (s *loginSuite) TestReadInvalidToken(c *gc.C) {
	path := fmt.Sprintf("%s/tokenFile", c.MkDir())
	err := ioutil.WriteFile(path, []byte("foobar"), 0700)
	c.Assert(err, jc.ErrorIsNil)
	store := ussologin.NewFileTokenStore(path)

	_, err = store.Get()
	c.Assert(err, gc.ErrorMatches, `cannot unmarshal token: invalid character 'o' in literal false \(expecting 'a'\)`)
}

type testTokenStore struct {
	testing.Stub
	tok *usso.SSOData
}

func (m *testTokenStore) Put(tok *usso.SSOData) error {
	m.MethodCall(m, "Put", tok)
	m.tok = tok
	return nil
}

func (m *testTokenStore) Get() (*usso.SSOData, error) {
	m.MethodCall(m, "Get")
	if m.tok == nil {
		return nil, fmt.Errorf("no token")
	}
	return m.tok, nil
}
