// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

// Package login defines functionality used for allowing clients to authenticate
// using USSO OAuth.
package login

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/juju/httprequest"
	"github.com/juju/usso"
	"gopkg.in/errgo.v1"
	"gopkg.in/juju/environschema.v1"
	"gopkg.in/juju/environschema.v1/form"
	"gopkg.in/macaroon-bakery.v1/httpbakery"
)

type tokenGetter interface {
	GetTokenWithOTP(username, password, otp, tokenName string) (*usso.SSOData, error)
}

// This is defined here to allow it to be stubbed out in tests
var ussoServer tokenGetter = usso.ProductionUbuntuSSOServer

// loginUSSO completes the login information using the provided filler
// and attempts to obtain a USSO token using this information.
// If the store is non-nil it is used to store this token.
func loginUSSO(filler form.Filler, store TokenStore) (*usso.SSOData, error) {
	login, err := filler.Fill(ussoLoginForm)
	if err != nil {
		return nil, errgo.Notef(err, "cannot read login parameters")
	}
	tok, err := ussoServer.GetTokenWithOTP(
		login["username"].(string),
		login["password"].(string),
		login["otp"].(string),
		"charm",
	)
	if err != nil {
		return nil, errgo.Notef(err, "cannot get token")
	}
	if err := store.Put(tok); err != nil {
		return nil, errgo.Notef(err, "cannot save token")
	}
	return tok, nil
}

var ussoLoginForm = form.Form{
	Fields: environschema.Fields{
		"username": environschema.Attr{
			Description: "Username",
			Type:        environschema.Tstring,
			Mandatory:   true,
			Group:       "1",
		},
		"password": environschema.Attr{
			Description: "Password",
			Type:        environschema.Tstring,
			Mandatory:   true,
			Secret:      true,
			Group:       "1",
		},
		"otp": environschema.Attr{
			Description: "Two-factor auth",
			Type:        environschema.Tstring,
			Group:       "2",
		},
	},
}

// DoSignedRequest signs a request to the given url with the provided token.
func DoSignedRequest(client *http.Client, ussoAuthUrl string, tok *usso.SSOData, u *url.URL) error {
	req, err := http.NewRequest("GET", ussoAuthUrl, nil)
	if err != nil {
		return errgo.Notef(err, "cannot create request")
	}
	base := *req.URL
	base.RawQuery = ""
	rp := usso.RequestParameters{
		HTTPMethod:      req.Method,
		BaseURL:         base.String(),
		Params:          req.URL.Query(),
		SignatureMethod: usso.HMACSHA1{},
	}
	if err := tok.SignRequest(&rp, req); err != nil {
		return errgo.Notef(err, "cannot sign request")
	}
	resp, err := client.Do(req)
	if err != nil {
		return errgo.Notef(err, "cannot do request")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	var herr httpbakery.Error
	if err := httprequest.UnmarshalJSONResponse(resp, &herr); err != nil {
		return errgo.Notef(err, "cannot unmarshal error")
	}
	return &herr
}

// TokenStore defines the interface for something that can store and returns oauth tokens.
type TokenStore interface {
	// Put stores an Ubuntu SSO OAuth token.
	Put(tok *usso.SSOData) error
	// Get returns an Ubuntu SSO OAuth token from store
	Get() (*usso.SSOData, error)
}

// FileTokenStore implements the TokenStore interface by storing the
// JSON-encoded oauth token in a file.
type FileTokenStore struct {
	path string
}

// NewFileTokenStore returns a new FileTokenStore
// that uses the given path for storage.
func NewFileTokenStore(path string) *FileTokenStore {
	return &FileTokenStore{path}
}

// Put implements TokenStore.Put by
// writing the token to the FileTokenStore's file.
func (f *FileTokenStore) Put(tok *usso.SSOData) error {
	data, err := json.Marshal(tok)
	if err != nil {
		return errgo.Notef(err, "cannot marshal token")
	}
	if err := ioutil.WriteFile(f.path, data, 0600); err != nil {
		return errgo.Notef(err, "cannot write file")
	}
	return nil
}

// Get implements TokenStore.Get by
// reading the token from the FileTokenStore's file.
func (f *FileTokenStore) Get() (*usso.SSOData, error) {
	data, err := ioutil.ReadFile(f.path)
	if err != nil {
		return nil, errgo.Notef(err, "cannot read token")
	}
	var tok usso.SSOData
	if err := json.Unmarshal(data, &tok); err != nil {
		return nil, errgo.Notef(err, "cannot unmarshal token")
	}
	return &tok, nil
}
