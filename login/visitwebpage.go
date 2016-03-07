// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package login

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/juju/usso"
	"gopkg.in/juju/environschema.v1/form"
	"gopkg.in/macaroon-bakery.v1/httpbakery"

	"github.com/juju/idmclient"
)

// VisitWebPage returns a function which will allow authentication with USSO
// via the cli.
// The user will be prompted for username, password and any two factor authentication
// code via the command line. Existing oauth tokens can be obtained, or new ones stored
// If non-nil, the given TokenStore is used to store the oauth token obtained during
// the login process so that less interaction may be required in future.
func VisitWebPage(filler form.Filler, client *http.Client, store TokenStore) func(*url.URL) error {
	if store == nil {
		store = &nopStore{}
	}
	return func(u *url.URL) error {
		lm, err := idmclient.LoginMethods(client, u)
		if err != nil {
			return err
		}
		if lm.UbuntuSSOOAuth != "" {
			var tok *usso.SSOData
			var err error
			if tok, err = store.Get(); err != nil {
				tok, err = loginUSSO(filler, store)
				if err != nil {
					return err
				}
			}
			return DoSignedRequest(client, lm.UbuntuSSOOAuth, tok, u)
		}
		return httpbakery.OpenWebBrowser(u)
	}
}

type nopStore struct{}

func (n *nopStore) Put(tok *usso.SSOData) error {
	return nil
}

func (n *nopStore) Get() (*usso.SSOData, error) {
	return nil, errors.New("no token storage")
}
