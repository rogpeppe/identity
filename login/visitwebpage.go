// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package login

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/juju/cmd"
	"github.com/juju/identity/idmclient"
	"github.com/juju/usso"
	"gopkg.in/macaroon-bakery.v1/httpbakery"
)

// VisitWebPage returns a function which will allow authentication with usso
// via the cli.
// The user will be prompted for username, password and any two factor authentication
// code via the command line. Existing oauth tokens can be obtained, or new ones stored
// using the given TokenStore. If no TokenStore is specified then the nopStore will be
// used.
func VisitWebPage(ctx *cmd.Context, client *http.Client, store TokenStore) func(*url.URL) error {
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
			if tok, err = store.ReadToken(); err != nil {
				tok, err = LoginUSSO(ctx, true, store)
				if err != nil {
					return err
				}
			}
			return idmclient.UbuntuSSOOAuthVisit(client, lm.UbuntuSSOOAuth, tok, u)
		}
		return httpbakery.OpenWebBrowser(u)
	}
}

type nopStore struct{}

func (n *nopStore) SaveToken(tok *usso.SSOData) error {
	return nil
}

func (n *nopStore) ReadToken() (*usso.SSOData, error) {
	return nil, errors.New("no token storage")
}
