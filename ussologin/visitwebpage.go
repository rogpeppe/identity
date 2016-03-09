// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package ussologin

import (
	"net/http"
	"net/url"

	"github.com/juju/usso"
	"gopkg.in/errgo.v1"
	"gopkg.in/juju/environschema.v1/form"
	"gopkg.in/macaroon-bakery.v1/httpbakery"

	"github.com/juju/idmclient"
)

// VisitWebPage returns a function which will allow authentication via USSO
// OAuth.  If UbuntuSSO OAuth login is not available then this function falls
// back to httpbakery.OpenWebBrowser.  The user will be prompted for username,
// password and any two factor authentication code via the command line.
// Existing oauth tokens can be obtained, or new ones stored If non-nil, the
// given TokenStore is used to store the oauth token obtained during the login
// process so that less interaction may be required in future.
func VisitWebPage(filler form.Filler, client *http.Client, store TokenStore) func(*url.URL) error {
	return func(u *url.URL) error {
		lm, err := idmclient.LoginMethods(client, u)
		if err != nil {
			return err
		}
		if lm.UbuntuSSOOAuth != "" {
			var tok *usso.SSOData
			var err error
			if store == nil {
				tok, err := Login(filler)
				if err != nil {
					return err
				}
				return doSignedRequest(client, lm.UbuntuSSOOAuth, tok, u)
			}
			if tok, err = store.Get(); err != nil {
				tok, err = Login(filler)
				if err != nil {
					return err
				}
				if err := store.Put(tok); err != nil {
					return errgo.Notef(err, "cannot save token")
				}
			}
			return doSignedRequest(client, lm.UbuntuSSOOAuth, tok, u)
		}
		return httpbakery.OpenWebBrowser(u)
	}
}
