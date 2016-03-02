// Copyright 2015 Canonical Ltd.

package login

import (
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
// code via the command line, an oath token will be obtained and saved to disk.:w
func VisitWebPage(ctx *cmd.Context, client *http.Client, tokenPath string) func(*url.URL) error {
	return func(u *url.URL) error {
		lm, err := idmclient.LoginMethods(client, u)
		if err != nil {
			return err
		}
		if lm.UbuntuSSOOAuth != "" {
			var tok *usso.SSOData
			var err error
			if tok, err = ReadToken(tokenPath); err != nil {
				tok, err = LoginUSSO(ctx, true, tokenPath)
				if err != nil {
					return err
				}
			}
			return idmclient.UssoOAuthVisit(client, lm.UbuntuSSOOAuth, tok, u)
		}
		return httpbakery.OpenWebBrowser(u)
	}
}
