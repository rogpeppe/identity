// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

// Package ussomacaroon provides a client that can authenticate with an
// identity server by discharging macaroons on an Ubuntu SSO server.
package ussodischarge

import (
	"net/url"

	"github.com/juju/httprequest"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"
	"gopkg.in/macaroon.v2-unstable"
)

const protocolName = "usso_discharge"

// Macaroon returns a macaroon from the identity provider at the given
// URL, which can be discharged using a Discharger. If doer is non-nil
// then it will be used to collect the macaroon.
func Macaroon(doer httprequest.Doer, url string) (*macaroon.Macaroon, error) {
	client := &httprequest.Client{
		Doer: doer,
	}
	var resp MacaroonResponse
	if err := client.Get(url, &resp); err != nil {
		return nil, errgo.Notef(err, "cannot get macaroon")
	}
	return resp.Macaroon, nil
}

// Visitor is an httpbakery.Visitor that will login using a macaroon
// discharged by an Ubuntu SSO service.
type Visitor struct {
	f func(*httpbakery.Client, string) (macaroon.Slice, error)
}

// NewVisitor creates a Visitor which uses a macaroon previously collected
// with Macaroon and discharged by the requisit Ubuntu SSO service to log
// in. The discharged macaroon to use will be requested from the given
// function when required.
func NewVisitor(f func(client *httpbakery.Client, url string) (macaroon.Slice, error)) *Visitor {
	return &Visitor{
		f: f,
	}
}

// VisitWebPage implements httpbakery.Visitor.VisitWebPage by using a
// macaroon previously discharged by a trusted Ubuntu SSO service as a
// login token.
func (v *Visitor) VisitWebPage(client *httpbakery.Client, methodURLs map[string]*url.URL) error {
	if methodURLs[protocolName] == nil {
		return httpbakery.ErrMethodNotSupported
	}
	url := methodURLs[protocolName].String()
	ms, err := v.f(client, url)
	if err != nil {
		return errgo.Mask(err, errgo.Any)
	}
	cl := httprequest.Client{
		Doer: client,
	}
	err = cl.CallURL(url, &LoginRequest{
		Login: Login{
			Macaroons: ms,
		},
	}, nil)
	return errgo.Mask(err)
}

// Discharger is a client that can discharge Ubuntu SSO third-party
// caveats.
type Discharger struct {
	// Email contains the email address of the user.
	Email string

	// Password contains the password of the user.
	Password string

	// OTP contains the verification code of the user.
	OTP string

	// Doer will be used to perform the discharge if non-nil.
	Doer httprequest.Doer
}

// AcquireDischarge discharges the given Ubuntu SSO third-party caveat using the
// user information from the Discharger.
func (d *Discharger) AcquireDischarge(cav macaroon.Caveat) (*macaroon.Macaroon, error) {
	client := httprequest.Client{
		BaseURL: cav.Location,
		Doer:    d.Doer,
	}
	req := &ussoDischargeRequest{
		Discharge: ussoDischarge{
			Email:    d.Email,
			Password: d.Password,
			OTP:      d.OTP,
			CaveatID: string(cav.Id),
		},
	}
	var resp ussoDischargeResponse
	if err := client.Call(req, &resp); err != nil {
		return nil, errgo.Mask(err)
	}
	return &resp.Macaroon.Macaroon, nil
}

// DischargeAll discharges the given macaroon which is assumed to only
// have third-party caveats addressed to an Ubuntu SSO server.
func (d *Discharger) DischargeAll(m *macaroon.Macaroon) (macaroon.Slice, error) {
	ms, err := bakery.DischargeAll(m, d.AcquireDischarge)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return ms, nil
}
