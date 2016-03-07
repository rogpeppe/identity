// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package login

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/juju/cmd"
	"github.com/juju/usso"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/errgo.v1"
)

type TokenGetter interface {
	GetTokenWithOTP(email, password, otp, tokenName string) (*usso.SSOData, error)
}

var ussoServer (TokenGetter) = usso.ProductionUbuntuSSOServer

// LoginUSSO reads login parameters from ctxt.Stdin and then retrieves an
// oauth token from Ubuntu SSO.
func LoginUSSO(ctx *cmd.Context, twoFactor bool, store TokenStore) (*usso.SSOData, error) {
	email, pass, otp, err := readUSSOParams(ctx, twoFactor)
	if err != nil {
		return nil, errgo.Notef(err, "cannot read login parameters")
	}
	tok, err := ussoServer.GetTokenWithOTP(email, pass, otp, "charm")
	if err != nil {
		return nil, errgo.Notef(err, "cannot get token")
	}
	if err := store.SaveToken(tok); err != nil {
		return nil, errgo.Notef(err, "cannot save token")
	}
	return tok, nil
}

func readPassword(ctx *cmd.Context, br *bufio.Reader) (string, error) {
	fmt.Fprint(ctx.Stderr, "Password: ")
	stdin, ok := ctx.Stdin.(*os.File)
	if !ok || !terminal.IsTerminal(int(stdin.Fd())) {
		return br.ReadString('\n')
	}
	pass, err := terminal.ReadPassword(int(stdin.Fd()))
	return string(pass), err
}

func readUSSOParams(ctx *cmd.Context, twoFactor bool) (email, password, otp string, err error) {
	fmt.Fprintln(ctx.Stderr, "Login to https://jujucharms.com:")
	br := bufio.NewReader(ctx.Stdin)
	fmt.Fprint(ctx.Stderr, "Username: ")
	email, err = br.ReadString('\n')
	if err != nil {
		return "", "", "", errgo.Notef(err, "cannot read email address")
	}
	email = strings.TrimSuffix(email, "\n")
	pass, err := readPassword(ctx, br)
	if err != nil {
		return "", "", "", errgo.Notef(err, "cannot read password")
	}
	pass = strings.TrimSuffix(pass, "\n")
	fmt.Fprintln(ctx.Stderr)
	if twoFactor {
		fmt.Fprint(ctx.Stderr, "Two-factor auth (Enter for none): ")
		var err error
		otp, err = br.ReadString('\n')
		if err != nil {
			return "", "", "", errgo.Notef(err, "cannot read verification code address")
		}
		otp = strings.TrimSuffix(otp, "\n")
	}
	return email, pass, otp, nil
}

// TokenStore defines the interface for something that can store and retrieve oauth tokens.
type TokenStore interface {
	// SaveToken stores an Ubuntu SSO OAuth token.
	SaveToken(tok *usso.SSOData) error
	// ReadToken retrieves an Ubuntu SSO OAuth token from store
	ReadToken() (*usso.SSOData, error)
}

// FileTokenStore implements the TokenStore interface by storing the oauth token
// in a json encoded format at the file path.
type FileTokenStore struct {
	path string
}

// NewFileTokenStore returns a new FileTokenStore for
// storing the token in a json encoded file.
func NewFileTokenStore(path string) *FileTokenStore {
	return &FileTokenStore{path}
}

// SaveToken stores an Ubuntu SSO OAuth token.
func (f *FileTokenStore) SaveToken(tok *usso.SSOData) error {
	data, err := json.Marshal(tok)
	if err != nil {
		return errgo.Notef(err, "cannot marshal token")
	}
	if err := ioutil.WriteFile(f.path, data, 0600); err != nil {
		return errgo.Notef(err, "cannot write file")
	}
	return nil
}

// ReadToken retrieves an Ubuntu SSO OAuth token from store
func (f *FileTokenStore) ReadToken() (*usso.SSOData, error) {
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
