// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

// Package login defines functionality used for allowing clients to authenticate
// using USSO OAuth.
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

type tokenGetter interface {
	GetTokenWithOTP(username, password, otp, tokenName string) (*usso.SSOData, error)
}

// This is defined here to allow it to be stubbed out in tests
var ussoServer tokenGetter = usso.ProductionUbuntuSSOServer

// loginUSSO reads login parameters from ctxt.Stdin and then returns an
// oauth token from Ubuntu SSO.
func loginUSSO(ctx *cmd.Context, twoFactor bool, store TokenStore) (*usso.SSOData, error) {
	email, pass, otp, err := readUSSOParams(ctx, twoFactor)
	if err != nil {
		return nil, errgo.Notef(err, "cannot read login parameters")
	}
	tok, err := ussoServer.GetTokenWithOTP(email, pass, otp, "charm")
	if err != nil {
		return nil, errgo.Notef(err, "cannot get token")
	}
	if err := store.Put(tok); err != nil {
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
