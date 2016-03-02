package login

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

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
func LoginUSSO(ctx *cmd.Context, twoFactor bool, tokenPath string) (*usso.SSOData, error) {
	email, pass, otp, err := readUSSOParams(ctx, twoFactor)
	if err != nil {
		return nil, errgo.Notef(err, "cannot read login parameters")
	}
	tok, err := ussoServer.GetTokenWithOTP(email, pass, otp, "charm")
	if err != nil {
		return nil, errgo.Notef(err, "cannot get token")
	}
	if err := SaveToken(tokenPath, tok); err != nil {
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
	pass, err := readPassword(ctx, br)
	if err != nil {
		return "", "", "", errgo.Notef(err, "cannot read password")
	}
	fmt.Fprintln(ctx.Stderr)
	if twoFactor {
		fmt.Fprint(ctx.Stderr, "Two-factor auth (Enter for none): ")
		var err error
		otp, err = br.ReadString('\n')
		if err != nil {
			return "", "", "", errgo.Notef(err, "cannot read verification code address")
		}
	}
	return email[:len(email)-1], pass[:len(pass)-1], otp[:len(otp)-1], nil
}

// SaveToken stores an Ubuntu SSO OAuth token.
func SaveToken(path string, tok *usso.SSOData) error {
	data, err := json.Marshal(tok)
	if err != nil {
		return errgo.Notef(err, "cannot marshal token")
	}
	if err := ioutil.WriteFile(path, data, 0600); err != nil {
		return errgo.Notef(err, "cannot write file")
	}
	return nil
}

// ReadToken loads an Ubuntu SSO OAuth token from the given path
func ReadToken(path string) (*usso.SSOData, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errgo.Notef(err, "cannot read token")
	}
	var tok usso.SSOData
	if err := json.Unmarshal(data, &tok); err != nil {
		return nil, errgo.Notef(err, "cannot unmarshal token")
	}
	return &tok, nil
}
