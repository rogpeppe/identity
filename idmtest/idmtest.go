// Copyright 2015 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

// Package idmtest holds a mock implementation of the identity manager
// suitable for testing.
package idmtest

import (
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/juju/httprequest"
	"github.com/juju/idmclient"
	"github.com/juju/utils"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/net/context"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2-unstable/bakerytest"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery/agent"

	"github.com/juju/idmclient/params"
)

// Server represents a mock identity server.
// It currently serves only the discharge and groups endpoints.
type Server struct {
	// URL holds the URL of the mock identity server.
	// The discharger endpoint is located at URL/v1/discharge.
	URL *url.URL

	// PublicKey holds the public key of the mock identity server.
	PublicKey *bakery.PublicKey

	// Router holds the HTTP router used to
	// handle the server's HTTP requests. This
	// may be modified to add more handlers.
	Router *httprouter.Router

	// Bakery holds the macaroon bakery used by
	// the mock server.
	Bakery *bakery.Bakery

	discharger *bakerytest.InteractiveDischarger

	// mu guards the fields below it.
	mu          sync.Mutex
	users       map[string]*user
	defaultUser string
}

type user struct {
	groups []string
	key    *bakery.KeyPair
}

// NewServer runs a mock identity server. It can discharge
// macaroons and return information on user group membership.
// The returned server should be closed after use.
func NewServer() *Server {
	srv := &Server{
		users:  make(map[string]*user),
		Router: httprouter.New(),
	}
	srv.discharger = bakerytest.NewInteractiveDischarger(nil, http.HandlerFunc(srv.serveVisit))
	srv.discharger.SetChecker(httpbakery.ThirdPartyCaveatCheckerFunc(srv.checkThirdPartyCaveat))
	srv.discharger.Mux.Handle("/", srv.Router)
	u, err := url.Parse(srv.discharger.Location())
	if err != nil {
		panic(err)
	}
	srv.URL = u

	key, err := bakery.GenerateKey()
	if err != nil {
		panic(err)
	}
	srv.PublicKey = &key.Public
	for _, route := range reqServer.Handlers(srv.newHandler) {
		srv.Router.Handle(route.Method, route.Path, route.Handle)
	}
	srv.Bakery = bakery.New(bakery.BakeryParams{
		Locator:        srv,
		Key:            key,
		IdentityClient: srv.IDMClient("noone"),
	})
	return srv
}

func (srv *Server) newHandler(p httprequest.Params) (*handler, context.Context, error) {
	if err := srv.checkLogin(p.Context, p.Request); err != nil {
		return nil, nil, errgo.Mask(err, errgo.Any)
	}
	return &handler{srv}, p.Context, nil
}

func (srv *Server) checkLogin(ctx context.Context, req *http.Request) error {
	_, authErr := srv.Bakery.Checker.Auth(httpbakery.RequestMacaroons(req)...).Allow(context.TODO(), bakery.LoginOp)
	if authErr == nil {
		return nil
	}
	derr, ok := errgo.Cause(authErr).(*bakery.DischargeRequiredError)
	if !ok {
		return errgo.Mask(authErr)
	}
	version := httpbakery.RequestVersion(req)
	m, err := srv.Bakery.Oven.NewMacaroon(ctx, version, ages, derr.Caveats, derr.Ops...)
	if err != nil {
		return errgo.Notef(err, "cannot create macaroon")
	}
	return httpbakery.NewDischargeRequiredErrorWithVersion(m, "", authErr, version)
}

var reqServer = httprequest.Server{
	ErrorMapper: errToResp,
}

func errToResp(ctx context.Context, err error) (int, interface{}) {
	// Allow bakery errors to be returned as the bakery would
	// like them, so that httpbakery.Client.Do will work.
	if err, ok := errgo.Cause(err).(*httpbakery.Error); ok {
		return httpbakery.ErrorToResponse(ctx, err)
	}
	errorBody := errorResponseBody(err)
	status := http.StatusInternalServerError
	switch errorBody.Code {
	case params.ErrNotFound:
		status = http.StatusNotFound
	case params.ErrForbidden, params.ErrAlreadyExists:
		status = http.StatusForbidden
	case params.ErrBadRequest:
		status = http.StatusBadRequest
	case params.ErrUnauthorized, params.ErrNoAdminCredsProvided:
		status = http.StatusUnauthorized
	case params.ErrMethodNotAllowed:
		status = http.StatusMethodNotAllowed
	case params.ErrServiceUnavailable:
		status = http.StatusServiceUnavailable
	}
	return status, errorBody
}

// errorResponse returns an appropriate error response for the provided error.
func errorResponseBody(err error) *params.Error {
	errResp := &params.Error{
		Message: err.Error(),
	}
	cause := errgo.Cause(err)
	if coder, ok := cause.(errorCoder); ok {
		errResp.Code = coder.ErrorCode()
	} else if errgo.Cause(err) == httprequest.ErrUnmarshal {
		errResp.Code = params.ErrBadRequest
	}
	return errResp
}

type errorCoder interface {
	ErrorCode() params.ErrorCode
}

// Close shuts down the server.
func (srv *Server) Close() {
	srv.discharger.Close()
}

// PublicKeyForLocation implements bakery.PublicKeyLocator
// by returning the server's public key for all locations.
func (srv *Server) PublicKeyForLocation(loc string) (*bakery.PublicKey, error) {
	return srv.PublicKey, nil
}

// ThirdPartyInfo implements bakery.ThirdPartyLocator.ThirdPartyInfo.
func (srv *Server) ThirdPartyInfo(ctx context.Context, loc string) (bakery.ThirdPartyInfo, error) {
	return srv.discharger.ThirdPartyInfo(ctx, loc)
}

// UserPublicKey returns the key for the given user.
// It panics if the user has not been added.
func (srv *Server) UserPublicKey(username string) *bakery.KeyPair {
	u := srv.user(username)
	if u == nil {
		panic("no user found")
	}
	return u.key
}

// IDMClient returns an identity manager client that takes
// to the given server as the given user name.
func (srv *Server) IDMClient(username string) *idmclient.Client {
	c, err := idmclient.New(idmclient.NewParams{
		BaseURL:       srv.URL.String(),
		AgentUsername: username,
		Client:        srv.Client(username),
	})
	if err != nil {
		panic(err)
	}
	return c
}

// Client returns a bakery client that will discharge as the given user.
// If the user does not exist, it is added with no groups.
func (srv *Server) Client(username string) *httpbakery.Client {
	c := httpbakery.NewClient()
	u := srv.user(username)
	if u == nil {
		srv.AddUser(username)
		u = srv.user(username)
	}
	c.Key = u.key
	// Note that this duplicates the SetUpAuth that idmclient.New will do
	// but that shouldn't matter as SetUpAuth is idempotent.
	agent.SetUpAuth(c, srv.URL.String(), username)
	return c
}

// SetDefaultUser configures the server so that it will discharge for
// the given user if no agent-login cookie is found. The user does not
// need to have been added. Note that this will bypass the
// VisitURL logic.
//
// If the name is empty, there will be no default user.
func (srv *Server) SetDefaultUser(name string) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.defaultUser = name
}

// AddUser adds a new user that's in the given set of groups.
// If the user already exists, the given groups are
// added to that user's groups.
func (srv *Server) AddUser(name string, groups ...string) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	u := srv.users[name]
	if u == nil {
		key, err := bakery.GenerateKey()
		if err != nil {
			panic(err)
		}
		srv.users[name] = &user{
			groups: groups,
			key:    key,
		}
		return
	}
	for _, g := range groups {
		found := false
		for _, ug := range u.groups {
			if ug == g {
				found = true
				break
			}
		}
		if !found {
			u.groups = append(u.groups, g)
		}
	}
}

// RemoveUsers removes all added users and resets the
// default user to nothing.
func (srv *Server) RemoveUsers() {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.users = make(map[string]*user)
	srv.defaultUser = ""
}

// RemoveUser removes the given user.
func (srv *Server) RemoveUser(user string) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	delete(srv.users, user)
}

func (srv *Server) user(name string) *user {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return srv.users[name]
}

type handler struct {
	srv *Server
}

type groupsRequest struct {
	httprequest.Route `httprequest:"GET /v1/u/:User/groups"`
	User              string `httprequest:",path"`
}

func (h handler) GetGroups(p httprequest.Params, req *groupsRequest) ([]string, error) {
	if err := h.checkRequest(p.Context, p.Request); err != nil {
		return nil, err
	}
	if u := h.srv.user(req.User); u != nil {
		return u.groups, nil
	}
	return nil, params.ErrNotFound
}

func (h handler) checkRequest(ctx context.Context, req *http.Request) error {
	_, err := h.srv.Bakery.Checker.Auth(httpbakery.RequestMacaroons(req)...).Allow(ctx, bakery.LoginOp)
	if err == nil {
		return nil
	}
	return h.maybeDischargeRequiredError(ctx, req, err)
}

func (h handler) maybeDischargeRequiredError(ctx context.Context, req *http.Request, checkErr error) error {
	derr, ok := errgo.Cause(checkErr).(*bakery.DischargeRequiredError)
	if !ok {
		return errgo.Mask(checkErr)
	}
	m, err := h.srv.Bakery.Oven.NewMacaroon(
		ctx,
		httpbakery.RequestVersion(req),
		time.Now().Add(time.Hour),
		derr.Caveats,
		derr.Ops...,
	)
	if err != nil {
		return errgo.Notef(err, "cannot create macaroon")
	}
	mpath, err := utils.RelativeURLPath(req.URL.Path, "/")
	if err != nil {
		return errgo.Mask(err)
	}
	err = httpbakery.NewDischargeRequiredErrorForRequest(m, mpath, checkErr, req)
	err.(*httpbakery.Error).Info.CookieNameSuffix = "idm"
	return err
}

var ages = time.Now().Add(time.Hour)

// serveVisit implements the default login handler which deals with agent login.
func (srv *Server) serveVisit(w http.ResponseWriter, req *http.Request) {
	// TODO take context from request.
	ctx := httpbakery.ContextWithRequest(context.TODO(), req)
	if err := srv.serveVisit0(ctx, w, req); err != nil {
		reqServer.WriteError(ctx, w, err)
		return
	}
	httprequest.WriteJSON(w, http.StatusOK, map[string]bool{"agent_login": true})
}

func (srv *Server) checkThirdPartyCaveat(ctx context.Context, req *http.Request, cav *bakery.ThirdPartyCaveatInfo) ([]checkers.Caveat, error) {
	srv.mu.Lock()
	defaultUser := srv.defaultUser
	srv.mu.Unlock()
	_, _, err := agent.LoginCookie(req)
	if err == nil || defaultUser == "" {
		return srv.discharger.CheckThirdPartyCaveat(ctx, req, cav)
	}
	return []checkers.Caveat{
		idmclient.UserDeclaration(srv.defaultUser),
	}, nil
}

func (srv *Server) serveVisit0(ctx context.Context, w http.ResponseWriter, req *http.Request) error {
	username, userPublicKey, err := agent.LoginCookie(req)
	if err != nil {
		return errgo.Notef(err, "cannot find agent login cookie")
	}
	loginOp := bakery.Op{
		Entity: "agent-" + username,
		Action: "login",
	}
	_, authErr := srv.Bakery.Checker.Auth(httpbakery.RequestMacaroons(req)...).Allow(ctx, loginOp)
	if authErr == nil {
		cavs := []checkers.Caveat{
			idmclient.UserDeclaration(username),
		}
		srv.discharger.FinishInteraction(ctx, w, req, cavs, nil)
		return nil
	}
	// Issue short-term macaroon that grants access for this particular
	// agent login operation.
	version := httpbakery.RequestVersion(req)
	m, err := srv.Bakery.Oven.NewMacaroon(ctx, version, ages, []checkers.Caveat{
		bakery.LocalThirdPartyCaveat(userPublicKey, version),
	}, loginOp)
	if err != nil {
		return errgo.Notef(err, "cannot create macaroon")
	}
	return httpbakery.NewDischargeRequiredErrorWithVersion(m, "", authErr, version)
}
