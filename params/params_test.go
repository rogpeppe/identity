// Copyright 2015 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package params_test

import (
	gc "gopkg.in/check.v1"

	"gopkg.in/CanonicalLtd/candidclient.v1/params"
)

type paramsSuite struct{}

var _ = gc.Suite(&paramsSuite{})

var usernameUnmarshalTests = []struct {
	username    string
	expectError string
}{{
	username: "user",
}, {
	username: "admin@candid",
}, {
	username: "agent@admin@candid",
}, {
	username:    "invalid username",
	expectError: `illegal username "invalid username"`,
}, {
	username:    "toolongusername_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef_",
	expectError: "username longer than 256 characters",
}}

func (s *paramsSuite) TestUsernameTextUnmarshal(c *gc.C) {
	for i, test := range usernameUnmarshalTests {
		c.Logf("%d. %s", i, test.username)
		u := new(params.Username)
		err := u.UnmarshalText([]byte(test.username))
		if test.expectError == "" {
			c.Assert(err, gc.IsNil)
			c.Assert(*u, gc.Equals, params.Username(test.username))
		} else {
			c.Assert(err, gc.ErrorMatches, test.expectError)
			c.Assert(*u, gc.Equals, params.Username(""))
		}
	}
}
