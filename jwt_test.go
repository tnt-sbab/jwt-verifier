package jwt_verifier

import (
	"testing"
)

func TestPreprocessJWT(t *testing.T) {
	tests := []struct {
		authHeader string
		token      Token
		err        string
	}{
		{"Bearer a.b.c", Token{"a", "b", "c"}, ""},
		{"c.d.e", Token{"c", "d", "e"}, ""},
		{"Bearer  a.b.c ", Token{"a", "b", "c"}, ""},
		{" c.d.e ", Token{"c", "d", "e"}, ""},
		{"Bearer a.b", Token{}, "invalid jwt token"},
		{"Bearer a.b.c.f", Token{}, "invalid jwt token"},
		{"a.b", Token{}, "invalid jwt token"},
		{"a.b.c.f", Token{}, "invalid jwt token"},
		{"", Token{}, "invalid jwt token"},
	}
	for _, row := range tests {
		token, err := PreprocessJWT(row.authHeader)
		if token != row.token {
			t.Errorf("Auth header '%s' should be parsed to token '%s' but was '%s'", row.authHeader, row.token, token)
		}
		if err != nil && err.Error() != row.err {
			t.Errorf("Expected auth header '%s' to generate error '%v' but was '%v'", row.authHeader, row.err, err)
		}
	}
}

func TestClaims_Verify(t *testing.T) {
	tests := []struct {
		claims Claims
		err    string
	}{
		{Claims{"SBAB", 1650489053, 1650460133}, ""},
		{Claims{"SWEDBANK", 1650489053, 1650460133}, "invalid iss"},
		{Claims{"", 1650489053, 1650460133}, "invalid iss"},
		{Claims{"SBAB", 1650460253, 1650460133}, "invalid exp"},
		{Claims{"SBAB", 1650460254, 1650460133}, ""},
		{Claims{"SBAB", 1650489053, 1650460253}, ""},
		{Claims{"SBAB", 1650489053, 1650460252}, "invalid nbf"},
	}
	for _, row := range tests {
		err := row.claims.Verify(1650460253, "SBAB")
		if err != nil && err.Error() != row.err {
			t.Errorf("Claims %v expected error '%s' but vas '%s'", row.claims, row.err, err)
		}
	}
}
