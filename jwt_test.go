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
