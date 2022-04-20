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
		{Claims{"SEB", 1650489053, 1650460133}, "invalid iss"},
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

func TestToken_VerifySignature(t *testing.T) {
	token, _ := PreprocessJWT("eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.zBlLlmRrUxx4SJPUbV37Q1joRcI9EW13grnKduK3wtYKmDXbgDpF1cZ6B-2Jsm5RB8REmMiLpGms-EjXhgnyh2TSHE-9W2gA_jvshegLWtwRVDX40ODSkTb7OVuaWgiy9y7llvcknFBTIg-FnVPVpXMmeV_pvwQyhaz1SSwSPrDyxEmksz1hq7YONXhXPpGaNbMMeDTNP_1oj8DZaqTIL9TwV8_1wb2Odt_Fy58Ke2RVFijsOLdnyEAjt2n9Mxihu9i3PhNBkkxa2GbnXBfq3kzvZ_xxGGopLdHhJjcGWXO-NiwI9_tiu14NRv4L2xC0ItD9Yz68v2ZIZEp_DuzwRQ")
	publicKey, _ := createPublicKey("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB")
	err := token.VerifySignature(publicKey)
	if err != nil {
		t.Error("Signature should be valid")
	}
}
