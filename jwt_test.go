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
		{Claims{"SBAB", 1650489053, 1650460254}, "invalid nbf"},
	}
	for _, row := range tests {
		err := row.claims.Verify(1650460253, "SBAB")
		if err != nil && err.Error() != row.err || (err == nil && row.err != "") {
			t.Errorf("Claims %v expected error '%s' but vas '%s'", row.claims, row.err, err)
		}
	}
}

func TestToken_VerifySignatureValid1(t *testing.T) {
	token, _ := PreprocessJWT("eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.zBlLlmRrUxx4SJPUbV37Q1joRcI9EW13grnKduK3wtYKmDXbgDpF1cZ6B-2Jsm5RB8REmMiLpGms-EjXhgnyh2TSHE-9W2gA_jvshegLWtwRVDX40ODSkTb7OVuaWgiy9y7llvcknFBTIg-FnVPVpXMmeV_pvwQyhaz1SSwSPrDyxEmksz1hq7YONXhXPpGaNbMMeDTNP_1oj8DZaqTIL9TwV8_1wb2Odt_Fy58Ke2RVFijsOLdnyEAjt2n9Mxihu9i3PhNBkkxa2GbnXBfq3kzvZ_xxGGopLdHhJjcGWXO-NiwI9_tiu14NRv4L2xC0ItD9Yz68v2ZIZEp_DuzwRQ")
	publicKey, _ := createPublicKey("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB")
	err := token.VerifySignature(publicKey)
	if err != nil {
		t.Errorf("Signature should be valid [%s]", err.Error())
	}
}

func TestToken_VerifySignatureValid2(t *testing.T) {
	token, _ := PreprocessJWT("eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.XHQCQdljxgiRttsFXVuTw1VjXOuvKrSAaud1H1WgXeFp5g0jSpeX8cevBqQBq8QODheiY9UeA1RJyJqrYBuF0uBJklyO6T4XGIx5H700XlLCOa7jtPp1_2VJlfenbsy4IQ-hBnY34PCsmoHrAcoHJsQl5W5fu9WjbEeeX9ZGQsX_CWcbJDNh_Z58E4DYBHl5IfYJFtvjwHsGelJLSeZwBpeF1EriSwmIpJdV13b10Qiv7BcZ_hTMWBS3ep1uiDUWRpqwjevZ4Mc-GHdqMAwoofdy4Q7enjz7q7KyXxszESh26CFZnwWtwoX9M46dAmI8NFcI1jwR26B9meJUIkkA5H4rZB4wLUycrFBP5bfrbt_qXnXs3YqVBm_p0GneB_SxIytDLgrdICIisZlh3A6Wztbo8MAQKtjqHQohZjHfXLY0WWAuO1jt7pzmVz-VQWK8uG0-IaMHVpSS0dkLmB3Y6Gd--8Maiak5HuiJ0ztX27p2-a5Uhn48Z--anvQYIo346roo1qC_teudS3DJdHFoZvmKjpKE0Cvfh5dRU3wf995PQOIptxlD3VH9uMZgfrTLGOqA7yZ34nZQ2YgI6vIzjY8VoYeyCYTYCOzfNijRkf4cago1SEOt-CGST78r37biqTnv7k4N9JWo9NW6CE0y3NBZrJobjvTRQenr7Al-NgE")
	publicKey, _ := createPublicKey("MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAoWiybiEdSvPB8YoF0vakUhBVqNSri8lIPBjC0Zc89dkm9p6Bhgn/SPha/U7lUPMjDoMckNhBeKqxIE7X3ikF6r8vVr5p++DWRoYU0WOYkFe2nbAAPjKsDu79FP+I7f49cfoCzq9+xmd3CbdSEFVmR6+G0kVI2TKZufOG3IZveILRSdHebgrrw+gPAedXX3NLFASrMh0616+1ia6YXY5kdtahoVbCBZ0FTLWwJuh6JT8Y6YVnHmcGOODbM88AZxYFmAzPEXx/pWucD3gJmeO85RDlrsrgZJ7Bvg/2Icx60BhF+7A8tYWZPuiKhr5e+I83ADq9bxuERBNW0bKfXogmLMocKyzyZ3Xfvy4yZm0GWs1tNmBJSl8WAn91K4ojEm+StLgZ69R+r+061JbHFMb7dbwnKnqUoIotyX/msxi4VN8wlIjztfan+XXCM/WDLGKdVIpoKEoSpCV3o95bQwaoZQOPAXn1dguQ3n8yCAMp+qz/WExlRZnkj4sxV8eaN1iFdM2QCP3YZOR4U8vpTWIGDQkzcsQzYVCuYn/pdmhyqTU4yP0aL+xZNek8EJ1pUE1cRR1deumLMXCkGy9gCo6TiSyn/ez1U5vSiPJmfv5hhlnscbpU6Vly/rAte9uaxmQz4JyaZl4M9En/HMwHCjhiz3XOOqJ/LfPvkDV+cvOdumECAwEAAQ==")
	err := token.VerifySignature(publicKey)
	if err != nil {
		t.Errorf("Signature should be valid [%s]", err.Error())
	}
}

func TestToken_VerifySignatureInvalid(t *testing.T) {
	token, _ := PreprocessJWT("eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.zBlLlmRrUxx4SJPUbV37Q1joRcI9EW13grnKduK3wtYKmDXbgDpF1cZ6B-2Jsm5RB8REmMiLpGms-EjXhgnyh2TSHE-9W2gA_jvshegLWtwRVDX40ODSkTb7OVuaWgiy9y7llvcknFBTIg-FnVPVpXMmeV_pvwQyhaz1SSwSPrDyxEmksz1hq7YONXhXPpGaNbMMeDTNP_1oj8DZaqTIL9TwV8_1wb2Odt_Fy58Ke2RVFijsOLdnyEAjt2n9Mxihu9i3PhNBkkxa2GbnXBfq3kzvZ_xxGGopLdHhJjcGWXO-NiwI9_tiu14NRv4L2xC0ItD9Yz68v2ZIZEp_DuzwRQ")
	publicKey, _ := createPublicKey("MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAoWiybiEdSvPB8YoF0vakUhBVqNSri8lIPBjC0Zc89dkm9p6Bhgn/SPha/U7lUPMjDoMckNhBeKqxIE7X3ikF6r8vVr5p++DWRoYU0WOYkFe2nbAAPjKsDu79FP+I7f49cfoCzq9+xmd3CbdSEFVmR6+G0kVI2TKZufOG3IZveILRSdHebgrrw+gPAedXX3NLFASrMh0616+1ia6YXY5kdtahoVbCBZ0FTLWwJuh6JT8Y6YVnHmcGOODbM88AZxYFmAzPEXx/pWucD3gJmeO85RDlrsrgZJ7Bvg/2Icx60BhF+7A8tYWZPuiKhr5e+I83ADq9bxuERBNW0bKfXogmLMocKyzyZ3Xfvy4yZm0GWs1tNmBJSl8WAn91K4ojEm+StLgZ69R+r+061JbHFMb7dbwnKnqUoIotyX/msxi4VN8wlIjztfan+XXCM/WDLGKdVIpoKEoSpCV3o95bQwaoZQOPAXn1dguQ3n8yCAMp+qz/WExlRZnkj4sxV8eaN1iFdM2QCP3YZOR4U8vpTWIGDQkzcsQzYVCuYn/pdmhyqTU4yP0aL+xZNek8EJ1pUE1cRR1deumLMXCkGy9gCo6TiSyn/ez1U5vSiPJmfv5hhlnscbpU6Vly/rAte9uaxmQz4JyaZl4M9En/HMwHCjhiz3XOOqJ/LfPvkDV+cvOdumECAwEAAQ==")
	err := token.VerifySignature(publicKey)
	if err == nil {
		t.Error("Signature verification should fail since incorrect public key is used to verify the JWT signature")
	} else if err.Error() != "crypto/rsa: verification error" {
		t.Errorf("Signature should not be valid. Expected 'rypto/rsa: verification error' but got [%s]", err.Error())
	}
}
