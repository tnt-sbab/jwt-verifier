package jwt_verifier

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	ErrInvalidJWT     = errors.New("invalid jwt token")
	ErrInvalidISS     = errors.New("invalid iss")
	ErrInvalidEXP     = errors.New("invalid exp")
	ErrInvalidNBF     = errors.New("invalid nbf")
	ErrInvalidKey     = errors.New("invalid key")
	ErrEmptyISS       = errors.New("Issuer cannot be empty")
	ErrEmptyPublicKey = errors.New("PublicKey cannot be empty")
	ErrPublicKey      = errors.New("key is not a valid RSA public key")
)

type Config struct {
	PublicKey string
	Issuer    string
}

type JWTVerifier struct {
	next      http.Handler
	publicKey *rsa.PublicKey
	issuer    string
	name      string
}

type Token struct {
	header    string
	payload   string
	signature string
}

func CreateConfig() *Config {
	return &Config{
		PublicKey: "",
		Issuer:    "",
	}
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.PublicKey) == 0 {
		return nil, ErrEmptyPublicKey
	}
	if len(config.Issuer) == 0 {
		return nil, ErrEmptyISS
	}
	publicKey, err := createPublicKey(config.PublicKey)
	if err != nil {
		return nil, err
	}
	log.SetOutput(os.Stdout)
	return &JWTVerifier{
		next:      next,
		publicKey: publicKey,
		issuer:    config.Issuer,
		name:      name,
	}, nil
}

func (j *JWTVerifier) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	headerToken := req.Header.Get("Authorization")
	if len(headerToken) == 0 {
		j.next.ServeHTTP(rw, req)
		return
	}
	token, preprocessError := PreprocessJWT(headerToken)
	if preprocessError != nil {
		log.Println("Invalid token format:", preprocessError)
		http.Error(rw, "Not allowed", http.StatusForbidden)
		return
	}
	signatureError := token.VerifySignature(j.publicKey)
	if signatureError != nil {
		log.Println("JWT signature error:", signatureError)
		http.Error(rw, "Not allowed", http.StatusForbidden)
		return
	}
	claimsError := token.VerifyClaims(time.Now().Unix(), j.issuer)
	if claimsError != nil {
		log.Println("JWT claims error:", claimsError)
		http.Error(rw, "Not allowed", http.StatusForbidden)
		return
	}
	j.next.ServeHTTP(rw, req)
}

func PreprocessJWT(authHeader string) (Token, error) {
	cleanedJwt := strings.TrimPrefix(authHeader, "Bearer")
	cleanedJwt = strings.TrimSpace(cleanedJwt)
	parts := strings.Split(cleanedJwt, ".")
	var token Token
	if len(parts) != 3 {
		return token, ErrInvalidJWT
	}
	token.header = parts[0]
	token.payload = parts[1]
	token.signature = parts[2]
	return token, nil
}

func createPublicKey(publicKey string) (*rsa.PublicKey, error) {
	keyData := strings.Join([]string{"-----BEGIN PUBLIC KEY-----", publicKey, "-----END PUBLIC KEY-----"}, "\n")
	return ParseRSAPublicKeyFromPEM([]byte(keyData))
}

func ParseRSAPublicKeyFromPEM(key []byte) (*rsa.PublicKey, error) {
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrInvalidKey
	}
	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pkey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, ErrPublicKey
	}
	return pkey, nil
}

func (t Token) VerifySignature(publicKey *rsa.PublicKey) error {
	hash := crypto.SHA512
	digest := hash.New()
	digest.Write([]byte(t.headerAndPayload()))
	sig, err := base64.RawURLEncoding.DecodeString(t.signature)
	if err != nil {
		return err
	}
	return rsa.VerifyPKCS1v15(publicKey, hash, digest.Sum(nil), sig)
}

func (t Token) headerAndPayload() string {
	return strings.Join([]string{t.header, t.payload}, ".")
}

func (t Token) VerifyClaims(now int64, issuer string) error {
	payload, err := base64.RawURLEncoding.DecodeString(t.payload)
	if err != nil {
		return err
	}
	var claims Claims
	err = json.Unmarshal(payload, &claims)
	if err != nil {
		return err
	}
	return claims.Verify(now, issuer)
}

type Claims struct {
	Issuer    string `json:"iss"`
	ExpiresAt int64  `json:"exp"`
	NotBefore int64  `json:"nbf"`
}

func (c Claims) Verify(now int64, issuer string) error {
	if !c.VerifyIssuer(issuer) {
		return ErrInvalidISS
	}
	if !c.VerifyExpiresAt(now) {
		return ErrInvalidEXP
	}
	if !c.VerifyNotBefore(now) {
		return ErrInvalidNBF
	}
	return nil
}

func (c Claims) VerifyIssuer(issuer string) bool {
	return c.Issuer == issuer
}

func (c Claims) VerifyExpiresAt(now int64) bool {
	return now < c.ExpiresAt
}

func (c Claims) VerifyNotBefore(now int64) bool {
	return c.NotBefore <= now
}
