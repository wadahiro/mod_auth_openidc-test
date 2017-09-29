package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

var (
	serverURL = flag.String(
		"server_url",
		"http://localhost:8080",
		"OIDC Server URL",
	)
	redirectURL = flag.String(
		"redirect_url",
		"http://localhost/callback",
		"Redirect URL of the OIDC/OAuth2 client",
	)
	rawPublicKey = []byte(`-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA9DaKLQ7JDnqn6JceI5zf
SwAkj9zv23PUPSgGfRk+j3oUcwU/EJsy1mGaATUwrdM4q5f1/cmjZaQpstoFrpDm
raeNDijmFZ6/MJQqWdy3Kxx5sD+G4ZIqi+hIk8Inqx1IJNYewoNpDlIL4+2D45QC
mppkM9gnWNaQvNWr4mjVxFBxNSWu2dyVknRlgeSR9zgQMH9nahbSQaF4xujsrQFh
RGzJ7Ha2Sc13XEu2DR4JR8Cfu5B4LRbFqH3qxLmZp1+AhjQ/dr/BOKg1GjnUy4xL
zJfxIlBGISYP+VtA6HSmZgyt3nA4UI8HodQuv7sOiA6ZwldDuo4vRFeOaAamLA4o
TplnU/MhziYnJQZeOuCBu15dZxPLDbA3fJzu6BoCQaRsYFw35bu0c8i06I/IUZyD
MhvVG330KXp7ENr7WNx/Xl32aPNyxiT5VWS+1ropTELeTJd0LaUHmEAtNUEXLNBD
QMP8nJZBJ9UXElb/2XTZp7YeIZxHACFG/jUlRbO43nhPIM5q7hMlH8pPeEyLN8VC
24/BTVEyyS31ZPZklhmN0xS4yxzeqMNp4v+sL1ObheVNL3xuO+vyMbAW3+TQSuHy
z/HZQV/c+iGhiofM09ErOCZsrY/am9Hh+HhfvxR7zkz8RfMTcYr/F9zXWWuFi7IG
fvlbYJJylx+ou7AQiUiZ7r8CAwEAAQ==
-----END PUBLIC KEY-----`)
	rawSecretKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`)

	secretKey interface{}
	publicKey interface{}
)

var mu sync.RWMutex
var session = make(map[string]string)

type Metadata struct {
	Issuer                     string `json:"issuer"`
	AuthorizationEndpoint      string `json:"authorization_endpoint"`
	TokenEndpoint              string `json:"token_endpoint"`
	TokenIntrospectionEndpoint string `json:"token_introspection_endpoint"`
	UserinfoEndpoint           string `json:"userinfo_endpoint"`
	EndSessionEndpoint         string `json:"end_session_endpoint"`
	JwksURI                    string `json:"jwks_uri"`
	//CheckSessionIframe                         string   `json:"check_session_iframe"`
	GrantTypesSupported                    []string `json:"grant_types_supported"`
	ResponseTypesSupported                 []string `json:"response_types_supported"`
	SubjectTypesSupported                  []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported       []string `json:"id_token_signing_alg_values_supported"`
	UserinfoSigningAlgValuesSupported      []string `json:"userinfo_signing_alg_values_supported"`
	RequestObjectSigningAlgValuesSupported []string `json:"request_object_signing_alg_values_supported"`
	ResponseModesSupported                 []string `json:"response_modes_supported"`
	//RegistrationEndpoint                       string   `json:"registration_endpoint"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	ClaimsSupported                            []string `json:"claims_supported"`
	ClaimTypesSupported                        []string `json:"claim_types_supported"`
	ClaimsParameterSupported                   bool     `json:"claims_parameter_supported"`
	ScopesSupported                            []string `json:"scopes_supported"`
	RequestParameterSupported                  bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported               bool     `json:"request_uri_parameter_supported"`
}

type Key struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type Jwks struct {
	Keys []Key `json:"keys"`
}

type Token struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

type UserInfo struct {
	Sub  string `json:"sub"`
	Name string `json:"name"`
}

type JWTHeader struct {
	Alg string `json:"alg"`
}

type JWTPayload struct {
	Iss   string `json:"iss"`
	Sub   string `json:"sub"`
	Aud   string `json:"aud"`
	Exp   int64  `json:"exp"`
	Iat   int64  `json:"iat"`
	Nonce string `json:"nonce"`
}

func base64URLEncode(data []byte) string {
	var result = base64.URLEncoding.EncodeToString(data)
	return strings.TrimRight(result, "=")
}

func metadata(w http.ResponseWriter, r *http.Request) {
	log.Printf("Start /.well-known/openid-configuration")

	t := Metadata{
		Issuer:                            *serverURL,
		AuthorizationEndpoint:             *serverURL + "/auth",
		TokenEndpoint:                     *serverURL + "/token",
		UserinfoEndpoint:                  *serverURL + "/userinfo",
		EndSessionEndpoint:                *serverURL + "/logout",
		JwksURI:                           *serverURL + "/certs",
		GrantTypesSupported:               []string{"authorization_code"},
		ResponseTypesSupported:            []string{"code", "id_token", "code id_token"},
		IDTokenSigningAlgValuesSupported:  []string{"none"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
		ClaimsSupported:                   []string{"sub", "iss"},
		ScopesSupported:                   []string{"openid"},
	}
	json.NewEncoder(w).Encode(t)
}

func certs(w http.ResponseWriter, r *http.Request) {
	log.Printf("Start /certs")

	bs := make([]byte, 4)
	u := uint32(publicKey.(*rsa.PublicKey).E)
	binary.BigEndian.PutUint32(bs, u)

	k := Key{
		Kid: "dummykid",
		Kty: "RSA",
		Alg: "RS256",
		Use: "sig",
		N:   base64URLEncode(publicKey.(*rsa.PublicKey).N.Bytes()),
		E:   base64URLEncode(bs),
	}
	j := Jwks{
		Keys: []Key{k},
	}

	json.NewEncoder(w).Encode(j)
}

func auth(w http.ResponseWriter, r *http.Request) {
	log.Printf("Start /auth")

	q := r.URL.Query()
	state := q["state"][0]
	code, _ := newUUID()

	nonce := q["nonce"][0]

	mu.Lock()
	session[code] = nonce
	mu.Unlock()

	http.Redirect(w, r, fmt.Sprintf(*redirectURL+"?state=%s&code=%s", state, code), http.StatusFound)
}

func token(w http.ResponseWriter, r *http.Request) {
	log.Printf("Start /token")

	r.ParseForm()
	code := r.Form["code"][0]

	mu.Lock()
	nonce := session[code]
	delete(session, "nonce")
	mu.Unlock()

	now := time.Now()
	secs := now.Unix()

	claims := jwt.MapClaims{
		"iss":   *serverURL,
		"sub":   "dummysub",
		"aud":   "test",
		"iat":   secs,
		"exp":   secs + 1000,
		"nonce": nonce,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		log.Printf("JWT Sign error!: %s", err)
		return
	}

	t := Token{
		AccessToken:  newRandom(1512),
		TokenType:    "Bearer",
		RefreshToken: "dummyrefreshtoken",
		IDToken:      tokenString,
	}

	json.NewEncoder(w).Encode(t)
}

func userinfo(w http.ResponseWriter, r *http.Request) {
	log.Printf("Start /userinfo")

	t := UserInfo{
		Sub:  "dummysub",
		Name: "dummyname",
	}
	json.NewEncoder(w).Encode(t)
}

func logout(w http.ResponseWriter, r *http.Request) {
	log.Printf("Start /logout")

	fmt.Fprintf(w, "Logout OK")
}

func app(w http.ResponseWriter, r *http.Request) {
	c := r.FormValue("code")
	if c != "" {
		i, err := strconv.Atoi(c)
		if err == nil {
			http.Error(w, "# HTTP Status Code Test: "+c, i)
		}
	}
	r.Write(w)
}

func main() {
	flag.Usage = func() {
		_, exe := filepath.Split(os.Args[0])
		fmt.Fprint(os.Stderr, "oidc-dummy-server.\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n\n  %s [options]\n\nOptions:\n\n", exe)
		flag.PrintDefaults()
	}
	flag.Parse()

	http.HandleFunc("/.well-known/openid-configuration", metadata)
	http.HandleFunc("/certs", certs)
	http.HandleFunc("/auth", auth)
	http.HandleFunc("/token", token)
	http.HandleFunc("/userinfo", userinfo)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/app", app)

	http.ListenAndServe(":8080", nil)
}

func newUUID() (string, error) {
	uuid := make([]byte, 16)
	n, err := io.ReadFull(rand.Reader, uuid)
	if n != len(uuid) || err != nil {
		return "", err
	}
	// variant bits; see section 4.1.1
	uuid[8] = uuid[8]&^0xc0 | 0x80
	// version 4 (pseudo-random); see section 4.1.3
	uuid[6] = uuid[6]&^0xf0 | 0x40
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]), nil
}

func newRandom(size int64) string {
	b := make([]byte, size)
	rand.Read(b)

	return base64.URLEncoding.EncodeToString(b)
}

func parseKeys(rawSK []byte, rawPK []byte) error {
	var err error
	privateKeyBlock, _ := pem.Decode(rawSK)
	if privateKeyBlock == nil {
		return errors.New("Private key cannot decode")
	}
	if privateKeyBlock.Type != "RSA PRIVATE KEY" {
		return errors.New("Private key type is not rsa")
	}
	secretKey, err = x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return errors.New("Failed to parse private key")
	}

	publicKeyBlock, _ := pem.Decode(rawPK)
	if publicKeyBlock == nil {
		return errors.New("Public key cannot decode")
	}
	if publicKeyBlock.Type != "PUBLIC KEY" {
		return errors.New("Public key type is invalid")
	}

	publicKey, err = x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return errors.New("Failed to parse public key")
	}

	return nil
}

func init() {
	err := parseKeys(rawSecretKey, rawPublicKey)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
