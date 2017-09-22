package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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

	h := JWTHeader{
		Alg: "none",
	}
	p := JWTPayload{
		Iss:   *serverURL,
		Sub:   "dummysub",
		Aud:   "test",
		Exp:   secs + 1000,
		Iat:   secs,
		Nonce: nonce,
	}

	bh, _ := json.Marshal(h)
	bp, _ := json.Marshal(p)

	jwt := base64URLEncode(bh) + "." + base64URLEncode(bp) + "."

	t := Token{
		AccessToken:  newRandom(1512),
		TokenType:    "Bearer",
		RefreshToken: "dummyrefreshtoken",
		IDToken:      jwt,
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
