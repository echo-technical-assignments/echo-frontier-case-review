# OpenID Connect provider accepts an ID token whose signature is never verified (goth <= 1.82.0)

| | |
|---|---|
| Package | `github.com/markbates/goth` (golang) |
| Where | `decodeJWT` / `validateClaims` / `Provider.FetchUser` in `providers/openidConnect/openidConnect.go` |
| Affected | >= 1.38.0 <= 1.82.0 (tested only at 1.82.0, commit 6c7fc31) |
| Fixed | none |
| Public ID | none (no CVE, no GHSA), checked 2026-11-14 |
| CWE | CWE-347, Improper Verification of Cryptographic Signature |
| CVSS 3.1 | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` → **7.4 (High)** |

## Summary

**The library.** Goth is a Go package that wraps OAuth2 and OpenID Connect authentication for web
applications: an app registers providers, sends the user to the identity provider, and gets a
populated `goth.User` back. The direction that matters here is the consuming side: goth is the
client that reads the identity provider's responses.

**The defect.** The OpenID Connect provider promises to authenticate the user from the ID token the
identity provider returns. It never checks that token's signature: **the JWT's header and signature
segments are discarded, and only the payload is decoded**. The validation that does run compares
`aud` against the configured client key and `iss` against the configured issuer (both non-secret
values an attacker copies freely) and checks that `exp` is in the future. The `jwks_uri` the
discovery document advertises is never fetched, so no key is ever used to verify anything. An empty
userinfo endpoint is a supported configuration, so no userinfo cross-check happens either.

In the flow an integrator drives exactly as `gothic.CompleteUserAuth` does, the session stores the
`id_token` verbatim from the token endpoint response, and `FetchUser` builds the authenticated
`goth.User` straight from the unverified claims.

A reference JWT verifier (golang-jwt, already a dependency of the project) rejects the same token
goth accepts, so this is a missing verification, not a parsing choice.

**The attack.** An attacker who can alter the token endpoint response (an identity provider
configured with an `http://` token endpoint, which the library accepts, or weakened TLS verification
in the supplied HTTP client) returns `x.<base64url payload>.x` as the `id_token`, with the victim's
`sub`, `email` and `name` in the payload. `FetchUser` returns a fully populated `goth.User` for that
victim identity, and **the attacker is logged in as anyone they name**.

### What we ran

The full public flow against a local identity provider whose token endpoint returns the forged
`id_token`, on `github.com/markbates/goth` built from `1.82.0 @ 6c7fc31`. Condensed from
`poc/main.go`, with the same calls and arguments:

```go
provider, _ := openidConnect.New(clientKey, clientSecret, callbackURL,
    issuer+"/.well-known/openid-configuration", "openid", "email", "profile")
sess, _ := provider.BeginAuth("state-123")
sess.Authorize(provider, url.Values{"code": {"attacker-authorization-code"}})
user, err := provider.FetchUser(sess) // the id_token was "x.<payload>.x"
```

| Input to `FetchUser` | 1.82.0 @ 6c7fc31 |
|---|---|
| control: genuinely signed ES256 ID token, same claims | accepted, but no forgery occurred: a reference verifier accepts it too, and the run states the effect is absent (exit 1) |
| forged ID token `x.<payload>.x` | **accepted: `UserID="victim-user-12345"`, `Email="victim@example.com"`, `Name="Victim User"`; a reference verifier rejects it (exit 0)** |

Captured lines (`logs/baseline.stdout.log`):

```
FetchUser SUCCEEDED on the token from the attacker-controlled token endpoint
authenticated user: UserID="victim-user-12345" Email="victim@example.com" Name="Victim User" Provider="openid-connect"
accepted token segments: header="x" payload_len=286 signature="x"
reference verifier (golang-jwt) rejects the forged token: true
```

The accepted token's header and signature segments were both the literal `x`; a 286-byte payload
carrying the victim's claims was all it took.

**Not shown:** a browser round trip, a real identity provider, or network interception; the run's
local identity provider plays the attacker-controlled token endpoint directly.

### Why this vector

| Metric | Value | Why |
|---|---|---|
| Attack Vector | Network | the attacker works through the token endpoint response, over the network |
| Attack Complexity | High | the attacker must first alter that response: an `http://` token endpoint or weakened TLS verification |
| Privileges Required | None | no account on the consuming application is needed |
| User Interaction | None | the forged token is consumed in the login flow without extra user action |
| Scope | Unchanged | the forged identity lands inside the same application doing the authentication |
| Confidentiality | High | the attacker is logged in as the victim, reading the victim's account |
| Integrity | High | the attacker acts as the victim, writing to the victim's account |
| Availability | None | nothing in the run touches availability |

## Am I affected?

**Yes**, if you use goth's OpenID Connect provider (`providers/openidConnect`, configured from a
discovery URL) and trust the `goth.User` that `FetchUser` returns, on `github.com/markbates/goth`
>= 1.38.0 <= 1.82.0.

**No**, if:
- you use goth only with its plain OAuth2 providers;
- you verify the ID token signature yourself before trusting the user.

Configuring a userinfo endpoint doesn't by itself rule this out (read, not run): its response must
then return the same `sub`, which the same attacker position controls.

## What this does not claim

- **Impact:** no real identity provider or service was attacked; the run used a local one whose
  responses the PoC controls.
- **Not run end to end:** no browser login; the PoC drives the same public API calls
  `gothic.CompleteUserAuth` makes.
- **Tested on:** one build, `1.82.0 @ 6c7fc31` (go1.27.4, linux/arm64); the releases below it in the
  range were read, not run. The lower bound is the discovered range, not a bisected one.
- **Not tested:** the variant with a configured userinfo endpoint and `SkipUserInfoRequest` false,
  which additionally requires control of that response.
- **The fix:** none exists, and no setting inside the library turns signature verification on.

## Verification

### Is this already known?

No CVE and no GHSA cover this, checked 2026-11-14. The tracker has open issues and PRs touching the
OpenID Connect provider, none about ID token signature verification:
[#649](https://github.com/markbates/goth/issues/649) (parse the JWKS URI out of the discovery
document), [#639](https://github.com/markbates/goth/issues/639) /
[#640](https://github.com/markbates/goth/pull/640) (auto-configure PKCE from discovery),
[#610](https://github.com/markbates/goth/pull/610) (respect the discovered auth style in token
refresh), [#283](https://github.com/markbates/goth/issues/283) (default HTTP client). #649 treats
the JWKS URI as something to parse, not as a missing step in token validation. No commit on master
changed the sink lines.

### Is it still unfixed?

Yes. Checked against master as of 2026-11-14: `decodeJWT` still splits on `.` and discards the
header and signature segments, and no JWKS fetch exists in the package.

### What does upstream think?

No published position. The repository has no SECURITY.md (root, `.github/`, `docs/` all absent),
GitHub private vulnerability reporting is off, the published security-advisories list is empty, and
no CONTRIBUTING.md or security.txt exists. The README's homepage points to a post saying the
project needs a new maintainer.

## Running the PoC

`poc/main.go` starts a local identity provider (`httptest`) that serves a discovery document, an
advertised but empty `jwks_uri`, and a token endpoint returning the chosen `id_token`. It then runs
the consumer flow through the public API only: `openidConnect.New` → `BeginAuth` →
`Session.Authorize` → `FetchUser`.

- **Baseline:** the token endpoint returns the forged `x.<payload>.x` token. Exits 0 when
  `FetchUser` returns the victim identity for it.
- **Control:** the token endpoint returns a genuinely signed ES256 token with the same claims.
  Exits 1, stating the effect is absent because the accepted token was not forged.

```sh
git clone https://github.com/markbates/goth repo
git -C repo checkout 6c7fc319f1f5149273c813736418e5b27fce988e
OFFLINE= sh poc/run.sh baseline   # builds the consumer against repo/ and runs the forged-token arm
OFFLINE= sh poc/run.sh control    # same flow, genuinely signed token
```

Or use the `Dockerfile`, which does the same. The exact commands and exit codes of the captured
runs are in `logs/commands.jsonl`.
