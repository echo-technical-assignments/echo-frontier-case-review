# OpenID Connect provider accepts an ID token whose signature is never verified

Draft report to the project's active maintainer by email (the repository has no security policy and
private vulnerability reporting is off).

| Field | Value |
|---|---|
| Package | `github.com/markbates/goth` (golang) |
| Affected | >= 1.38.0 <= 1.82.0 |
| Patched | None |
| Severity | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` (7.4 High) |
| CWEs | CWE-347 |

### Summary

`Provider.FetchUser` in `providers/openidConnect` builds the authenticated `goth.User` from the
ID token's claims without ever verifying the token's signature: `decodeJWT` discards the header
and signature segments, and no JWKS is fetched even though the discovery document advertises a
`jwks_uri`. In the flow we ran, a token endpoint response carrying `x.<base64url payload>.x` as
`id_token` (garbage header and signature, 286-byte payload) made `FetchUser` return
`UserID="victim-user-12345"`, `Email="victim@example.com"`, `Name="Victim User"`, while a
reference verifier (golang-jwt, already a dependency) rejects the same token.

The token endpoint's response is the only thing that authenticates the claims in an ID token.
Here, whoever controls that response names the user:

1. `providers/openidConnect/session.go:52-67` `Session.Authorize` performs the code exchange and
   stores the `id_token` from the token endpoint response verbatim.
2. `providers/openidConnect/openidConnect.go:510-523` `decodeJWT` splits the JWT on `.`, requires
   three parts, and decodes only the payload. **The header and signature segments are discarded;
   no key is ever used.**
3. `providers/openidConnect/openidConnect.go:318-346` `validateClaims` checks only `aud`, `iss`
   and `exp`, all values a forger sets freely.
4. `providers/openidConnect/openidConnect.go:351` `userFromClaims` fills `goth.User.UserID`,
   `Email` and `Name` from the unverified claims.

#### Reachability

- **Entry points:** `openidConnect.New` (discovery) → `BeginAuth` → `Session.Authorize` →
  `Provider.FetchUser`; the same path `gothic.CompleteUserAuth` drives.
- **Needs:** an attacker who can alter the token endpoint response, for example an identity
  provider configured with an `http://` token_endpoint, which the library accepts, or weakened
  TLS verification in the supplied `HTTPClient`.
- **Doesn't help:** a configured userinfo endpoint; its response must then return the same `sub`,
  which the same attacker position controls (read, not run).

### Impact

Any Go application that registers goth's OpenID Connect provider and trusts the `goth.User` that
`FetchUser` returns. The attacker chooses the victim identity carried in the forged claims, and
the application receives it as an authenticated user.

### CVE request

Please assign a CVE for this when you fix it, or let us know and we can assign one as a CNA. The
mechanism is CWE-347 (improper verification of cryptographic signature); the affected range is
>= 1.38.0 <= 1.82.0, read from the repository's git history, with no fixed release.

### Fix status

- **Upstream fix:** none; no CVE or GHSA as of 2026-11-14.
- **Suggested fix:** verify the ID token's signature before trusting its claims, using the
  `jwks_uri` already present in the discovery document: fetch the JWKS, select the key by the
  token header's `kid`, and verify before `validateClaims` runs (`not tested`). The project already
  depends on `github.com/golang-jwt/jwt/v5`, which can do the verification.
- **Same pattern elsewhere:** none found in the other providers, which don't decode ID tokens
  (read, not run).
