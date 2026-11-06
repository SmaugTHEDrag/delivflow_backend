# Authentication API and frontend contract

The backend uses stateless Spring Security OAuth2 Resource Server authentication.
Keycloak authenticates credentials and owns password policy, email verification,
access/refresh-token issuance, and refresh-session revocation. Protected backend
APIs accept only `Authorization: Bearer <access-token>`; they do not create or
use an HTTP session. PostgreSQL stores profile data only and never stores
passwords or tokens.

## Register → Verify Email → Login → Refresh → Logout

1. **Register** with `POST /api/auth/register`:
   ```json
   {
     "username": "thainguyen",
     "email": "thai@example.com",
     "password": "StrongPassword123!",
     "firstName": "Thai",
     "lastName": "Nguyen"
   }
   ```
   Username and normalized email must both be unique. The backend sends the
   supplied username, first name, and last name to Keycloak as separate fields,
   then saves those fields and the Keycloak user ID in PostgreSQL. Passwords
   are sent directly to Keycloak and are never saved locally.
2. **Verify Email** using the verification link sent by Keycloak. Until Keycloak
   reports `email_verified=true`, the account cannot complete login or call
   protected APIs. After verification, the first successful login marks the
   local profile `ACTIVE` and `emailVerified=true`.
3. **Login** with `POST /api/auth/login` using the registered email/password:
   ```json
   {"email":"thai@example.com","password":"StrongPassword123!"}
   ```
   On success, the JSON `data` contains `accessToken`, `tokenType`,
   `expiresIn` (the value returned by Keycloak), and `user`. The refresh token is
   never returned in JSON; it is set in the `DELIVFLOW_REFRESH` HttpOnly cookie.
   Keycloak must be configured with a short access-token lifespan (recommended
   5 minutes); the API reports the actual expiration returned by Keycloak.
4. **Call protected APIs** with:
   ```http
   Authorization: Bearer <accessToken>
   ```
   Keep the access token only in application memory. Do not write either token
   to `localStorage`, `sessionStorage`, URLs, logs, or PostgreSQL.
5. **Refresh** with `POST /api/auth/refresh`. Send the refresh cookie
   automatically (`credentials: "include"` / `withCredentials: true`) and send
   the CSRF token header described below. The backend validates the refresh
   token with Keycloak, checks the resulting access token and local account,
   returns the new access token and actual expiry, and replaces the cookie if
   Keycloak rotated the refresh token. Invalid, expired, or revoked tokens are
   rejected with `401`.
6. **Logout** with `POST /api/auth/logout`, also including credentials and the
   CSRF header. The backend terminates the Keycloak refresh session, clears the
   cookie, and returns success. The frontend should also discard its in-memory
   access token. A Keycloak service outage returns an error rather than claiming
   that revocation succeeded, but the cookie is still cleared.

## CSRF, cookies, and CORS

Refresh and logout are cookie-authenticated and require CSRF protection. First
call `GET /api/auth/csrf`, retain its token in memory, then send it using the
returned header name (`X-CSRF-TOKEN` by default) on both POST requests. The CSRF cookie is
not an authentication credential. Register and login do not require a CSRF
token.

The refresh cookie is `HttpOnly`, `Secure` by default, scoped to `/api/auth`,
and `SameSite=Lax` by default. For a cross-site HTTPS frontend, configure
`AUTH_REFRESH_COOKIE_SAME_SITE=None` and keep `AUTH_REFRESH_COOKIE_SECURE=true`.
Configure `CORS_ALLOWED_ORIGINS` with the exact frontend origins; wildcard
origins are not supported with credentials.

The frontend should keep access tokens in memory, send them as Bearer tokens,
and on an eligible `401` attempt one refresh with credentials and the CSRF
header before retrying the original request once. Do not persist the refresh
token or attempt to read it from JavaScript.

## JWT validation and Keycloak setup

Spring Security validates the JWT signature using Keycloak's JWKS, issuer, and
expiration. Set `KEYCLOAK_EXPECTED_AUDIENCES` to a comma-separated audience
allowlist when the realm/client is configured to issue an API audience; when
set, tokens without a matching audience are rejected. Realm roles map to
`ROLE_*` authorities and existing method-level authorization remains enforced.
The JWT subject must match the local `keycloakId`, and the account must be
active and verified.

Configure `KEYCLOAK_ISSUER_URI`, `KEYCLOAK_BASE_URL`, `KEYCLOAK_REALM`,
`KEYCLOAK_BACKEND_CLIENT_ID`, and `KEYCLOAK_BACKEND_CLIENT_SECRET`. The
confidential backend client needs service-account permissions for user
management and Direct Access Grants enabled for this password-login contract.
The client secret stays on the backend and must never be exposed to React.

This repository contains the backend only; React integration is described above
but no frontend source is present to modify.

## Profile migration

Flyway V4 preserves the previous `display_name` text by splitting it at its
first space into `first_name` and `last_name`, uses the previous email-based
Keycloak username for existing accounts, and promotes the existing Keycloak subject
to `keycloak_id`. The obsolete `display_name`, issuer, and subject columns are
removed only after backfilling. Rows that cannot satisfy the new required email
or Keycloak identity constraints cause the migration to fail visibly rather
than being silently discarded.
