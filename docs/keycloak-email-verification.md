# Keycloak email verification

DelivFlow delegates verification email delivery and action-token creation to Keycloak. Spring Boot does not send verification email. A new local profile remains `PENDING_VERIFICATION` until the backend re-fetches the corresponding Keycloak user and confirms `emailVerified=true`.

## Keycloak Admin Console

1. **Realm Settings → Email:** configure the SMTP host, port, sender address, credentials, and TLS options for your mail provider, then use Keycloak's test-email option to confirm delivery.
2. **Realm Settings → Login:** enable **Verify email** so Keycloak enforces verification as part of the account flow.
3. **Clients → delivflow-backend → Credentials:** enable the confidential service-account client and set its secret as `KEYCLOAK_BACKEND_CLIENT_SECRET`.
4. **Clients → delivflow-backend → Service account roles:** assign the `realm-management` client roles `manage-users` and `view-users`. The backend uses these roles to create/delete users and re-fetch their verification state.
5. **Clients → the configured email-verification client → Settings:** allow the exact redirect URI in `KEYCLOAK_EMAIL_VERIFICATION_REDIRECT_URI` (and the corresponding web origin where required). Do not use a wildcard redirect in production.
6. Configure an action-token lifetime appropriate for your security policy. The backend supplies `KEYCLOAK_EMAIL_VERIFICATION_LIFESPAN_SECONDS` on each action-email request.

The backend sends `PUT /admin/realms/{realm}/users/{id}/execute-actions-email` with the JSON body `["VERIFY_EMAIL"]`, plus `client_id`, `redirect_uri`, and `lifespan` query parameters.

## Sync and reconciliation

An authenticated caller can request a sync with:

```text
PUT /api/auth/email-verification/sync/{keycloakUserId}
Authorization: Bearer <valid Keycloak access token>
```

The request contains no verification claim. The backend fetches the user from the Admin API and changes the local profile only when Keycloak reports `emailVerified=true`. The scheduled reconciliation uses that same method for pending profiles, covering missed sync requests.

No Keycloak Event Listener SPI is bundled with this backend, so no listener registration is required for correctness. If an external listener is deployed to reduce sync latency, install its provider in Keycloak and register it under **Realm Settings → Events → Event listeners**; it should call the authenticated sync endpoint and must not send a trusted verification boolean.

## Backend environment variables

| Variable | Purpose |
|---|---|
| `KEYCLOAK_BASE_URL` | Keycloak base URL |
| `KEYCLOAK_REALM` | Realm containing DelivFlow users |
| `KEYCLOAK_ISSUER_URI` | Expected realm issuer |
| `KEYCLOAK_BACKEND_CLIENT_ID` | Confidential service-account client |
| `KEYCLOAK_BACKEND_CLIENT_SECRET` | Service-account client secret |
| `KEYCLOAK_EMAIL_VERIFICATION_CLIENT_ID` | Client used for the verification action link |
| `KEYCLOAK_EMAIL_VERIFICATION_REDIRECT_URI` | Exact allowed destination after verification |
| `KEYCLOAK_EMAIL_VERIFICATION_LIFESPAN_SECONDS` | Action-token lifetime in seconds |
| `KEYCLOAK_EMAIL_VERIFICATION_RECONCILIATION_INTERVAL_MS` | Reconciliation delay; defaults to 300000 ms |

Defaults in `application.yaml` are for local development. Set the client ID and redirect URI to values configured in the target realm before deploying.
