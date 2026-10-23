# Live identity and provider validation

The local QA environment completed real authorization-code/PKCE/nonce flows
against Keycloak 26.8.1, using distinct synthetic administrator, reviewer and
auditor identities. It exercised application logout, provider logout between
identities, role restrictions, workspace switching, file upload/approval/download,
package generation and fresh sign-in after restore/session invalidation.
This was HTTP on isolated loopback in development mode, not a public TLS/MFA
deployment or a test of your chosen customer's IdP outage/recovery policy.

For production, configure an asymmetric-signing OIDC provider and exact HTTPS
callback URI `PUBLIC_URL/auth/callback`. Pin the issuer and client; require MFA
and approved account recovery at the IdP. Membership remains the verified
issuer/subject pair; email/domain claims never grant access. Exercise missing
membership, revoked members, logout, expired/replayed responses, issuer/audience
rejection, key rotation, disabled accounts and IdP unavailability. Existing offline
regressions cover signature/claim/replay boundaries; the selected real IdP and
its actual MFA/SSO lifecycle still need deployment-specific validation.

## Provider checks

Use dedicated test organizations/accounts and the same read-only integration
workflow as customers. Configure explicit GitHub organization/repository population,
Google Workspace customer ID and AWS expected account/region. Customer AWS trust
must use the generated workspace external ID. Keep secrets in encrypted integration
storage and workload identity; do not send them in chat or put them in reports.

Run on the trusted operator host/container with its private hosted environment:

```sh
python -m cleartrail.hosted_admin validate-providers --tenant WORKSPACE_UUID --report NEW_PRIVATE_REPORT.json
```

This executes isolated, bounded, read-only collectors for eligible scopes. It
does not change cloud settings, create provider resources or publish a normal
monitoring snapshot. The report contains scope/snapshot hashes and counts, never
raw resource/people inventories, credentials or SDK exception text. It reserves
a private report file without overwriting an existing one.

Exit 0 means supported checks for all three advertised providers were observed
without unknown coverage. A failed security control is still a valid observation;
passing access validation does not mean customer security controls passed.
Exit 2 means missing/blocked/incomplete provider evidence; exit 1 is an operational
failure. Missing integrations and inaccessible scopes never become a pass.

Also exercise two distinct organizations/accounts per provider, reduced scopes,
revoked/expired credentials, pagination/rate limits, hidden repositories, wrong AWS
account/external ID and Google customer mismatch. Validate customer's actual trust
policy and provider audit trail. If a deployment excludes a provider, document that
scope explicitly instead of claiming all three were validated.

For Google sign-in on a dedicated compliance subdomain, see
[GOOGLE_STAGING.md](GOOGLE_STAGING.md). No exact GitHub repository/test organization,
Workspace customer/authorization or AWS account was supplied in this session. The locally available generic Google API key is not a
Workspace Directory authorization credential and was not used. Live cloud-provider
checks therefore remain **not run**. The preflight intentionally reports them
blocked until those accounts/scopes and credentials are configured.
