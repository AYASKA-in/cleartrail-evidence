# Google OIDC staging setup

Example hostname: `https://compliance.example.com`.
Issuer: `https://accounts.google.com`.
Exact authorized redirect URI:
`https://compliance.example.com/auth/callback`.

This is a prepared deployment plan, not a DNS change or deployed service. The
existing main website remains unchanged. Provision your own hosting platform, Google Web OAuth client and DNS/TLS
configuration before attempting a live sign-in.

1. Use a Google Cloud project you control. Configure the OAuth consent audience
   and permitted test accounts for staging; create an OAuth client of type
   **Web application** with the exact redirect URI above. Follow Google's current
   consent/publishing requirements before broad access. No browser JavaScript SDK
   is required by this server-side authorization-code implementation.
2. Deliver the client secret privately through the hosting secret store. Set
   `CLEARTRAIL_PUBLIC_URL` to the intended origin, `CLEARTRAIL_OIDC_ISSUER` to the
   issuer above, and `CLEARTRAIL_OIDC_CLIENT_ID` and
   `CLEARTRAIL_OIDC_CLIENT_SECRET` to the actual client. Generate independent session/vault secrets and a
   separate least-privilege database runtime role as in HOSTED_DEPLOYMENT.md.
3. Provision DNS/TLS and ingress for the dedicated subdomain. Preserve its Host,
   use the exact HTTPS callback, disable sensitive query logging, enforce shared
   limits and keep the database/scanner private. Do not reuse unrelated website
   secrets, database roles or sessions.
4. Obtain each initial administrator's verified Google ID-token `sub` through a
   trusted operator verification workflow. Bootstrap explicit issuer/subject
   membership using hosted_admin; do not infer membership from email, callback
   `hd`, domain ownership or an unverified token. The application intentionally
   has no first-user or email-domain auto-enrollment bypass.
5. Test fresh sign-in, unassigned identity, logout, revoked membership, independent
   review, cross-workspace boundaries and actual MFA/account-recovery policy.
   Personal Google accounts need operator-enforced account-security requirements;
   choosing Google OIDC alone does not guarantee organizational MFA enforcement.

Only `openid` is requested for authentication. Google Workspace Directory evidence
collection is a separate authorization and requires a Workspace customer and
appropriate read-only permissions. AWS is also independent. Neither subscription
is needed to sign in or use manual evidence, reviews and packages. Leave those
connectors unconfigured until suitable authorized test accounts exist; unknown
controls must not turn into passes. Do not create paid accounts merely for QA.

Official references: [Google OIDC](https://developers.google.com/identity/openid-connect/openid-connect),
[Google discovery](https://accounts.google.com/.well-known/openid-configuration),
[code-response fields](https://developers.google.com/identity/oauth2/web/guides/use-code-model).
These references informed compatibility work; no real Google authorization flow
was completed with a deployment-specific client during this session.
