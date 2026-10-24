# AWS credit-funded staging (Mumbai)

Prepared 24 October 2026. This is an operator-reviewed deployment path, not a
record of a cloud deployment. No AWS account, credit balance, AMI, instance
offering, domain, Google OAuth client or live cost estimate has been validated
for this project. The software is free under MIT; infrastructure consumes credits
and can incur charges on a Paid Plan.

## Credit eligibility and lifetime

AWS currently gives eligible new accounts $100 at signup and offers activities
to earn up to $100 more. Its **Free account plan** closes after six months or
credit exhaustion, whichever comes first. A Paid Plan can charge beyond credits
or for ineligible services. Check the Billing console for your actual plan,
remaining credits, expiry and eligible services. Preserve an off-account backup
before expiry; do not rely on the account's post-closure retention window.

Sources: [AWS account plans](https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/free-tier-plans.html),
[Free Tier terms](https://aws.amazon.com/free/terms/),
[EC2 Free Tier eligibility](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-free-tier-usage.html).

## Proposed staging footprint

- Region `ap-south-1` (Mumbai); one x86-64 `m7i-flex.large` candidate, currently
  listed among the new Free Tier eligible types. Check the selected AZ's
  offering, account restrictions, AMI eligibility and price before launch.
- One EC2 host running the API, worker, scheduler, PostgreSQL and optional
  ClamAV scanner/updater. An 8 GiB host is a **capacity-test candidate**, not a
  proven production sizing: scanner/updater memory caps alone total 7 GiB and
  can overlap. Measure peak RSS, OOM events, definition reloads and collection
  latency before admitting customers. A micro instance is unsuitable for this
  complete stack. Keep binary uploads disabled if scanning cannot be operated
  reliably; never bypass scan failures.
- 30 GiB encrypted gp3 root disk plus a 40 GiB encrypted gp3 data disk. Durable
  PostgreSQL and scanner storage must be placed on the data disk, with backups
  outside this host. The template only attaches the disk; it does not format it
  or configure mounts. Identify it by EBS volume ID/NVMe mapping before any
  filesystem operation. Never format an existing data volume.
- A dedicated HTTPS hostname and Google OIDC client. The API remains on host
  loopback; PostgreSQL and ClamAV have no public listeners. Use an operated
  HTTPS reverse proxy with the limits in [hosted deployment](HOSTED_DEPLOYMENT.md).
- Session Manager for administration; no SSH ingress or key pair. The host role
  grants SSM management only. It has no access to customer AWS accounts and the
  application must not inherit its host credentials. Provider collection needs
  its own reviewed workload identity and customer role trust.

This avoids a NAT gateway, load balancer, managed database and paid marketplace
image in the initial design. It has a single point of failure and is appropriate
for controlled staging. AWS service eligibility and availability still need
account-specific confirmation.

## Cost worksheet before launch

Create a saved [AWS Pricing Calculator](https://calculator.aws/) estimate for
Mumbai covering Linux On-Demand compute, 70 GiB gp3 storage, any extra IOPS or
throughput, public IPv4, outbound data, snapshots/backups and optional logs/DNS.
Include taxes and service-specific credit exclusions where applicable. Do not
equate “Free Tier eligible” with unlimited free usage. No monthly dollar total
is asserted here because an account/region quote has not been retrieved.

For a forecast daily eligible spend `D` and usable remaining credit `C`, the
credit runway is approximately `C / D` days, capped by the Free Plan's remaining
duration. Usage varies; check actual daily billing after launch. Set credit,
usage and forecast alerts where available and plan an explicit stop/export
date. Budget alerts are notifications, not a universal spending stop. On the
Free Plan, account closure itself can interrupt the service.

Stopping EC2 is useful for intermittent staging but storage and other retained
resources can continue consuming credits. Ephemeral public IPv4/DNS changes on
restart require revalidation. A future Paid Plan upgrade changes billing risk;
do not upgrade it implicitly as part of this deployment.

## Review the infrastructure before execution

The [CloudFormation template](../deploy/aws/staging.yaml) creates a separate VPC,
one public subnet, routing, a security group, SSM role/profile, EC2 and encrypted
disks. It installs no application, sends no secrets through user data, and makes
no DNS changes. HTTP/HTTPS ingress requires an explicit tester CIDR parameter.
Public ACME HTTP challenges cannot reach a tester-only rule; use DNS validation
or deliberately review public ingress before requesting a certificate. Do not
open the API, database, scanner or SSH ports to solve connectivity problems.

Use an AWS CLI v2 profile authenticated through your normal browser/SSO flow;
never paste access keys into chat. Check the account ID in the console first.
The following are **read-only checks**, not provisioning commands:

```powershell
aws sts get-caller-identity --profile cleartrail-staging
aws ec2 describe-instance-types --profile cleartrail-staging --region ap-south-1 --instance-types m7i-flex.large --query 'InstanceTypes[*].[InstanceType,FreeTierEligible,VCpuInfo.DefaultVCpus,MemoryInfo.SizeInMiB]'
aws ec2 describe-instance-type-offerings --profile cleartrail-staging --region ap-south-1 --location-type availability-zone --filters Name=instance-type,Values=m7i-flex.large
aws cloudformation validate-template --profile cleartrail-staging --region ap-south-1 --template-body file://deploy/aws/staging.yaml
```

Then create a **CloudFormation change set** in Mumbai with the chosen AZ,
tester CIDR and reviewed AMI. Review all resources, replacement behavior,
`CAPABILITY_IAM`, estimated cost and retained-data policy before executing it.
No change set has been created or executed by this project. CloudFormation
validation checks syntax; it does not prove quota, credit coverage or deployment
success.

## Application installation and acceptance

1. Connect using [Session Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-sessions-start.html).
   Patch the host and install supported Docker Engine and Compose v2 through
   reviewed upstream instructions. Restrict Docker access to trusted operators.
2. Identify, mount and persist the encrypted data disk. Place Docker's durable
   data/database volume there. Record a tested restore procedure before storing
   customer evidence. EBS encryption does not replace backups or vault keys.
3. Fetch a reviewed ClearTrail commit or source release. Configure PostgreSQL
   with a non-superuser schema owner and a separate DML-only runtime role,
   explicit grants and no public database port. Follow
   [HOSTED_DEPLOYMENT.md](HOSTED_DEPLOYMENT.md) for migration and runtime setup.
4. Deliver `.env.hosted` securely with restrictive permissions. Keep migration
   credentials out of runtime services. Store vault keys and backups separately;
   losing the keys loses access to encrypted documents and governance records.
5. Configure the dedicated hostname, DNS and TLS, and register the exact Google
   callback `https://YOUR_HOST/auth/callback`. Follow
   [GOOGLE_STAGING.md](GOOGLE_STAGING.md); Google sign-in alone is not proof of
   enforced MFA. Bootstrap membership with a verified issuer and subject.
6. Start the pinned application stack behind the proxy. For binary documents,
   initialize fresh definitions and start the `scanning` profile. Verify scanner
   freshness and fail-closed behavior before enabling binary uploads.
7. Run the release gates: HTTPS and exact-host checks, real Google code/PKCE
   login, two-workspace isolation, independent approvals, provider scope/failure
   tests, register/package offline verification, peak-memory tests, host reboot
   and restore to a separate environment. Record evidence, not just a checklist.
8. Schedule encrypted off-host database backups, preserve matching vault keys,
   and test restoration independently. Track patching, disk/memory usage,
   certificate expiry, scanner freshness, collection failures and credit expiry.

## Shutdown and retained data

Drain workers, stop admissions and produce a verified off-account backup before
teardown or credit expiry. The template retains the data EBS volume on stack
deletion/replacement. This protects against accidental stack deletion but it is
not a backup and **retained storage still costs money/credits**. Review retained
volumes, snapshots, logs and any separately created DNS/IP resources after
teardown. Delete data only after a verified restore and the agreed retention
period. [AWS volume deletion guidance](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-deleting-volume.html).

## Other free hosting options

Netlify Free can host the public project site with its current 300-credit
monthly hard cap; its Functions, including background functions, do not run
this persistent Python/Docker/PostgreSQL/ClamAV stack unchanged.
[Netlify pricing](https://docs.netlify.com/manage/accounts-and-billing/billing/billing-for-credit-based-plans/credit-based-pricing-plans/),
[background functions](https://docs.netlify.com/build/functions/background-functions/).
Vercel Hobby is restricted to personal, non-commercial use, so it is not the
default for a customer-facing compliance service.
[Vercel Hobby](https://vercel.com/docs/plans/hobby).
