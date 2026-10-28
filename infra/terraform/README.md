# Optional infrastructure template (not applied)

`readonly-evidence-role/` defines a **read-only** IAM role that a future AWS evidence
collector could assume. It is not needed for the RecoveryProof demo. The project has
never applied it to any AWS account and has created no AWS resources.

- No write, delete, restore or IAM-management permissions.
- `sts:ExternalId` is required to assume the role.
- Collects metadata only: vault locks, recovery-point lists, restore jobs, encryption settings.

Verified locally only with `terraform fmt -check`. `terraform init/validate` was not run,
because that downloads the AWS provider. Review before use. An IAM role has no standing
charge, but API usage (for example CloudTrail `LookupEvents` at volume) and any resources
you add may be billed. Check current AWS pricing for your account.
