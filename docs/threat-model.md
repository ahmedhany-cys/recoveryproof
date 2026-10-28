# Threat model

Scope: the RecoveryProof application (local Streamlit server, CLI, report generation) and
its input/output files. Out of scope: the security of the real backup platforms
RecoveryProof might one day assess.

## Assets

| Asset | Why it matters |
|---|---|
| Inventory and evidence data | May describe real infrastructure, owners and weaknesses (sensitive in a real deployment) |
| Analysis results and reports | Shape leadership decisions; wrong output could cause unsafe recovery choices |
| Remediation state and audit log | Record who claimed what was fixed |
| Host running the app | Must not be compromised through crafted inputs |

## Trust boundaries

1. **Input files and uploads → loader.** Untrusted.
2. **Browser ↔ Streamlit server.** Local user, localhost by default.
3. **App → file system.** Writes only to `var/` (state) and user-requested downloads.
4. **Optional future AWS collector → AWS APIs.** Read-only role template, not implemented.

## Threats and mitigations (STRIDE)

| Threat | Example | Mitigation |
|---|---|---|
| **Tampering / injection** via input | Crafted JSON with extra fields, huge payloads, deeply invalid data | Strict Pydantic models (`extra="forbid"`), 2 MiB limit before parsing, JSON only, readable but bounded error output |
| Unsafe deserialization | Pickle/YAML object payloads | Not supported: `json.loads` only; no `pickle`, `yaml.load`, `eval` or `exec` |
| Path traversal | `../../etc/passwd`, symlink escaping the data dir | `safe_path()` resolves and requires the target inside the base directory; tested for `..`, absolute paths and symlinks |
| Code execution via upload | Uploading Python | Only `.json` accepted, and it is parsed as data; no plugin loading |
| Command injection | — | No shell or subprocess calls in the application |
| XSS in dashboard/report | Asset named `<script>` | `html.escape` on every interpolated string in custom HTML; Jinja2 autoescape for reports; tested |
| **Repudiation** | Claiming a fix without proof | Resolution requires a verification record; every status change is written to the hash-chained audit log |
| Audit-log tampering | Editing an earlier entry | Hash chain detects edits, deletions and reordering (`verify()`). **Limitation:** an attacker with file access can rewrite the whole chain, so the log is tamper-evident, not tamper-proof |
| **Information disclosure** | Secrets in logs | Audit details redact keys containing password/secret/token/credential/api_key; `.env`, `var/`, tfstate and keys are git-ignored; demo data is fictional |
| Telemetry leakage | Usage stats sent externally | `gatherUsageStats = false`; no outbound calls by default |
| **Denial of service** | Huge uploads, giant inventories | `maxUploadSize = 2` MB, model limits (≤ 500 assets, ≤ 10 000 evidence records, ≤ 50 injections) |
| **Elevation of privilege** | App used to change real systems | No write integrations exist. The app never deletes backups, disables logging or revokes credentials. The optional AWS template is read-only and requires an External ID |
| **Misleading output** (safety) | Overstating recoverability | Evidence-first eligibility, conservative contradiction handling, "unknown earns no credit", basis labels on every finding, blocked steps instead of guessed orders, honest "cannot be estimated" |

## Residual risks

- Running the server on a non-localhost address would expose an unauthenticated dashboard.
  Keep the default bind or put it behind authentication.
- Dependency vulnerabilities can appear after release. CI runs `pip-audit` on every push.
- The analysis is only as good as the evidence supplied. Fabricated evidence would produce
  confident but wrong results. Signed evidence is on the roadmap.
