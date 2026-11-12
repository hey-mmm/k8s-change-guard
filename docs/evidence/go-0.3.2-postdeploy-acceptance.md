# Go 0.3.2 post-deploy acceptance — PR9 restricted merge / PR8 BLOCK

Captured: 2026-11-12T13:47:12Z (21:47 +08)
Operator: independent dsh (post-deploy acceptance; no postdeploy/revert/final/live)
Rule/protection changes: none.

## Environment

- Service `active`; `/opt/change-guard/current -> releases/0.3.2`;
  `change-guard 0.3.2 (rules go-2026-11-12.1)`; correct Go `ExecStart`;
  daemon restarted by the trusted merge script at 21:45:25 CST (PID 103994).
- main after merge: `a9a29da30832380bbdbda091177c738d7a7fde4b`
  (from `321eb9517b83dc0e9261e16dcdb26016332dd7c3`).
- Argo `Synced/Healthy`, operation revision `a9a29da...`; both nodes Ready.
- Open PR count at capture: 0.

## PR9 — real evaluation, owner approval, restricted merge

- Head/base unchanged: `a9a29da30832380bbdbda091177c738d7a7fde4b` /
  `321eb9517b83dc0e9261e16dcdb26016332dd7c3`.
- Fresh Go 0.3.2 report `ev-78c8a50fe61439c39c1a05d8`: decision **REVIEW**,
  guard 0.3.2, no BLOCK/ERROR; changed path only `gitops/demo/values.yaml`;
  findings `AI_ADDITIONAL_RISK`, `CAPACITY_POD_REQUESTS_UNRESERVED`,
  `FIRING_ALERTS`. The AI redacted-env concern was refuted by the unchanged
  base/head blobs (same SHAs as the previously reviewed candidate):
  `APP_ENV=production`, `DEMO_ERROR_RATE=0`, `DEMO_LATENCY_MS=0`,
  `DEMO_STARTUP_FAIL=false`; no fault injection shipped.
- Required CI `Test, lint, render` (GitHub Actions app id 15368) success,
  exact head/latest; chart pin unchanged.
- Owner approval comment: `/guard approve ev-78c8a50fe61439c39c1a05d8`
  (comment 6825277923, actor hey-mmm, 13:43:52Z, TTL remaining 272 s).
- Merge path: `scripts/merge-release.sh 9` (sha256
  `094aae10d395643202803553b620d98a12e64ef981318988c61229231f464a09`),
  whose Go invocation is
  `merge --config /etc/change-guard/config.yaml --pr 9` — **no
  `--evaluation-id`**. Go 0.3.2 resolved the recorded id from the index.
  Result `MERGED`, strategy `fast-forward`, `github_merge_api_used=false`,
  synthetic merge `f1efb1e208c833990234a93a247d4427283561c6`, main tree
  `d84a7099...` equals the merge-record head tree. PR merged 13:45:25Z.
- This verifies the 0.3.2 “omit `--evaluation-id`” merge fix on the real
  protected path. CI authentication also passed on the production merge
  (`ci-merge-9` evidence), the second 0.3.2 fix.

## PR8 — BLOCK proof only (closed by go-pr-032, not by this dsh)

- Fresh 0.3.2 report `ev-250e5d31f8ee30f9dd9ec867`: decision **BLOCK**,
  finding `FAULT_INJECTION` (DEMO_STARTUP_FAIL) bound to head
  `9953651978cbb862e78d80fb8e582679f4ba3f19`; GitHub status `failure`.
- Pre-close proof 13:41:44Z (main still `321eb951...`):
  `mergeable=true` (no textual conflict) but `mergeable_state=blocked`;
  GitHub merge API **405** “Required status check change-guard/release is
  failing / protected ref”; direct main PATCH **422** (2 required checks
  expected, PR required); main unchanged after both probes. PR8 was never
  merged (`merged=false`).
- Timeline: BLOCK status 13:41:10Z → unmergeable proof 13:41:44Z → PR8
  closed 13:41:56Z by go-pr-032 under root authorization → PR9 merged
  13:45:25Z.

## Protection unchanged

- Both rulesets (`27101219 change-guard-main-required-checks`, `27101186
  change-guard-main-updates`) structurally identical to the 21:14 baseline:
  same enforcement, rules, required checks (`change-guard/release`,
  `Test, lint, render` integration 15368, strict), bypass actors
  (DeployKey only), and `updated_at`. Normalized digest
  `be5c3efb77326ad4728c5d3052a610215646c84501dd8d6d01051973b57b24c8`.
- Classic branch protection remains absent (404 “Branch not protected”),
  matching baseline. No ruleset/protection edit was made.

## Scope limits

- This dsh did not run postdeploy, revert, final or live; go-pr-032 owns
  those. No PR was reopened/closed/merged after the PR9 merge.
- `mergeable=true` for PR8 means “no merge conflict”, not “merge allowed”;
  the enforced block was the failing required check plus rulesets (405/422).
- The approval reason conservatively noted traffic/health limitations and
  capacity headroom; no threshold, TTL, CI or approval gate was relaxed.

## Evidence

- `go-0.3.2-postdeploy-acceptance.json` (consolidated, sanitized)
- `go-snapshot-pr9-032-pre-approval.json`, `go-snapshot-pr9-032-postmerge.json`
- `go-approval-ev-78c8a50fe61439c39c1a05d8.json`
- `go-ci-approval-9.json`, `go-ci-merge-9.json`
- `go-merge-command-9.json`, `go-merge-record-9.json`
- `go-snapshot-pr8-032-check2.json`, `go-danger-protection-proof.json`
- `go-snapshot-pr8-032-postmerge-readonly.json`

**Result: PR9 restricted merge PASS (0.3.2 omitted-id fix verified); PR8
BLOCK/blocked and never merged; rulesets unchanged. `GO_PR_032_MERGE=PASS`
(not final live acceptance).**
