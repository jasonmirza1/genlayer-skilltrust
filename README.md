# SkillTrust

SkillTrust is a standalone GenLayer Intelligent Contract for pre-installation review of agent skills. A policy owner stores permitted capabilities, exact outbound domains, and prohibited behavior. Any user can submit an immutable GitHub skill bundle to be reviewed against that policy. Validators independently fetch and hash the listed source files, inspect what the skill can do, and compare their judgments before a bounded receipt is stored.

Its evidence is executable agent-skill source, not a model card or a proposed agent transaction. This gives it a distinct review purpose from ModelUseGate and IntentScope.

This repository is a **local prototype, not a deployed or submitted contract**. The contract does not install, execute, or sandbox skills.

## Why decentralized judgment is used

Determining whether instructions and scripts imply shell, network, wallet, secret, or file access requires interpretation of source content, not just JSON parsing. A leader proposes a structured assessment; validators independently retrieve the locked bytes and compare the substantive capability, domain, missing-reference, policy-conflict, and risk findings. Matching output shape alone is explicitly insufficient.

The custom validator first checks both result schemas and requires exact equality of verification flags, manifest/file hashes, file paths and final decision. Capability/domain lists must match irrespective of order. Only then does it ask the model to compare narrative findings. An AI agreement cannot override an exact-field mismatch; malformed comparator responses are rejected. Two identical canonical evidence-failure results agree without a model call.

## State and methods

- `create_policy(name, allowed_capabilities_csv, allowed_domains_csv, prohibited_behavior)` creates an owned, immutable policy. Capabilities are `READ_FILES`, `WRITE_FILES`, `SHELL`, `NETWORK`, `BROWSER`, `WALLET`, `SECRETS`, `PROCESS`, and `OTHER`. Use `-` for no permitted domains.
- `deactivate_policy(policy_id)` is owner-only and prevents new reviews; old receipts remain readable.
- `review_skill(policy_id, bundle_url, nonce)` writes one receipt and consumes a lowercase hex nonce scoped to the policy and caller address. Another wallet can use the same nonce without blocking your request. Outcomes are `ALLOW`, `REVIEW`, `BLOCK`, or `INSUFFICIENT_EVIDENCE`.
- `get_policy`, `get_review`, and `get_counts` expose stored state.

An `ALLOW` receipt means only that the submitted, bounded source set appeared consistent with the specified policy at review time. It is **not** a malware-free or permission grant. Operators should still sandbox execution and inspect the complete repository/dependencies themselves.

## Locked source protocol

`bundle_url` must be a GitHub `blob` URL containing an exact 40-character lowercase commit SHA, for example:

```text
https://github.com/OWNER/REPO/blob/FULL_COMMIT_SHA/examples/fixture/bundle.json
```

The manifest uses `skilltrust.bundle.v1`, lists 1–5 UTF-8 files relative to the manifest directory, and includes their exact SHA-256 bytes. `SKILL.md` is mandatory. The [fixture manifest](examples/fixture/bundle.json) and [fixture skill](examples/fixture/SKILL.md) demonstrate the format. Each file is limited to 6,000 bytes and all listed source content to 18,000 bytes. Files that cannot be fetched or whose bytes do not match fail closed to `INSUFFICIENT_EVIDENCE`. The validator also flags local references absent from the manifest. Unlisted transitive dependencies, runtime downloads, hidden instructions and external services remain outside this bounded proof.

## Reproduce locally

With the dependencies in `requirements.txt` installed:

```powershell
python -m pytest tests -q -p no:cacheprovider
$env:PYTHONIOENCODING='utf-8'; python -m genvm_linter.cli check contracts/skilltrust.py
Get-FileHash -Algorithm SHA256 examples/fixture/SKILL.md
```

From this directory, the fixture skill hash should be `f96dbd07be6383efa962d0b516111624b4de2806efe542028af3935c2b349da6`. The 43 local tests cover policy conflicts, long domains, missing references, immutable URLs, tampering, replay, caller isolation, owner controls, and forged positive results. Tests in `tests/sdk/` use the real SDK with mocked web/model responses and Python execution. They explicitly invoke the captured validator callback to check independent evidence collection, exact-field mismatch rejection even with an always-agree comparator, semantic acceptance/rejection, malformed comparator output, and leader-error rejection. The external semantic comparator is mocked; these tests do not prove model judgment quality, WASM execution, or network consensus.

Full GenVM/Studio consensus verification is still pending. No local GenLayer Studio runtime was installed or running during this validation. Use the Studio Next verification path below and record a stored receipt before publishing any claim of live consensus success.

## Studio Next verification path

1. Deploy `contracts/skilltrust.py` on Studio Next with full consensus and record the new address and deploy transaction. Do not reuse a different contract address.
2. Publish this directory to a public GitHub repository. Commit the manifest and listed files; use that **full commit SHA** in the review URL.
3. Call `create_policy` using `Local notes reader`, `READ_FILES`, `-`, and `No shell, network, wallet, or secret access is allowed.`
4. Call `review_skill` for policy `1`, the locked manifest URL, and a fresh random 32–64-character lowercase hex nonce. Record its transaction hash.
5. Wait for finalization. Verify `get_counts().reviews == 1` and inspect `get_review("1")`. Do not equate a `FINALIZED` transaction label with a stored receipt or an `ALLOW` verdict.

The public source is at https://github.com/jasonmirza1/genlayer-skilltrust. No Studio Next transaction has been submitted as part of this build. Deployment, fee approval, and Portal submission require separate user action.

## Security boundaries

Source files are untrusted data; embedded instructions or claimed results must not direct the validators. Exact content hashes and a full Git commit pin source identity, but cannot establish that the listed files cover everything that would execute. Semantic classification can miss behavior. Decisions should be interpreted as evidence-bearing review aids, not an authorization or execution control. The storage cap is 10,000 policies and 10,000 reviews; a production system may need paging/indexing or a separate registry.
