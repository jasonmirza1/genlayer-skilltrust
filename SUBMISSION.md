# SkillTrust — Portal draft

Category: Builder → Intelligent Contracts. This is a **draft**, not proof of deployment or acceptance.

One-liner: Consensus-reviewed admission of immutable agent skills against onchain capability and domain policies.

Description: SkillTrust is a reusable GenLayer contract primitive for reviewing agent skills before installation. A policy owner records allowed runtime capabilities, exact outbound domains, and prohibited behavior. A reviewer submits a full-commit GitHub URL for a manifest containing SKILL.md and up to four additional files with exact SHA-256 digests. Validators fetch and hash the same locked bytes independently, inspect capabilities and missing references, and compare the substance of their policy judgments. The contract stores a nonce-bound ALLOW, REVIEW, BLOCK, or INSUFFICIENT_EVIDENCE receipt, including file hashes and specific findings. It fails closed on missing or tampered evidence and prevents nonce replay. ALLOW is a review aid, not a sandbox, authorization, or proof that unlisted runtime dependencies are safe.

Public repository: https://github.com/jasonmirza1/genlayer-skilltrust

Studio Next contract link: **TODO — deploy and verify address**

Finalized review transaction: **TODO — submit one fixture review and verify a stored receipt**

Reviewer verification: Open the Studio Next contract, call `get_counts`, then `get_policy("1")` and `get_review("1")`. Confirm the fixture manifest URL contains one full commit SHA, the returned `bundle_sha256` and SKILL.md hash match those files, and the receipt contains the nonce, policy ID, decision, and validator findings. Compare the transaction's status with the stored review; finalization alone is insufficient.

Before submitting, rerun `python -m pytest tests -q -p no:cacheprovider`, run the linter, publish source and fixture at one commit, deploy on Studio Next, make one policy and review transaction, and replace every TODO above with exact public links. Do not submit this draft as if those actions are complete.
