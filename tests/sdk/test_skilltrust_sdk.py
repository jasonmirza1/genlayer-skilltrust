import base64
import copy
import hashlib
import json
from pathlib import Path

import pytest


CONTRACT = str(Path(__file__).parents[2] / "contracts/skilltrust.py")
SHA = "a" * 40
NONCE = "b" * 48
SKILL = "# File reader\nRead local files only.\n"
MANIFEST = json.dumps({"schema": "skilltrust.bundle.v1", "files": [{"path": "SKILL.md", "sha256": hashlib.sha256(SKILL.encode()).hexdigest()}]})
ANSWER = {"decision": "ALLOW", "source_complete": True, "policy_fit": True, "capabilities": ["READ_FILES"], "domains": [], "policy_violations": [], "uncovered_references": [], "risks": [], "summary": "Only local reads are described."}


def _envelope(raw):
    return json.dumps({"type": "file", "encoding": "base64", "size": len(raw.encode()), "content": base64.b64encode(raw.encode()).decode()})


def test_locked_skill_review_in_sdk(direct_vm, direct_deploy_compat):
    direct_vm.mock_web(r".*api\.github\.com/repos/example/skilltrust/contents/bundle\.json\?ref=a{40}.*", {"status": 200, "body": _envelope(MANIFEST)})
    direct_vm.mock_web(r".*api\.github\.com/repos/example/skilltrust/contents/SKILL\.md\?ref=a{40}.*", {"status": 200, "body": _envelope(SKILL)})
    direct_vm.mock_llm(r".*Review an agent skill before.*", json.dumps(json.dumps(ANSWER)))
    contract = direct_deploy_compat(CONTRACT)
    contract.create_policy("Local reader", "READ_FILES", "-", "Do not execute shell commands or access the network.")
    receipt = contract.review_skill("1", f"https://github.com/example/skilltrust/blob/{SHA}/bundle.json", NONCE)
    assert receipt["decision"] == "ALLOW"
    assert contract.get_counts()["reviews"] == 1


def _mock_comparison(direct_vm, monkeypatch, answer):
    validator = direct_vm._captured_validators[-1][2]
    calls = []
    nondet = validator.__globals__["gl"].nondet
    original = nondet.exec_prompt

    def compare(prompt, *args, **kwargs):
        if not prompt.startswith("Compare independently produced skill reviews."):
            return original(prompt, *args, **kwargs)
        calls.append(prompt)
        return answer

    monkeypatch.setattr(nondet, "exec_prompt", compare)
    return calls


@pytest.mark.parametrize("agreement", [True, False])
def test_validator_checks_semantics_after_matching_evidence(direct_vm, direct_deploy_compat, monkeypatch, agreement):
    test_locked_skill_review_in_sdk(direct_vm, direct_deploy_compat)
    calls = _mock_comparison(direct_vm, monkeypatch, {"agree": agreement})
    leader = copy.deepcopy(direct_vm._captured_validators[-1][0])
    leader["summary"] = "The declared source only reads local files."
    assert direct_vm.run_validator(leader_result=leader) is agreement
    assert len(calls) == 1
    assert leader["summary"] in calls[0] and ANSWER["summary"] in calls[0]


@pytest.mark.parametrize("field", ["bundle_sha256", "file_hash", "file_path", "bundle_verified", "source_complete", "policy_fit", "decision", "capabilities", "domains"])
def test_validator_rejects_exact_mismatch_even_if_comparator_agrees(direct_vm, direct_deploy_compat, monkeypatch, field):
    test_locked_skill_review_in_sdk(direct_vm, direct_deploy_compat)
    calls = _mock_comparison(direct_vm, monkeypatch, {"agree": True})
    leader = copy.deepcopy(direct_vm._captured_validators[-1][0])
    if field == "file_hash":
        leader["file_hashes"][0]["sha256"] = "0" * 64
    elif field == "file_path":
        leader["file_hashes"][0]["path"] = "OTHER.md"
    elif field == "bundle_sha256":
        leader[field] = "0" * 64
    elif field in ("bundle_verified", "source_complete", "policy_fit"):
        leader[field] = False
        leader["decision"] = "REVIEW"
    elif field == "decision":
        leader[field] = "REVIEW"
    elif field == "capabilities":
        leader[field] = []
    else:
        leader[field] = ["example.com"]
        leader["decision"] = "REVIEW"
    assert direct_vm.run_validator(leader_result=leader) is False
    assert calls == []


def test_validator_cannot_verify_leaders_evidence(direct_vm, direct_deploy_compat, monkeypatch):
    test_locked_skill_review_in_sdk(direct_vm, direct_deploy_compat)
    calls = _mock_comparison(direct_vm, monkeypatch, {"agree": True})
    direct_vm.clear_mocks()
    direct_vm.mock_web(r".*api\.github\.com/.*", {"status": 503, "body": "unavailable"})
    assert direct_vm.run_validator() is False
    assert calls == []


@pytest.mark.parametrize("answer", [None, {}, {"agree": "true"}, {"agree": 1}, {"agree": True, "extra": 1}, "not json", '{"agree":false,"agree":true}'])
def test_validator_rejects_malformed_comparison(direct_vm, direct_deploy_compat, monkeypatch, answer):
    test_locked_skill_review_in_sdk(direct_vm, direct_deploy_compat)
    calls = _mock_comparison(direct_vm, monkeypatch, answer)
    assert direct_vm.run_validator() is False
    assert len(calls) == 1


def test_validator_rejects_leader_error(direct_vm, direct_deploy_compat):
    test_locked_skill_review_in_sdk(direct_vm, direct_deploy_compat)
    assert direct_vm.run_validator(leader_error=ValueError("leader failed")) is False


def test_comparison_uses_sdk_json_response(direct_vm, direct_deploy_compat):
    test_locked_skill_review_in_sdk(direct_vm, direct_deploy_compat)
    direct_vm.mock_llm(r".*Compare independently produced skill reviews.*", json.dumps(json.dumps({"agree": True})))
    assert direct_vm.run_validator() is True
