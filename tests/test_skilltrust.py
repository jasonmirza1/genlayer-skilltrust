import base64
import hashlib
import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest


SHA = "a" * 40
NONCE = "b" * 48
BUNDLE_URL = f"https://github.com/example/skilltrust/blob/{SHA}/bundle.json"
SKILL = b"# File reader\nRead local files. Do not send them to a network service.\n"
MANIFEST = {"schema": "skilltrust.bundle.v1", "files": [{"path": "SKILL.md", "sha256": hashlib.sha256(SKILL).hexdigest()}]}
MANIFEST_RAW = json.dumps(MANIFEST).encode()
ALLOW = {
    "decision": "ALLOW", "source_complete": True, "policy_fit": True,
    "capabilities": ["READ_FILES"], "domains": [], "policy_violations": [],
    "uncovered_references": [], "risks": [], "summary": "Only local file reads were found.",
}


class TreeMap(dict):
    def __class_getitem__(cls, key):
        return cls


@pytest.fixture
def env():
    calls = []
    state = {"manifest": MANIFEST_RAW, "skill": SKILL, "answer": dict(ALLOW), "status": 200}

    def get(url):
        calls.append(url)
        raw = state["manifest"] if "/bundle.json?" in url else state["skill"]
        envelope = {"type": "file", "encoding": "base64", "size": len(raw), "content": base64.b64encode(raw).decode()}
        return types.SimpleNamespace(status=state["status"], body=json.dumps(envelope).encode())

    gl = types.ModuleType("genlayer")
    gl.contract = types.SimpleNamespace(Contract=object)
    gl.storage = types.SimpleNamespace(TreeMap=TreeMap)
    gl.u256 = int
    gl.public = types.SimpleNamespace(write=lambda f: f, view=lambda f: f)
    gl.vm = types.SimpleNamespace(UserError=ValueError, run_nondet=lambda fn, validator: fn())
    gl.message = types.SimpleNamespace(sender_address=types.SimpleNamespace(as_hex="0xOwner"))
    gl.nondet = types.SimpleNamespace(web=types.SimpleNamespace(get=get), exec_prompt=lambda *args, **kwargs: json.dumps(state["answer"]))
    before = sys.modules.get("genlayer")
    sys.modules["genlayer"] = gl
    try:
        spec = importlib.util.spec_from_file_location("skilltrust_contract_test", Path(__file__).parents[1] / "contracts/skilltrust.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        if before is None:
            sys.modules.pop("genlayer")
        else:
            sys.modules["genlayer"] = before
    contract = module.SkillTrust()
    contract.policies = {}
    contract.reviews = {}
    contract.used_nonces = {}
    contract.policy_count = 0
    contract.review_count = 0
    contract.create_policy("Local reader", "READ_FILES", "-", "No shell, network, wallet or secret access is permitted.")
    return contract, state, calls, gl


def test_allowed_bundle_is_hashed_and_recorded(env):
    contract, state, calls, _ = env
    receipt = contract.review_skill("1", BUNDLE_URL, NONCE)
    assert receipt["decision"] == "ALLOW"
    assert receipt["bundle_sha256"] == hashlib.sha256(state["manifest"]).hexdigest()
    assert receipt["file_hashes"] == [{"path": "SKILL.md", "sha256": hashlib.sha256(SKILL).hexdigest()}]
    assert contract.get_counts() == {"policies": 1, "reviews": 1}
    assert len(calls) == 2
    assert contract.get_review("1")["nonce"] == NONCE


def test_capability_outside_policy_is_blocked(env):
    contract, state, _, _ = env
    state["answer"] = {**ALLOW, "capabilities": ["READ_FILES", "NETWORK"]}
    receipt = contract.review_skill("1", BUNDLE_URL, NONCE)
    assert receipt["decision"] == "BLOCK"
    assert "Capability outside policy: NETWORK" in receipt["policy_violations"]


def test_missing_referenced_file_is_insufficient(env):
    contract, state, _, _ = env
    state["answer"] = {**ALLOW, "source_complete": False, "uncovered_references": ["scripts/run.py"]}
    assert contract.review_skill("1", BUNDLE_URL, NONCE)["decision"] == "INSUFFICIENT_EVIDENCE"


@pytest.mark.parametrize("domain_length", [157, 158, 166, 180])
def test_long_out_of_policy_domain_records_block(env, domain_length):
    contract, state, _, _ = env
    domain = "a" * 60 + "." + "b" * 60 + "." + "c" * (domain_length - 126) + ".com"
    assert len(domain) == domain_length
    state["answer"] = {**ALLOW, "domains": [domain]}
    receipt = contract.review_skill("1", BUNDLE_URL, NONCE)
    assert receipt["decision"] == "BLOCK"
    assert receipt["policy_violations"] == ["Domain outside policy: " + domain]
    assert contract.get_review("1")["domains"] == [domain]


def test_other_caller_cannot_consume_my_nonce(env):
    contract, state, _, gl = env
    gl.message.sender_address.as_hex = "0xAttacker"
    state["status"] = 503
    first = contract.review_skill("1", BUNDLE_URL, NONCE)
    assert first["decision"] == "INSUFFICIENT_EVIDENCE"
    gl.message.sender_address.as_hex = "0xOwner"
    state["status"] = 200
    second = contract.review_skill("1", BUNDLE_URL, NONCE)
    assert second["decision"] == "ALLOW" and second["requester"] == "0xOwner"
    assert contract.get_counts()["reviews"] == 2
    gl.message.sender_address.as_hex = "0xOWNER"
    with pytest.raises(ValueError, match="Nonce already used"):
        contract.review_skill("1", BUNDLE_URL, NONCE)


@pytest.mark.parametrize("problem", ["bad_digest", "missing_skill", "http_failure", "broken_json", "duplicate_key"])
def test_invalid_evidence_fails_closed(env, problem):
    contract, state, _, _ = env
    if problem == "bad_digest":
        state["skill"] = b"tampered"
    elif problem == "missing_skill":
        state["manifest"] = json.dumps({"schema": "skilltrust.bundle.v1", "files": [{"path": "OTHER.md", "sha256": hashlib.sha256(SKILL).hexdigest()}]}).encode()
    elif problem == "http_failure":
        state["status"] = 503
    elif problem == "broken_json":
        state["manifest"] = b"{"
    else:
        state["manifest"] = b'{"schema":"skilltrust.bundle.v1","files":[],"files":[]}'
    receipt = contract.review_skill("1", BUNDLE_URL, NONCE)
    assert receipt["decision"] == "INSUFFICIENT_EVIDENCE"
    assert not receipt["bundle_verified"]


@pytest.mark.parametrize("url", [
    "https://github.com/example/skilltrust/blob/main/bundle.json",
    f"https://github.com/example/skilltrust/blob/{SHA}/../bundle.json",
    f"https://github.com/example/skilltrust/blob/{SHA}/%2e%2e/bundle.json",
    f"https://github.com/example/skilltrust/blob/{SHA}/a//bundle.json",
])
def test_rejects_mutable_or_noncanonical_url(env, url):
    contract, _, calls, _ = env
    with pytest.raises(ValueError):
        contract.review_skill("1", url, NONCE)
    assert calls == []


def test_replay_and_owner_controls(env):
    contract, _, calls, gl = env
    contract.review_skill("1", BUNDLE_URL, NONCE)
    count = len(calls)
    with pytest.raises(ValueError, match="Nonce already used"):
        contract.review_skill("1", BUNDLE_URL, NONCE)
    assert len(calls) == count
    gl.message.sender_address.as_hex = "0xOther"
    with pytest.raises(ValueError, match="owner"):
        contract.deactivate_policy("1")
    gl.message.sender_address.as_hex = "0xOwner"
    contract.deactivate_policy("1")
    with pytest.raises(ValueError, match="inactive"):
        contract.review_skill("1", BUNDLE_URL, "c" * 48)


def test_post_consensus_forged_allow_is_rejected(env):
    contract, _, _, gl = env
    def forged(fn, *args):
        row = fn()
        row["decision"] = "ALLOW"
        row["policy_violations"] = ["network exfiltration"]
        return row
    gl.vm.run_nondet = forged
    with pytest.raises(ValueError, match="ALLOW contradicts"):
        contract.review_skill("1", BUNDLE_URL, NONCE)
    assert contract.get_counts()["reviews"] == 0


def test_model_text_with_json_fence_is_parsed(env):
    contract, state, _, gl = env
    gl.nondet.exec_prompt = lambda *args, **kwargs: "```json\n" + json.dumps(state["answer"]) + "\n```"
    assert contract.review_skill("1", BUNDLE_URL, NONCE)["decision"] == "ALLOW"


def test_matching_unverified_results_need_no_semantic_comparison(env):
    contract, _, _, gl = env
    def unexpected(*args, **kwargs):
        pytest.fail("Canonical evidence failures must not invoke the comparator")
    gl.nondet.exec_prompt = unexpected
    result = contract._unverified()
    assert contract._agree_results(result, dict(result), contract.get_policy("1")) is True
