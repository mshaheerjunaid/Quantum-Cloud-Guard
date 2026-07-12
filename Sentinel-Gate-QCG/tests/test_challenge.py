"""Proof-of-work challenge and pass-token tests."""

from __future__ import annotations

import time

from sentinel_gate_qcg.challenge import ChallengeService, _leading_zero_bits


def test_leading_zero_bits():
    assert _leading_zero_bits(bytes([0x00, 0x00, 0xFF])) == 16
    assert _leading_zero_bits(bytes([0x0F])) == 4
    assert _leading_zero_bits(bytes([0xFF])) == 0


def test_solve_then_verify_succeeds():
    svc = ChallengeService("secret-key-long-enough-for-hmac-usage-0001")
    ch = svc.issue("9.9.9.9", difficulty=8)
    solution = ChallengeService.solve(ch.token, 8)
    assert svc.verify("9.9.9.9", ch.token, solution) is True


def test_verify_rejects_wrong_solution():
    svc = ChallengeService("secret-key-long-enough-for-hmac-usage-0001")
    ch = svc.issue("9.9.9.9", difficulty=12)
    assert svc.verify("9.9.9.9", ch.token, "not-a-valid-solution") is False


def test_verify_rejects_forged_token():
    svc = ChallengeService("secret-key-long-enough-for-hmac-usage-0001")
    # Token with a valid shape but a bogus signature must be rejected.
    forged = f"{int(time.time())}.deadbeef.8.{'0' * 64}"
    assert svc.verify("9.9.9.9", forged, "0") is False


def test_verify_rejects_expired_challenge():
    svc = ChallengeService("secret-key-long-enough-for-hmac-usage-0001", ttl=0)
    ch = svc.issue("9.9.9.9", difficulty=4)
    sol = ChallengeService.solve(ch.token, 4)
    time.sleep(0.01)
    assert svc.verify("9.9.9.9", ch.token, sol) is False


def test_pass_token_roundtrip_and_ip_binding():
    svc = ChallengeService("secret-key-long-enough-for-hmac-usage-0001")
    token = svc.issue_pass("9.9.9.9")
    assert svc.verify_pass("9.9.9.9", token) is True
    # A pass minted for one IP must not validate for another (no replay/share).
    assert svc.verify_pass("8.8.8.8", token) is False
    assert svc.verify_pass("9.9.9.9", None) is False
    assert svc.verify_pass("9.9.9.9", "garbage") is False


def test_pass_token_expiry():
    svc = ChallengeService("secret-key-long-enough-for-hmac-usage-0001", pass_ttl=0)
    token = svc.issue_pass("9.9.9.9")
    time.sleep(0.01)
    assert svc.verify_pass("9.9.9.9", token) is False
