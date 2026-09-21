"""VulnerabilityDetector 테스트 — 휴리스틱은 항상, Slither는 설치 시 검증."""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.vuln_detector import VulnerabilityDetector
from engine.recon_agent import ReconAgent


@pytest.fixture()
def detection_result(config, contracts_dir: Path):
    contracts, _, _ = ReconAgent.parse_directory(contracts_dir)
    return VulnerabilityDetector(config).detect(contracts_dir, contracts=contracts)


def _heur_findings(result, contract: str, function: str | None = None):
    out = [
        f
        for f in result.findings
        if f.source == "heuristic" and f.contract == contract
        and (function is None or f.function == function)
    ]
    return out


def test_reentrancy_detected_in_vulnerable_bank(detection_result) -> None:
    """VulnerableBank.withdraw 의 재진입이 (어떤 엔진이든) 탐지되어야 한다.

    참고: Slither 가 설치된 환경에서는 dedupe 정책상 Slither 결과가
    휴리스틱 결과를 대체하므로 source 를 특정하지 않는다.
    """
    findings = [
        f
        for f in detection_result.findings
        if f.contract == "VulnerableBank" and f.function == "withdraw"
    ]
    reentrancies = [f for f in findings if f.is_reentrancy]
    assert reentrancies, "재진입 취약점이 탐지되지 않았습니다"

    top = max(reentrancies, key=lambda f: f.severity_rank)
    assert top.severity in ("HIGH", "CRITICAL")
    assert top.attack_path  # 공격 경로 설명 포함
    assert top.fix_snippet  # 수정 제안 스니펫 포함


def test_safe_bank_has_no_reentrancy_finding(detection_result) -> None:
    """SafeBank 는 재진입 휴리스틱에 걸리지 않아야 한다."""
    findings = _heur_findings(detection_result, "SafeBank", "withdraw")
    assert not any("REENTRANCY" in f.id for f in findings)


def test_tx_origin_detected(detection_result) -> None:
    """tx.origin 인증 사용이 탐지되어야 한다."""
    findings = _heur_findings(detection_result, "VulnerableBank", "transferOwnershipTxOrigin")
    assert any(f.id == "HEUR-TX-ORIGIN" for f in findings)


def test_unchecked_arithmetic_detected(detection_result) -> None:
    """unchecked 산술 블록이 탐지되어야 한다."""
    findings = _heur_findings(detection_result, "VulnerableBank", "addCreditsUnchecked")
    assert any(f.id == "HEUR-UNCHECKED-ARITH" for f in findings)


def test_result_structure_and_json(detection_result) -> None:
    """탐지 결과는 구조화 dict/JSON 으로 직렬화 가능해야 한다."""
    data = detection_result.to_dict()
    assert "findings" in data and len(data["findings"]) >= 3
    assert data["max_severity"] in ("CRITICAL", "HIGH")
    assert detection_result.to_json()  # JSON 직렬화 가능
    # 심각도 내림차순 정렬 확인
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    ranks = [order[f["severity"]] for f in data["findings"]]
    assert ranks == sorted(ranks, reverse=True)


@pytest.mark.skipif(shutil.which("slither") is None, reason="slither 미설치")
def test_slither_integration(config, contracts_dir: Path) -> None:
    """Slither 가 설치된 환경에서 재진입 detector 가 동작해야 한다."""
    result = VulnerabilityDetector(config).detect(contracts_dir)
    if result.slither_used:
        slither_ids = {f.id for f in result.findings if f.source == "slither"}
        assert any("reentrancy" in fid.lower() for fid in slither_ids)
    else:
        pytest.skip("slither 실행 환경 미구축 (solc 부재 등) — 휴리스틱으로 대체됨")
