"""ReconAgent 단위 테스트 — 네트워크 없이 로컬 파서만 검증."""
from __future__ import annotations

from pathlib import Path

import pytest

from engine.recon_agent import ReconAgent, ReconError

from conftest import PROJECT_ROOT


@pytest.fixture()
def agent(config) -> ReconAgent:
    return ReconAgent(config)


def test_local_parse_finds_contracts(agent: ReconAgent, contracts_dir: Path) -> None:
    """로컬 디렉터리 정찰 시 컨트랙트 2개와 함수들이 추출되어야 한다."""
    result = agent.analyze(local_dir=contracts_dir)

    names = {c.name for c in result.contracts}
    assert {"VulnerableBank", "SafeBank"} <= names

    vuln = next(c for c in result.contracts if c.name == "VulnerableBank")
    fn_names = {f.name for f in vuln.functions}
    assert {"deposit", "withdraw", "getBalance"} <= fn_names


def test_withdraw_signature_and_visibility(agent: ReconAgent, contracts_dir: Path) -> None:
    """withdraw 함수는 external/0-파라미터로 식별되어야 한다."""
    result = agent.analyze(local_dir=contracts_dir)
    vuln = next(c for c in result.contracts if c.name == "VulnerableBank")
    withdraw = vuln.find_function("withdraw")

    assert withdraw is not None
    assert withdraw.visibility == "external"
    assert withdraw.params_types == []
    assert withdraw.signature == "withdraw()"


def test_deposit_payable_flag(agent: ReconAgent, contracts_dir: Path) -> None:
    """deposit 함수는 payable 로 식별되어야 한다."""
    result = agent.analyze(local_dir=contracts_dir)
    vuln = next(c for c in result.contracts if c.name == "VulnerableBank")
    deposit = vuln.find_function("deposit")

    assert deposit is not None and deposit.is_payable


def test_external_call_patterns_detected(agent: ReconAgent, contracts_dir: Path) -> None:
    """msg.sender.call 패턴이 외부 호출로 탐지되어야 한다."""
    result = agent.analyze(local_dir=contracts_dir)
    kinds = result.external_call_summary

    assert kinds.get("call", 0) >= 2  # VulnerableBank.withdraw + SafeBank.withdraw
    vuln_calls = [ec for ec in result.external_calls if ec.contract == "VulnerableBank"]
    assert any(ec.function == "withdraw" for ec in vuln_calls)


def test_analyze_requires_exactly_one_source(agent: ReconAgent, contracts_dir: Path) -> None:
    """repo_url 과 local_dir 동시/미지정 시 ReconError."""
    with pytest.raises(ReconError):
        agent.analyze()
    with pytest.raises(ReconError):
        agent.analyze(repo_url="https://github.com/a/b", local_dir=contracts_dir)


def test_missing_dir_raises(agent: ReconAgent) -> None:
    with pytest.raises(ReconError):
        agent.analyze(local_dir=PROJECT_ROOT / "does_not_exist")
