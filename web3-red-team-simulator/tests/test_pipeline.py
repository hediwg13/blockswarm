"""전체 파이프라인 통합 테스트 — 공격은 Ganache 구동 시에만 실행."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from engine.config import EngineConfig
from main import run_pipeline

RPC_URL = os.environ.get("RTS_RPC_URL", "http://127.0.0.1:8545")


def _ganache_up() -> bool:
    try:
        from web3 import Web3

        w3 = Web3(Web3.HTTPProvider(RPC_URL, request_kwargs={"timeout": 3}))
        return w3.is_connected() and len(w3.eth.accounts) >= 2
    except Exception:
        return False


def test_pipeline_without_exploit(config: EngineConfig, contracts_dir: Path) -> None:
    """공격 생략 모드: 정찰→탐지→보고서가 네트워크 없이 완주되어야 한다."""
    summary = run_pipeline(local_path=contracts_dir, config=config, run_exploit=False)

    assert "VulnerableBank" in summary["contracts_found"]
    assert summary["max_severity"] in ("CRITICAL", "HIGH")
    assert summary["findings"]
    assert summary["attack"] is None
    assert Path(summary["report_path"]).exists()


@pytest.mark.skipif(
    not _ganache_up(), reason="로컬 Ganache(8545) 미구동 — 통합 공격 테스트 건너뜀"
)
def test_pipeline_full_with_attack(contracts_dir: Path, tmp_path: Path) -> None:
    """스펙 검증: 취약 샘플로 정찰→탐지→공격 성공→보고서까지 완주되어야 한다."""
    config = EngineConfig(workdir=tmp_path / "work")
    config.reports_dir = tmp_path / "reports"
    config.ensure_dirs()

    summary = run_pipeline(local_path=contracts_dir, config=config, run_exploit=True)

    assert summary["attack"] is not None
    attack = summary["attack"]
    assert attack["success"] is True
    assert attack["stolen_eth"] > 0
    assert Path(summary["report_path"]).exists()
