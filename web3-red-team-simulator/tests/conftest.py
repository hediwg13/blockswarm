"""테스트용 공통 픽스처."""
from __future__ import annotations

from pathlib import Path

import pytest

from engine.config import EngineConfig

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture()
def contracts_dir() -> Path:
    """샘플 취약 컨트랙트 디렉터리."""
    return PROJECT_ROOT / "contracts"


@pytest.fixture()
def config(tmp_path: Path) -> EngineConfig:
    """테스트 격리용 EngineConfig (작업/보고서 디렉터리를 tmp 로 분리)."""
    cfg = EngineConfig(workdir=tmp_path / "work")
    cfg.reports_dir = tmp_path / "reports"
    cfg.ensure_dirs()
    return cfg
