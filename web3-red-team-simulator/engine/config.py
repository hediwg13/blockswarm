"""
engine/config.py — 중앙 설정 관리.

모든 엔진 모듈이 공유하는 설정값(네트워크, 경로, 컴파일러 버전, 자금 규모 등)을
하나의 데이터클래스로 관리한다. 환경 변수로 런타임 오버라이드가 가능하다.

환경 변수:
    RTS_RPC_URL    : 로컬 Ganache RPC 엔드포인트 (기본 http://127.0.0.1:8545)
    RTS_WORKDIR    : 클론/빌드 아티팩트 작업 디렉터리 (기본 .rts_workdir)
    GITHUB_TOKEN   : GitHub API 토큰 (미설정 시 비인증 요청 — 낮은 레이트리밋)
    SOLC_VERSION   : py-solc-x 로 사용할 solc 버전 (기본 0.8.19)

보안 제약:
    공격 시뮬레이션은 로컬 Ganache 네트워크에서만 실행된다.
    assert_local_rpc() 가 이 제약을 강제한다.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

# 보안 제약: 모의 공격 실행을 허용하는 유일한 호스트 (로컬 전용)
ALLOWED_ATTACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


class SecurityViolationError(RuntimeError):
    """보안 제약(로컬 전용 실행 등) 위반 시 발생."""


def assert_local_rpc(rpc_url: str) -> None:
    """공격 대상 RPC URL이 로컬 Ganache인지 검증한다.

    Args:
        rpc_url: 검증할 RPC 엔드포인트 URL.

    Raises:
        SecurityViolationError: URL이 로컬호스트가 아니거나 http(s) 스킴이 아닌 경우.
    """
    parsed = urlparse(rpc_url)
    if parsed.scheme not in ("http", "https"):
        raise SecurityViolationError(f"지원하지 않는 RPC 스킴입니다: {rpc_url!r} (http/https 만 허용)")
    host = (parsed.hostname or "").lower()
    if host not in ALLOWED_ATTACK_HOSTS:
        raise SecurityViolationError(
            f"모의 공격은 로컬 Ganache({sorted(ALLOWED_ATTACK_HOSTS)})에서만 허용됩니다. "
            f"요청된 호스트: {host!r}"
        )


@dataclass
class EngineConfig:
    """엔진 전역 설정.

    Attributes:
        rpc_url: 로컬 Ganache RPC 엔드포인트.
        workdir: GitHub 코드 다운로드 / 익스플로잇 빌드 아티팩트 디렉터리.
        reports_dir: 생성된 HTML 보고서 저장 디렉터리.
        solc_version: 컴파일에 사용할 solc 버전.
        github_token: GitHub API 토큰 (선택).
        max_repo_sol_files: 저장소에서 가져올 .sol 파일 수 상한 (레이트리밋 보호).
        slither_timeout: Slither 서브프로세스 타임아웃(초).
        target_funding_eth: 시뮬레이션용 타깃 컨트랙트에 예치할 ETH.
        attacker_funding_eth: 공격 컨트랙트 배포 시 부여할 초기 자금(ETH).
        attack_gas_limit: 공격 트랜잭션 gas 상한.
        max_reentries: 재진입 공격의 최대 재진입 횟수 (무한 루프 방지).
    """

    rpc_url: str = field(
        default_factory=lambda: os.environ.get("RTS_RPC_URL", "http://127.0.0.1:8545")
    )
    workdir: Path = field(
        default_factory=lambda: Path(os.environ.get("RTS_WORKDIR", ".rts_workdir"))
    )
    reports_dir: Path = field(default_factory=lambda: Path("reports"))
    solc_version: str = field(
        default_factory=lambda: os.environ.get("SOLC_VERSION", "0.8.19")
    )
    github_token: str | None = field(
        default_factory=lambda: os.environ.get("GITHUB_TOKEN") or None
    )
    max_repo_sol_files: int = 50
    slither_timeout: int = 180
    target_funding_eth: float = 5.0
    attacker_funding_eth: float = 2.0
    attack_gas_limit: int = 5_000_000
    max_reentries: int = 10

    def ensure_dirs(self) -> None:
        """작업 디렉터리와 보고서 디렉터리를 생성한다(멱등)."""
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_env(cls) -> "EngineConfig":
        """환경 변수를 반영한 설정 인스턴스를 반환한다.

        Returns:
            구성된 EngineConfig 인스턴스.
        """
        return cls()
