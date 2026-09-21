"""
main.py — Web3 Red Team Simulator 파이프라인 통합 진입점.

CLI 모드:
    python main.py --local contracts            # 로컬 디렉터리 전체 파이프라인
    python main.py --repo https://github.com/o/r  # GitHub 저장소 정찰부터 실행
    python main.py --local contracts --no-exploit # 공격 시뮬레이션 생략
    python main.py --serve                       # FastAPI 서버 기동

파이프라인: ReconAgent → VulnerabilityDetector → ExploitAgent → ReportGenerator
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

from engine.config import EngineConfig, SecurityViolationError
from engine.exploit_agent import AttackResult, ExploitAgent
from engine.recon_agent import ReconAgent, ReconError, ReconResult
from engine.report_generator import ReportGenerator
from engine.vuln_detector import DetectionResult, VulnerabilityDetector

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("main")


def run_pipeline(
    repo_url: str | None = None,
    local_path: str | Path | None = None,
    config: EngineConfig | None = None,
    run_exploit: bool = True,
) -> dict:
    """정찰 → 탐지 → (선택) 공격 → 보고서 전체 파이프라인을 실행한다.

    Args:
        repo_url: GitHub 저장소 URL.
        local_path: 로컬 Solidity 디렉터리.
        config: 엔진 설정 (없으면 환경변수 기반 생성).
        run_exploit: 재진입 공격 시뮬레이션 실행 여부.

    Returns:
        요약 dict (report_id, report_path, findings, attack 등).

    Raises:
        ReconError: 정찰 실패.
        SecurityViolationError: 로컬 이외 네트워크 대상 시도.
    """
    config = config or EngineConfig.from_env()
    config.ensure_dirs()

    # 1) 정찰
    logger.info("=== [1/4] 정찰(Recon) 시작 ===")
    recon: ReconResult = ReconAgent(config).analyze(repo_url=repo_url, local_dir=local_path)

    # 2) 취약점 탐지
    logger.info("=== [2/4] 취약점 탐지 시작 ===")
    detection: DetectionResult = VulnerabilityDetector(config).detect(
        recon.source_dir, contracts=recon.contracts
    )

    # 3) 모의 공격 (재진입 취약점이 있을 때만)
    attack: AttackResult | None = None
    if run_exploit:
        logger.info("=== [3/4] 모의 공격 시뮬레이션 시작 ===")
        target_finding = detection.pick_reentrancy_finding()
        if target_finding is None:
            logger.info("재진입 취약점이 없어 공격 시뮬레이션을 건너뜁니다.")
        else:
            contract_info = next(
                (c for c in recon.contracts if c.name == target_finding.contract), None
            )
            attack = ExploitAgent(config).simulate_reentrancy(
                recon.source_dir, target_finding, contract_info
            )
    else:
        logger.info("=== [3/4] 공격 시뮬레이션 건너뜀 (--no-exploit) ===")

    # 4) 보고서
    logger.info("=== [4/4] HTML 보고서 생성 ===")
    report_id = time.strftime("report_%Y%m%d_%H%M%S")
    report_path = ReportGenerator(config).generate(recon, detection, attack, report_id)

    return {
        "report_id": report_id,
        "report_path": str(report_path),
        "source": recon.source_label,
        "contracts_found": [c.name for c in recon.contracts],
        "max_severity": detection.max_severity,
        "severity_counts": detection.severity_counts,
        "findings": [f.to_dict() for f in detection.sorted_findings()],
        "attack": attack.to_dict() if attack else None,
    }


# ---------------------------------------------------------------------------
# FastAPI 백엔드
# ---------------------------------------------------------------------------
def _build_app():
    """FastAPI 앱을 지연 생성한다 (의존성 부재 시 CLI 만 사용 가능)."""
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import FileResponse
    from pydantic import BaseModel

    app = FastAPI(
        title="Web3 Red Team Simulator (MVP)",
        description="스마트컨트랙트 취약점 자동 탐지 + 로컬 Ganache 모의 공격 시뮬레이터",
        version="0.1.0",
    )
    reports: dict[str, Path] = {}

    class AnalyzeRequest(BaseModel):
        """분석 요청 바디 — repo_url 또는 local_path 중 하나 필수."""

        repo_url: str | None = None
        local_path: str | None = None
        run_exploit: bool = True

    @app.post("/analyze")
    def analyze(req: AnalyzeRequest) -> dict:
        """전체 파이프라인을 실행하고 요약 JSON 을 반환한다."""
        if not req.repo_url and not req.local_path:
            raise HTTPException(422, "repo_url 또는 local_path 중 하나는 필수입니다.")
        config = EngineConfig.from_env()
        try:
            summary = run_pipeline(
                repo_url=req.repo_url,
                local_path=req.local_path,
                config=config,
                run_exploit=req.run_exploit,
            )
        except (ReconError, SecurityViolationError) as exc:
            raise HTTPException(400, str(exc)) from exc
        reports[summary["report_id"]] = Path(summary["report_path"])
        return summary

    @app.get("/report/{report_id}")
    def get_report(report_id: str) -> FileResponse:
        """생성된 HTML 보고서를 반환한다."""
        path = reports.get(report_id)
        if path is None or not path.exists():
            raise HTTPException(404, "보고서를 찾을 수 없습니다.")
        return FileResponse(path, media_type="text/html")

    return app


app = _build_app()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> int:
    """CLI 엔트리포인트."""
    parser = argparse.ArgumentParser(
        prog="web3-red-team-simulator",
        description="스마트컨트랙트 취약점 자동 탐지 + 로컬 모의 공격 시뮬레이터 (MVP)",
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--repo", help="분석 대상 GitHub 저장소 URL")
    src.add_argument("--local", help="분석 대상 로컬 Solidity 디렉터리")
    parser.add_argument("--rpc", default=None, help="로컬 Ganache RPC URL (기본: env 또는 127.0.0.1:8545)")
    parser.add_argument("--no-exploit", action="store_true", help="공격 시뮬레이션 생략")
    parser.add_argument("--serve", action="store_true", help="FastAPI 서버 기동 (--repo/--local 불필요)")
    parser.add_argument("--port", type=int, default=8000, help="FastAPI 포트")
    parser.add_argument("--json", action="store_true", help="결과 요약을 JSON 으로 출력")
    args = parser.parse_args()

    if args.serve:
        import uvicorn

        uvicorn.run(app, host="127.0.0.1", port=args.port)
        return 0

    config = EngineConfig.from_env()
    if args.rpc:
        config.rpc_url = args.rpc

    try:
        summary = run_pipeline(
            repo_url=args.repo,
            local_path=args.local,
            config=config,
            run_exploit=not args.no_exploit,
        )
    except (ReconError, SecurityViolationError) as exc:
        logger.error("파이프라인 실패: %s", exc)
        return 1

    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print("\n" + "=" * 62)
        print(f"  대상        : {summary['source']}")
        print(f"  컨트랙트    : {', '.join(summary['contracts_found'])}")
        print(f"  최고 심각도 : {summary['max_severity']}")
        for f in summary["findings"]:
            print(f"    [{f['severity']:<8}] {f['title']}  ({f['contract']}.{f['function'] or '-'})")
        if summary["attack"]:
            a = summary["attack"]
            state = "성공" if a["success"] else "실패"
            print(f"  공격 결과   : {state} — 탈취 {a['stolen_eth']} ETH")
        print(f"  보고서      : {summary['report_path']}")
        print("=" * 62)
    return 0


if __name__ == "__main__":
    sys.exit(main())
