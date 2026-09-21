"""ReportGenerator 테스트 — 샘플 데이터로 HTML 생성 검증."""
from __future__ import annotations

from pathlib import Path

from engine.report_generator import ReportGenerator
from engine.recon_agent import ReconAgent
from engine.vuln_detector import VulnerabilityDetector


def _build_inputs(contracts_dir: Path, config):
    recon_result = ReconAgent(config).analyze(local_dir=contracts_dir)
    detection = VulnerabilityDetector(config).detect(
        recon_result.source_dir, contracts=recon_result.contracts
    )
    return recon_result, detection


def test_report_generated_with_content(config, contracts_dir: Path) -> None:
    """보고서 파일이 생성되고 핵심 섹션을 포함해야 한다."""
    recon, detection = _build_inputs(contracts_dir, config)
    path = ReportGenerator(config).generate(recon, detection, attack=None, report_id="t_report")

    assert Path(path).exists()
    html_text = Path(path).read_text(encoding="utf-8")
    assert "Red Team" in html_text
    assert "탐지된 취약점" in html_text
    assert "VulnerableBank" in html_text
    assert "면책 조항" in html_text


def test_report_contains_attack_section(config, contracts_dir: Path) -> None:
    """공격 결과가 있으면 시나리오/트랜잭션 섹션이 포함되어야 한다."""
    from engine.exploit_agent import AttackResult, AttackStep

    recon, detection = _build_inputs(contracts_dir, config)
    attack = AttackResult(
        success=True,
        vulnerability_id="HEUR-REENTRANCY",
        target_name="VulnerableBank",
        target_address="0xabc",
        stolen_wei=5 * 10**18,
        scenario=[AttackStep(1, "타깃 배포", "테스트")],
        tx_hashes=["0xdeadbeef"],
    )
    path = ReportGenerator(config).generate(recon, detection, attack=attack, report_id="t_attack")
    html_text = Path(path).read_text(encoding="utf-8")

    assert "공격 성공" in html_text
    assert "5.000000 ETH" in html_text
    assert "0xdeadbeef" in html_text


def test_report_escapes_html(config, contracts_dir: Path, tmp_path: Path) -> None:
    """악성 문자열이 포함된 입력도 이스케이프되어야 한다."""
    sol = tmp_path / "x.sol"
    sol.write_text(
        "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.19;\n"
        "contract A { function f() external payable returns (uint256) "
        "{ <script>alert(1)</script> }\n}\n",
        encoding="utf-8",
    )
    recon = ReconAgent(config).analyze(local_dir=tmp_path)
    detection = VulnerabilityDetector(config).detect(tmp_path, contracts=recon.contracts)
    path = ReportGenerator(config).generate(recon, detection, report_id="t_esc")
    html_text = Path(path).read_text(encoding="utf-8")

    assert "<script>alert(1)</script>" not in html_text
