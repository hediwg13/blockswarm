"""
engine/report_generator.py — HTML 보고서 생성기.

정찰/탐지/공격 결과를 받아 자기완결형(외부 리소스 없는) HTML 보고서를 만든다.
섹션: 요약 KPI → 대상 정보 → 취약점 목록/상세(공격 경로·수정 제안) →
공격 시뮬레이션 결과(시나리오·트랜잭션) → 면책 조항.
"""
from __future__ import annotations

import html
import json
import logging
import time
from pathlib import Path

from engine.config import EngineConfig
from engine.exploit_agent import AttackResult
from engine.recon_agent import ReconResult
from engine.vuln_detector import DetectionResult, SEVERITY_ORDER

logger = logging.getLogger(__name__)

_SEV_COLORS: dict[str, str] = {
    "CRITICAL": "#b91c1c",
    "HIGH": "#ea580c",
    "MEDIUM": "#ca8a04",
    "LOW": "#2563eb",
    "INFO": "#6b7280",
}

_CSS = """\
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', 'Malgun Gothic', sans-serif; background: #0f172a;
       color: #e2e8f0; padding: 32px; line-height: 1.6; }
.wrap { max-width: 1080px; margin: 0 auto; }
h1 { font-size: 26px; margin-bottom: 4px; }
h2 { font-size: 19px; margin: 28px 0 12px; border-left: 4px solid #38bdf8; padding-left: 10px; }
.sub { color: #94a3b8; font-size: 13px; margin-bottom: 24px; }
.card { background: #1e293b; border: 1px solid #334155; border-radius: 10px;
        padding: 16px 20px; margin-bottom: 14px; }
.kpis { display: flex; gap: 14px; flex-wrap: wrap; margin: 16px 0; }
.kpi { flex: 1 1 160px; background: #1e293b; border: 1px solid #334155;
       border-radius: 10px; padding: 14px 18px; text-align: center; }
.kpi .num { font-size: 26px; font-weight: 700; }
.kpi .lbl { font-size: 12px; color: #94a3b8; }
table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 14px; }
th, td { padding: 8px 10px; border-bottom: 1px solid #334155; text-align: left;
         vertical-align: top; }
th { color: #94a3b8; font-weight: 600; background: #16213a; }
.badge { display: inline-block; padding: 2px 10px; border-radius: 999px;
         color: #fff; font-size: 11px; font-weight: 700; letter-spacing: .4px; }
pre { background: #0b1220; border: 1px solid #334155; border-radius: 8px;
      padding: 12px 14px; overflow-x: auto; font-size: 13px; margin-top: 10px;
      font-family: Consolas, 'D2Coding', monospace; }
code.inline { background: #0b1220; padding: 1px 6px; border-radius: 4px; font-size: 13px; }
.ok { color: #4ade80; font-weight: 700; }
.fail { color: #f87171; font-weight: 700; }
.muted { color: #94a3b8; font-size: 12px; }
.attack-path { background: #2a1a10; border: 1px solid #7c2d12; border-radius: 8px;
               padding: 10px 14px; margin-top: 10px; font-size: 13px; }
.disclaimer { margin-top: 32px; padding: 14px 18px; border: 1px dashed #64748b;
              border-radius: 10px; color: #94a3b8; font-size: 12px; }
"""


def esc(text: object) -> str:
    """HTML 특수문자를 이스케이프한다."""
    return html.escape(str(text), quote=True)


def sev_badge(sev: str) -> str:
    """심각도 배지 HTML을 반환한다."""
    color = _SEV_COLORS.get(sev, "#6b7280")
    return f'<span class="badge" style="background:{color}">{esc(sev)}</span>'


class ReportGenerator:
    """분석 결과를 단일 HTML 보고서로 변환한다."""

    def __init__(self, config: EngineConfig) -> None:
        self.config = config

    def generate(
        self,
        recon: ReconResult,
        detection: DetectionResult,
        attack: AttackResult | None = None,
        report_id: str | None = None,
    ) -> Path:
        """보고서를 생성하고 파일 경로를 반환한다.

        Args:
            recon: 정찰 결과.
            detection: 취약점 탐지 결과.
            attack: 공격 시뮬레이션 결과 (미실행 시 None).
            report_id: 보고서 식별자 (없으면 타임스탬프 생성).

        Returns:
            생성된 HTML 파일 경로.
        """
        self.config.ensure_dirs()
        report_id = report_id or time.strftime("report_%Y%m%d_%H%M%S")
        out_path = Path(self.config.reports_dir) / f"{report_id}.html"
        out_path.write_text(
            self._render(recon, detection, attack, report_id), encoding="utf-8"
        )
        logger.info("[Report] 보고서 생성: %s", out_path)
        return out_path

    # ------------------------------------------------------------------
    # 렌더링
    # ------------------------------------------------------------------
    def _render(
        self,
        recon: ReconResult,
        detection: DetectionResult,
        attack: AttackResult | None,
        report_id: str,
    ) -> str:
        counts = detection.severity_counts
        findings = detection.sorted_findings()
        meta = recon.repo_metadata

        kpi_attack = self._attack_kpi(attack)
        parts: list[str] = [
            "<!DOCTYPE html><html lang='ko'><head><meta charset='utf-8'>",
            f"<title>Red Team Report — {esc(report_id)}</title>",
            f"<style>{_CSS}</style></head><body><div class='wrap'>",
            "<h1>🛡️ Web3 Red Team 시뮬레이션 보고서</h1>",
            f"<div class='sub'>보고서 ID: {esc(report_id)} · 생성: "
            f"{time.strftime('%Y-%m-%d %H:%M:%S')} · 대상: {esc(recon.source_label)}</div>",
            # KPI
            "<div class='kpis'>",
            f"<div class='kpi'><div class='num'>{len(findings)}</div>"
            "<div class='lbl'>탐지된 취약점</div></div>",
            f"<div class='kpi'><div class='num' style='color:{_SEV_COLORS['CRITICAL']}'>"
            f"{counts.get('CRITICAL', 0)}</div><div class='lbl'>CRITICAL</div></div>",
            f"<div class='kpi'><div class='num' style='color:{_SEV_COLORS['HIGH']}'>"
            f"{counts.get('HIGH', 0)}</div><div class='lbl'>HIGH</div></div>",
            kpi_attack,
            "</div>",
            # 대상 정보
            "<h2>1. 대상 정보 (Recon)</h2>",
            "<div class='card'><table>",
            "<tr><th>항목</th><th>값</th></tr>",
            f"<tr><td>소스</td><td>{esc(recon.source_label)}</td></tr>",
            f"<tr><td>Solidity 파일</td><td>{len(recon.sol_files)}개</td></tr>",
            f"<tr><td>컨트랙트</td><td>{esc(', '.join(c.name for c in recon.contracts))}</td></tr>",
            f"<tr><td>pragma</td><td>{esc(', '.join(recon.pragma_versions) or 'n/a')}</td></tr>",
            f"<tr><td>외부 호출 패턴</td><td>{esc(json.dumps(recon.external_call_summary, ensure_ascii=False))}</td></tr>",
        ]
        for key, label in (
            ("full_name", "저장소"),
            ("stars", "스타"),
            ("default_branch", "기본 브랜치"),
            ("language", "주 언어"),
        ):
            if meta.get(key):
                parts.append(f"<tr><td>{label}</td><td>{esc(meta[key])}</td></tr>")
        parts.append("</table></div>")

        # 취약점 목록
        parts.append("<h2>2. 탐지된 취약점</h2>")
        if not findings:
            parts.append("<div class='card'>탐지된 취약점이 없습니다. ✅</div>")
        else:
            parts.append(
                "<div class='card'><table><tr><th>ID</th><th>심각도</th>"
                "<th>제목</th><th>위치</th><th>출처</th></tr>"
            )
            for f in findings:
                loc = f"{Path(f.file).name if f.file else '?'}"
                if f.line:
                    loc += f":{f.line}"
                parts.append(
                    f"<tr><td>{esc(f.id)}</td><td>{sev_badge(f.severity)}</td>"
                    f"<td>{esc(f.title)}</td>"
                    f"<td><code class='inline'>{esc(f.contract)}"
                    f".{esc(f.function or '-')}() <span class='muted'>@ {esc(loc)}</span>"
                    "</code></td><td>{}</td></tr>".format(
                        "<span class='muted'>slither</span>"
                        if f.source == "slither"
                        else "<span class='muted'>heuristic</span>"
                    )
                )
            parts.append("</table></div>")

        # 취약점 상세
        parts.append("<h2>3. 취약점 상세 · 공격 경로 · 수정 제안</h2>")
        for f in findings:
            parts.append(f"<div class='card'><p>{sev_badge(f.severity)} <b>{esc(f.title)}</b>"
                         f" <span class='muted'>({esc(f.id)} · 신뢰도 {esc(f.confidence)})</span></p>")
            if f.description:
                parts.append(f"<p style='margin-top:8px'>{esc(f.description)}</p>")
            if f.attack_path:
                parts.append(
                    f"<div class='attack-path'>⚔️ <b>예상 공격 경로:</b> {esc(f.attack_path)}</div>"
                )
            if f.fix_snippet:
                parts.append("<p class='muted' style='margin-top:10px'>✅ 수정 제안:</p><pre>"
                             f"<code>{esc(f.fix_snippet)}</code></pre>")
            parts.append("</div>")

        # 공격 시뮬레이션
        parts.append("<h2>4. 모의 공격 시뮬레이션 (로컬 Ganache)</h2>")
        parts.append(self._attack_section(attack))

        parts.append(
            "<div class='disclaimer'>⚠️ <b>면책 조항:</b> 본 보고서의 모든 공격 시뮬레이션은 "
            "로컬 Ganache 개발 네트워크의 가상 자금으로만 수행되었습니다. 실제 자산, 메인넷, "
            "타인의 컨트랙트 대상 사용은 금지되며 본 도구는 보안 진단/교육 목적으로만 사용해야 합니다.</div>"
        )
        parts.append("</div></body></html>")
        return "\n".join(parts)

    @staticmethod
    def _attack_kpi(attack: AttackResult | None) -> str:
        """공격 결과 KPI 카드 HTML."""
        if attack is None:
            return ("<div class='kpi'><div class='num'>—</div>"
                    "<div class='lbl'>공격 미실행</div></div>")
        if attack.success:
            return (
                f"<div class='kpi'><div class='num ok'>+{attack.stolen_wei / 1e18:.3f} ETH</div>"
                "<div class='lbl'>탈취 시뮬레이션 성공</div></div>"
            )
        return ("<div class='kpi'><div class='num fail'>FAILED</div>"
                "<div class='lbl'>공격 실패/불가</div></div>")

    def _attack_section(self, attack: AttackResult | None) -> str:
        """공격 시뮬레이션 섹션 HTML."""
        if attack is None:
            return ("<div class='card'>공격 시뮬레이션이 실행되지 않았습니다 "
                    "(--no-exploit 또는 재진입 취약점 부재).</div>")

        status = (
            "<span class='ok'>✅ 공격 성공</span>"
            if attack.success
            else f"<span class='fail'>❌ 공격 실패</span> {esc(attack.error or '')}"
        )
        parts = [f"<div class='card'><p>{status}</p><table>"]
        rows = [
            ("공격 유형", attack.attack_type),
            ("대상 컨트랙트", f"{attack.target_name} @ {attack.target_address or '-'}"),
            ("익스플로잇", attack.exploit_address or "-"),
            ("공격자 EOA", attack.attacker_eoa or "-"),
            ("탈취 금액", f"{attack.stolen_wei / 1e18:.6f} ETH"),
            (
                "타깃 잔액 변화",
                f"{attack.target_balance_before_wei / 1e18:.4f} → "
                f"{attack.target_balance_after_wei / 1e18:.4f} ETH",
            ),
            ("총 가스 사용", f"{attack.gas_used:,} gas"),
        ]
        parts.extend(f"<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>" for k, v in rows)
        parts.append("</table>")

        parts.append("<p class='muted' style='margin-top:14px'>공격 시나리오:</p><table>")
        for s in attack.scenario:
            parts.append(
                f"<tr><td style='width:40px'>{s.order}</td><td style='width:170px'>"
                f"<b>{esc(s.action)}</b></td><td>{esc(s.detail)}</td></tr>"
            )
        parts.append("</table>")

        if attack.executed_steps:
            parts.append("<p class='muted' style='margin-top:14px'>실행 기록:</p><table>")
            for s in attack.executed_steps:
                parts.append(
                    f"<tr><td style='width:40px'>{s.order}</td><td style='width:170px'>"
                    f"<b>{esc(s.action)}</b></td><td>{esc(s.detail)}</td></tr>"
                )
            parts.append("</table>")

        if attack.tx_hashes:
            parts.append("<p class='muted' style='margin-top:14px'>트랜잭션 해시:</p><pre><code>")
            parts.append("\n".join(esc(h) for h in attack.tx_hashes))
            parts.append("</code></pre>")
        parts.append("</div>")
        return "\n".join(parts)
