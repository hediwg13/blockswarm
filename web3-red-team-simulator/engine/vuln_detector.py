"""
engine/vuln_detector.py — 취약점 탐지기.

두 탐지 엔진을 결합해 구조화된 결과를 반환한다.
    1. Slither (서브프로세스, --json): 정적 분석의 1차 권위 소스
    2. 휴리스틱 스캐너: Slither 미설치/실패 환경에서도 동작하는 보조 탐지
       (재진입, tx.origin 인증, unchecked 산술, 무권한 이더 인출 등)

산출물은 Finding/DetectionResult 데이터클래스이며 to_json() 으로 구조화된
JSON 을 얻을 수 있다.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from engine.config import EngineConfig
from engine.recon_agent import ContractInfo, FunctionInfo, ReconAgent, mask_comments

logger = logging.getLogger(__name__)

# 심각도 순위 (높을수록 위험)
SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}

# ---------------------------------------------------------------------------
# Slither detector 매핑: check 이름 -> (심각도, 제목, 공격 경로, 수정 스니펫)
# ---------------------------------------------------------------------------
_DETECTOR_MAP: dict[str, dict] = {
    "reentrancy-eth": {
        "severity": "CRITICAL",
        "title": "재진입(Reentrancy) — 이더 탈취 가능",
        "attack_path": "공격 컨트랙트가 {contract}.{function}() 을 호출 → 폴백/receive 에서 재호출 → 상태 갱신 전 잔액을 반복 인출",
        "fix": (
            "function withdraw() external noReentrant {{\n"
            "    uint256 amount = balances[msg.sender];\n"
            "    require(amount > 0, \"nothing\");\n"
            "    balances[msg.sender] = 0;                       // Effect 를 먼저\n"
            "    (bool ok, ) = msg.sender.call{{value: amount}}(\"\"); // Interaction 은 마지막에\n"
            "    require(ok, \"transfer failed\");\n"
            "}}"
        ),
    },
    "reentrancy-no-eth": {
        "severity": "MEDIUM",
        "title": "재진입 — ERC 토큰/상태 조작 가능",
        "attack_path": "{contract}.{function}() 재진입으로 내부 상태(토큰 잔액/플래그)를 조작",
        "fix": "Checks-Effects-Interactions 패턴 적용 + ReentrancyGuard 사용",
    },
    "reentrancy-unlimited-gas": {
        "severity": "LOW",
        "title": "무제한 gas 재진입 가능성",
        "attack_path": "{contract}.{function}() 에 gas 를 충분히 부여해 재진입 시도",
        "fix": "상태 갱신을 외부 호출 이전으로 이동",
    },
    "arbitrary-send-eth": {
        "severity": "CRITICAL",
        "title": "임의 주소 이더 전송 (자금 탈취)",
        "attack_path": "공격자가 제어 가능한 파라미터/상태로 {contract}.{function}() 을 호출해 컨트랙트 보유 ETH 를 임의 주소로 인출",
        "fix": "전송 대상/금액에 대한 owner 검증(onlyOwner) 및 화이트리스트 적용",
    },
    "arbitrary-send": {
        "severity": "HIGH",
        "title": "임의 주소 자금 전송 가능",
        "attack_path": "통제되지 않은 흐름으로 {contract}.{function}() 이 임의 대상에게 자금 전송",
        "fix": "접근 제어자 추가 및 전송 경로 검증",
    },
    "controlled-delegatecall": {
        "severity": "CRITICAL",
        "title": "사용자 제어 delegatecall (스토리지 장악)",
        "attack_path": "{contract}.{function}() 의 delegatecall 대상을 공격자가 지정 → 컨트랙트 컨텍스트에서 임의 코드 실행",
        "fix": "delegatecall 대상을 불변(immutable)/화이트리스트로 고정",
    },
    "suicidal": {
        "severity": "HIGH",
        "title": "누구나 실행 가능한 selfdestruct",
        "attack_path": "공격자가 {contract}.{function}() 을 호출해 컨트랙트 파괴 및 잔액 흡수",
        "fix": "selfdestruct 에 onlyOwner 등 강한 접근 제어 적용",
    },
    "tx-origin": {
        "severity": "HIGH",
        "title": "tx.origin 기반 인증 (피싱 취약)",
        "attack_path": "피싱 컨트랙트가 소유자를 유인 → 소유자 트랜잭션 내에서 {contract}.{function}() 호출 시 tx.origin 검증 통과",
        "fix": "tx.origin 대신 msg.sender 기반 검증 사용",
    },
    "unchecked-transfer": {
        "severity": "MEDIUM",
        "title": "반환값 미확인 토큰 전송",
        "attack_path": "{contract}.{function}() 에서 transfer 반환값을 확인하지 않아 전송 실패 시 상태 불일치",
        "fix": "SafeTransferLib / require(transfer(...)) 로 반환값 확인",
    },
    "weak-prng": {
        "severity": "MEDIUM",
        "title": "취약한 난수원 (block.* 기반 PRNG)",
        "attack_path": "검증자/마이너가 블록 변수를 조작해 {contract}.{function}() 의 무작위성 왜곡",
        "fix": "체인링크 VRF 등 검증 가능한 난수 사용",
    },
    "protected-vars": {
        "severity": "HIGH",
        "title": "보호되지 않은 중요 상태 변수",
        "attack_path": "공격자가 {contract} 의 중요 상태 변수를 직접 조작하는 함수 경로 확보",
        "fix": "상태 변수 변경 경로에 접근 제어 적용",
    },
    "unprotected-upgrade": {
        "severity": "CRITICAL",
        "title": "무보호 업그레이드 경로",
        "attack_path": "공격자가 {contract}.{function}() 으로 구현체 교체 후 악의적 로직 실행",
        "fix": "업그레이드 함수에 다중서명/타임락 보호 적용",
    },
}

# ---------------------------------------------------------------------------
# 휴리스틱 상수
# ---------------------------------------------------------------------------
_STATE_WRITE_RE = re.compile(
    r"(\w+)\s*\[[^\]]+\]\s*(?:\+|-)?=[^=]"                       # mapping 쓰기
    r"|\b(\w*[Bb]alance\w*|\w*[Cc]redit\w*|\w*[Dd]eposit\w*)\s*(?:\+|-)?=[^=]"
)
_TX_ORIGIN_RE = re.compile(r"\btx\.origin\b")
_UNCHECKED_RE = re.compile(r"\bunchecked\b")
_ZERO_PRAGMA_RE = re.compile(r"pragma\s+solidity\s*[^;]*\^?0\.([0-7])\.")
_ETH_MOVE_RE = re.compile(r"\.call\s*\{|\.transfer\s*\(|\.send\s*\(")


@dataclass
class Finding:
    """단일 취약점 탐지 결과."""

    id: str                    # 예: SLITHER-reentrancy-eth / HEUR-REENTRANCY
    title: str
    severity: str              # CRITICAL | HIGH | MEDIUM | LOW | INFO
    confidence: str            # High | Medium | Low
    contract: str
    function: str | None = None
    file: str | None = None
    line: int | None = None
    description: str = ""
    attack_path: str = ""
    fix_snippet: str | None = None
    source: str = "slither"    # slither | heuristic

    @property
    def severity_rank(self) -> int:
        """심각도 순위 값."""
        return SEVERITY_ORDER.get(self.severity, -1)

    @property
    def is_reentrancy(self) -> bool:
        """재진입 계열 취약점 여부."""
        return "reentrancy" in (self.title + self.id).lower()

    def to_dict(self) -> dict:
        """직렬화용 dict 반환."""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "contract": self.contract,
            "function": self.function,
            "file": self.file,
            "line": self.line,
            "description": self.description,
            "attack_path": self.attack_path,
            "fix_snippet": self.fix_snippet,
            "source": self.source,
        }


@dataclass
class DetectionResult:
    """탐지 단계 최종 결과."""

    source_dir: Path
    findings: list[Finding] = field(default_factory=list)
    slither_used: bool = False
    heuristics_used: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def severity_counts(self) -> dict[str, int]:
        """심각도별 탐지 수 집계."""
        counts = {k: 0 for k in SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    @property
    def max_severity(self) -> str:
        """발견된 최고 심각도 (없으면 CLEAN)."""
        if not self.findings:
            return "CLEAN"
        return max(self.findings, key=lambda f: f.severity_rank).severity

    def pick_reentrancy_finding(self) -> Finding | None:
        """공격 시뮬레이션 대상이 될 가장 심각한 재진입 취약점을 선택한다.

        Returns:
            Finding 또는 None.
        """
        candidates = [f for f in self.findings if f.is_reentrancy]
        if not candidates:
            return None
        return max(candidates, key=lambda f: f.severity_rank)

    def sorted_findings(self) -> list[Finding]:
        """심각도 내림차순 정렬된 목록 반환."""
        return sorted(self.findings, key=lambda f: -f.severity_rank)

    def to_dict(self) -> dict:
        """직렬화용 dict 반환."""
        return {
            "source_dir": str(self.source_dir),
            "slither_used": self.slither_used,
            "heuristics_used": self.heuristics_used,
            "max_severity": self.max_severity,
            "severity_counts": self.severity_counts,
            "notes": self.notes,
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }

    def to_json(self, indent: int = 2) -> str:
        """구조화된 JSON 문자열 반환."""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)


class VulnerabilityDetector:
    """Slither + 휴리스틱 결합 취약점 탐지기."""

    def __init__(self, config: EngineConfig) -> None:
        self.config = config

    # ------------------------------------------------------------------
    # 공개 API
    # ------------------------------------------------------------------
    def detect(
        self,
        source_dir: Path,
        contracts: list[ContractInfo] | None = None,
    ) -> DetectionResult:
        """디렉터리 전체에 대해 취약점 탐지를 수행한다.

        Args:
            source_dir: Solidity 소스 디렉터리.
            contracts: ReconAgent 가 생성한 컨트랙트 정보 (없으면 내부에서 재파싱).

        Returns:
            DetectionResult.
        """
        source_dir = Path(source_dir)
        if contracts is None:
            contracts, _, _ = ReconAgent.parse_directory(source_dir)

        result = DetectionResult(source_dir=source_dir)

        slither_findings, slither_note = self._run_slither(source_dir)
        result.slither_used = slither_findings is not None
        if slither_note:
            result.notes.append(slither_note)
        result.findings.extend(slither_findings or [])

        heur = self._run_heuristics(source_dir, contracts)
        result.heuristics_used = True
        result.findings.extend(heur)

        result.findings = self._dedupe(result.findings)
        result.findings.sort(key=lambda f: -f.severity_rank)
        logger.info(
            "[Detector] Slither=%s, 휴리스틱 포함 총 %d개 탐지 (최고 심각도: %s)",
            "사용" if result.slither_used else "미사용",
            len(result.findings),
            result.max_severity,
        )
        return result

    # ------------------------------------------------------------------
    # Slither 통합
    # ------------------------------------------------------------------
    def _slither_env(self) -> dict:
        """Slither 서브프로세스용 환경변수 — slither/solc 바이너리를 PATH 에 추가."""
        import sysconfig

        env = os.environ.copy()
        path_entries: list[str] = []
        # 1) slither 실행 파일 위치 (pip 설치 시 Scripts 디렉터리가 PATH 에 없을 수 있음)
        slither_path = shutil.which("slither")
        if slither_path:
            path_entries.append(str(Path(slither_path).parent))
        else:
            scripts_dir = sysconfig.get_path("scripts")
            if scripts_dir and (Path(scripts_dir) / "slither.exe").exists():
                path_entries.append(scripts_dir)
        # 2) py-solc-x 가 설치한 solc 바이너리
        try:
            import solcx

            solc_dir = Path(solcx.get_install_dir())
            if solc_dir.is_dir():
                path_entries.append(str(solc_dir))
        except Exception:
            pass
        if path_entries:
            env["PATH"] = os.pathsep.join(path_entries + [env.get("PATH", "")])
        return env

    def _run_slither(self, source_dir: Path) -> tuple[list[Finding] | None, str]:
        """Slither 를 서브프로세스로 실행하고 JSON 결과를 Finding 으로 변환한다.

        Args:
            source_dir: 분석 대상 디렉터리.

        Returns:
            (Finding 리스트 또는 None, 진행 노트)
        """
        slither_bin = shutil.which("slither")
        if slither_bin is None:
            return None, "Slither 미설치 — 휴리스틱 스캐너만 사용합니다."

        cmd = [slither_bin, str(source_dir), "--json", "-"]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.slither_timeout,
                env=self._slither_env(),
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            return None, f"Slither 실행 실패: {exc} — 휴리스틱 스캐너로 대체합니다."

        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError:
            stderr_tail = (proc.stderr or "")[-400:]
            return None, f"Slither JSON 파싱 실패 — 휴리스틱으로 대체. stderr: {stderr_tail}"

        findings: list[Finding] = []
        for det in payload.get("results", {}).get("detectors", []):
            findings.extend(self._slither_finding(det))
        if not findings:
            return findings, "Slither 실행 완료 — 자체 detector 탐지 0건."
        return findings, f"Slither 실행 완료 — {len(findings)}건 탐지."

    def _slither_finding(self, det: dict) -> list[Finding]:
        """Slither detector 항목 1건을 Finding 으로 변환한다.

        Args:
            det: slither JSON 의 results.detectors[*] 원소.

        Returns:
            변환된 Finding 리스트 (element 가 없으면 컨트랙트 미지정 1건).
        """
        check = det.get("check", "unknown")
        meta = _DETECTOR_MAP.get(
            check,
            {
                "severity": str(det.get("impact", "Low")).upper().replace("INFORMATIONAL", "INFO"),
                "title": det.get("check", check),
                "attack_path": "",
                "fix": None,
            },
        )
        if meta["severity"] == "INFORMATIONAL":
            meta["severity"] = "INFO"

        findings: list[Finding] = []
        elements = det.get("elements", []) or []
        described = det.get("description", "")

        func_elems = [e for e in elements if e.get("type") == "function"]
        targets = func_elems or [e for e in elements if e.get("type") == "contract"] or [{}]

        seen: set[tuple] = set()
        for elem in targets:
            # 컨트랙트명: slither 버전에 따라 최상위 "contract" 키가 없고
            # type_specific_fields.parent 에 숨어 있는 경우가 있다.
            # 주의: 함수 element 의 "name" 은 함수명이므로 컨트랙트명 폴백으로 쓰면 안 된다.
            tsf = elem.get("type_specific_fields") or {}
            parent = tsf.get("parent") or {}
            if elem.get("type") == "contract":
                contract = elem.get("name") or "?"
            else:
                contract = parent.get("name") or elem.get("contract") or "?"
            function = elem.get("name") if func_elems else None
            sm = elem.get("source_mapping", {}) or {}
            lines = sm.get("lines") or []
            line = lines[0] if lines else None
            filename = sm.get("filename_absolute") or sm.get("filename_relative")
            key = (check, contract, function, line)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    id=f"SLITHER-{check}",
                    title=meta["title"],
                    severity=meta["severity"],
                    confidence=str(det.get("confidence", "Medium")),
                    contract=contract,
                    function=function,
                    file=filename,
                    line=line,
                    description=described,
                    attack_path=(
                        meta["attack_path"].format(
                            contract=contract, function=function or "?"
                        )
                        if meta["attack_path"]
                        else ""
                    ),
                    fix_snippet=meta.get("fix"),
                    source="slither",
                )
            )
        return findings

    # ------------------------------------------------------------------
    # 휴리스틱 스캐너
    # ------------------------------------------------------------------
    def _run_heuristics(
        self,
        source_dir: Path,
        contracts: list[ContractInfo],
    ) -> list[Finding]:
        """정규식 기반 보조 취약점 탐지를 수행한다.

        Args:
            source_dir: 소스 디렉터리 (파일 단위 검사용).
            contracts: recon 파싱 결과.

        Returns:
            Finding 리스트.
        """
        findings: list[Finding] = []
        sources = self._load_sources(source_dir)
        masked_cache: dict[Path, list[str]] = {
            p: mask_comments(src).splitlines() for p, src in sources.items()
        }

        for c in contracts:
            if c.kind != "contract":
                continue
            path = Path(c.file)
            masked_lines = masked_cache.get(path, [])
            raw = sources.get(path, "")

            for fn in c.functions:
                body = "\n".join(masked_lines[fn.body_start - 1 : fn.body_end])
                findings.extend(
                    self._function_heuristics(c, fn, body, masked_lines, sources)
                )

            # 파일 단위: solc 0.8 미만 오버플로우 가드 부재
            if raw and _ZERO_PRAGMA_RE.search(raw) and "SafeMath" not in raw:
                findings.append(
                    Finding(
                        id="HEUR-OVERFLOW-PRAGMA",
                        title="정수 오버플로우 컴파일러 가드 부재 (solc < 0.8)",
                        severity="LOW",
                        confidence="Medium",
                        contract=c.name,
                        file=str(path),
                        line=c.line,
                        description=(
                            "Solidity 0.8 미만에서는 산술 연산이 자동으로 오버/언더플로우를 "
                            "검사하지 않으며, SafeMath 사용 흔적도 없습니다."
                        ),
                        attack_path="오버/언더플로우를 유발하는 입력으로 잔액/카운터 변수 조작",
                        fix_snippet="pragma solidity ^0.8.0;  // 또는 SafeMath 래퍼 사용",
                        source="heuristic",
                    )
                )

        return findings

    def _function_heuristics(
        self,
        contract: ContractInfo,
        fn: FunctionInfo,
        body: str,
        masked_lines: list[str],
        sources: dict[Path, str],
    ) -> list[Finding]:
        """함수 단위 휴리스틱 검사를 수행한다."""
        findings: list[Finding] = []
        body_lines = body.splitlines()

        # 1) 재진입: 외부 호출 이후 상태 쓰기
        call_idx = [
            i for i, ln in enumerate(body_lines) if _ETH_MOVE_RE.search(ln)
        ]
        write_idx = [
            i for i, ln in enumerate(body_lines) if _STATE_WRITE_RE.search(ln)
        ]
        if call_idx and any(w > call_idx[0] for w in write_idx):
            findings.append(
                Finding(
                    id="HEUR-REENTRANCY",
                    title="재진입(Reentrancy) 의심 — 외부 호출 후 상태 갱신",
                    severity="HIGH",
                    confidence="Medium",
                    contract=contract.name,
                    function=fn.name,
                    file=str(contract.file),
                    line=fn.line,
                    description=(
                        f"{fn.signature} 함수에서 이더 이동 외부 호출(라인 "
                        f"{fn.body_start + call_idx[0]}) 이후 상태 변수 쓰기(라인 "
                        f"{fn.body_start + next(w for w in write_idx if w > call_idx[0])})가 "
                        "발생합니다. Checks-Effects-Interactions 패턴 위반입니다."
                    ),
                    attack_path=(
                        f"공격 컨트랙트가 {contract.name}.{fn.name}() 호출 → "
                        "receive()에서 재호출 반복 → 컨트랙트 잔액 전량 탈취"
                    ),
                    fix_snippet=(
                        "balances[msg.sender] = 0;              // 상태 갱신을 먼저\n"
                        "(bool ok, ) = msg.sender.call{value: amount}(\"\"); // 호출은 나중에\n"
                        "require(ok, \"transfer failed\");"
                    ),
                    source="heuristic",
                )
            )

        # 2) tx.origin 인증
        if _TX_ORIGIN_RE.search(body):
            findings.append(
                Finding(
                    id="HEUR-TX-ORIGIN",
                    title="tx.origin 기반 인증 사용",
                    severity="MEDIUM",
                    confidence="High",
                    contract=contract.name,
                    function=fn.name,
                    file=str(contract.file),
                    line=fn.line,
                    description=(
                        "tx.origin 은 피싱 트랜잭션 체인에서 소유자 서명을 우회할 수 있어 "
                        "인증 용도로 부적합합니다."
                    ),
                    attack_path="피싱 컨트랙트 → 소유자 서명 유도 → tx.origin 검증 통과 → 권한 탈취",
                    fix_snippet='require(msg.sender == owner, "not owner");',
                    source="heuristic",
                )
            )

        # 3) unchecked 산술
        if _UNCHECKED_RE.search(body):
            findings.append(
                Finding(
                    id="HEUR-UNCHECKED-ARITH",
                    title="unchecked 블록 산술 — 오버플로우 가드 회피",
                    severity="LOW",
                    confidence="Medium",
                    contract=contract.name,
                    function=fn.name,
                    file=str(contract.file),
                    line=fn.line,
                    description=(
                        "unchecked 블록 내 산술 연산은 solc 0.8+ 에서도 오버/언더플로우를 "
                        "검사하지 않습니다."
                    ),
                    attack_path="극단값 입력으로 카운터/잔액 변수 오버플로우 유도",
                    fix_snippet="unchecked 블록 제거 또는 입력 상한 검증 추가",
                    source="heuristic",
                )
            )

        # 4) 무권한 임의 주소 이더 인출: 파라미터 주소로 ETH 이동 + 소유자 검증 부재
        has_owner_check = bool(
            re.search(r"msg\.sender\s*==|onlyOwner|_msgSender\(\)\s*==", body)
        )
        protected = any(
            re.search(r"only|Owner|Admin|Auth|guard", m, re.I) for m in fn.modifiers
        )
        addr_params = [
            t for t in fn.params_types if t.startswith("address")
        ]
        if (
            fn.visibility in ("public", "external")
            and addr_params
            and _ETH_MOVE_RE.search(body)
            and not has_owner_check
            and not protected
        ):
            findings.append(
                Finding(
                    id="HEUR-UNRESTRICTED-ETH-DRAIN",
                    title="무권한 임의 주소 이더 인출",
                    severity="HIGH",
                    confidence="Medium",
                    contract=contract.name,
                    function=fn.name,
                    file=str(contract.file),
                    line=fn.line,
                    description=(
                        f"{fn.signature} 함수가 접근 제어 없이 파라미터로 받은 주소에 "
                        "이더를 전송할 수 있습니다."
                    ),
                    attack_path="누구나 임의 recipient 지정 → 컨트랙트 잔액 반복 인출",
                    fix_snippet="function withdrawTo(address to) external onlyOwner { ... }",
                    source="heuristic",
                )
            )

        return findings

    # ------------------------------------------------------------------
    # 공통 유틸
    # ------------------------------------------------------------------
    @staticmethod
    def _load_sources(source_dir: Path) -> dict[Path, str]:
        """디렉터리 내 모든 .sol 소스를 읽는다."""
        sources: dict[Path, str] = {}
        for path in sorted(Path(source_dir).rglob("*.sol")):
            try:
                sources[path.resolve()] = path.read_text(
                    encoding="utf-8", errors="replace"
                )
            except OSError as exc:
                logger.warning("[Detector] 파일 읽기 실패 %s: %s", path, exc)
        return sources

    @staticmethod
    def _dedupe(findings: list[Finding]) -> list[Finding]:
        """중복 탐지(동일 위치/유형)를 제거한다. Slither 결과를 우선 유지."""
        seen: dict[tuple, Finding] = {}
        for f in findings:
            key = (
                f.contract,
                f.function,
                f.line,
                "reentrancy" if f.is_reentrancy else f.id,
            )
            if key not in seen or (
                seen[key].source == "heuristic" and f.source == "slither"
            ):
                seen[key] = f
        return list(seen.values())
