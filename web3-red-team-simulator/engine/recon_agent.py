"""
engine/recon_agent.py — 정찰(Recon) 에이전트.

GitHub 저장소 URL(또는 로컬 디렉터리)을 입력받아 다음을 수행한다.
    1. 저장소 메타데이터 수집 (PyGithub)
    2. Solidity 파일 탐지 및 로컬 다운로드
    3. 컨트랙트/함수/외부 호출 패턴 정적 스캔 (MVP: 정규식 기반 파서)

산출물 ReconResult 는 이후 단계(VulnerabilityDetector, ExploitAgent,
ReportGenerator)의 입력으로 사용된다.
"""
from __future__ import annotations

import base64
import logging
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from engine.config import EngineConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Solidity 정적 스캔용 정규식 (주석 제거된 소스 기준)
# ---------------------------------------------------------------------------
_CONTRACT_RE = re.compile(
    r"^\s*(?:abstract\s+)?(contract|interface|library)\s+([A-Za-z_]\w*)"
    r"(?:\s+is\s+([\w\s,.\[\]]+?))?\s*\{",
    re.MULTILINE,
)
_FUNC_RE = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*([^;{]*)")
_RETURNS_RE = re.compile(r"\breturns\s*\(([^)]*)\)")
_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")
_RECEIVE_FALLBACK_RE = re.compile(r"^\s*(receive|fallback)\s*\(", re.MULTILINE)

_EXTERNAL_CALL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("delegatecall", re.compile(r"\.delegatecall\s*[\({]")),
    ("call", re.compile(r"\.call\s*[\({]")),
    ("transfer", re.compile(r"\.transfer\s*\(")),
    ("send", re.compile(r"\.send\s*\(")),
]

_KEYWORDS = {
    "public", "private", "internal", "external", "view", "pure", "payable",
    "returns", "virtual", "override", "constant", "immutable",
}

_GITHUB_URL_RE = re.compile(r"github\.com[/:]([^/]+)/([^/#.?]+)")


class ReconError(RuntimeError):
    """정찰 단계 실패 (저장소 접근 불가, SOL 파일 부재 등)."""


def mask_comments(source: str) -> str:
    """주석을 제거하되 줄 구조(개행 수)를 보존한 소스를 반환한다.

    Args:
        source: 원본 Solidity 소스.

    Returns:
        라인/컬럼 정보가 유지된 주석 제거 소스.
    """
    block = re.compile(r"/\*.*?\*/", re.DOTALL)
    src = block.sub(lambda m: "\n" * m.group(0).count("\n"), source)
    return re.sub(r"//[^\n]*", "", src)


def split_top_level(text: str, sep: str = ",") -> list[str]:
    """괄호 중첩을 고려해 최상위 레벨 기준으로 분리한다.

    Args:
        text: 분리 대상 문자열.
        sep: 구분자.

    Returns:
        분리된(공백 제거) 문자열 리스트.
    """
    parts: list[str] = []
    depth, cur = 0, []
    for ch in text:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == sep and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        parts.append(tail)
    return [p for p in parts if p]


@dataclass
class FunctionInfo:
    """정적 스캔으로 추출한 함수 정보."""

    name: str
    contract: str
    params_raw: str = ""
    params_types: list[str] = field(default_factory=list)
    returns_raw: str = ""
    visibility: str = "public"
    mutability: str = "nonpayable"  # nonpayable | view | pure
    is_payable: bool = False
    modifiers: list[str] = field(default_factory=list)
    line: int = 0
    body_start: int = 0
    body_end: int = 0

    @property
    def signature(self) -> str:
        """`name(type1,type2)` 형태의 시그니처 문자열."""
        return f"{self.name}({','.join(self.params_types)})"

    def to_dict(self) -> dict:
        """직렬화용 dict 반환."""
        return {
            "name": self.name,
            "signature": self.signature,
            "visibility": self.visibility,
            "mutability": self.mutability,
            "payable": self.is_payable,
            "modifiers": self.modifiers,
            "line": self.line,
        }


@dataclass
class ExternalCallInfo:
    """외부 컨트랙트 호출 패턴 정보."""

    kind: str          # call | delegatecall | transfer | send
    contract: str
    function: str | None
    line: int
    snippet: str

    def to_dict(self) -> dict:
        """직렬화용 dict 반환."""
        return {
            "kind": self.kind,
            "contract": self.contract,
            "function": self.function,
            "line": self.line,
            "snippet": self.snippet.strip()[:160],
        }


@dataclass
class ContractInfo:
    """단일 Solidity 컨트랙트 정보."""

    name: str
    kind: str  # contract | interface | library
    file: Path
    line: int
    base_contracts: list[str] = field(default_factory=list)
    functions: list[FunctionInfo] = field(default_factory=list)
    has_receive: bool = False
    has_fallback: bool = False

    def find_function(self, name: str) -> FunctionInfo | None:
        """이름으로 함수 정보를 조회한다.

        Args:
            name: 함수명.

        Returns:
            FunctionInfo 또는 None.
        """
        for fn in self.functions:
            if fn.name == name:
                return fn
        return None

    def to_dict(self) -> dict:
        """직렬화용 dict 반환."""
        return {
            "name": self.name,
            "kind": self.kind,
            "file": str(self.file),
            "line": self.line,
            "base_contracts": self.base_contracts,
            "has_receive": self.has_receive,
            "has_fallback": self.has_fallback,
            "functions": [fn.to_dict() for fn in self.functions],
        }


@dataclass
class ReconResult:
    """정찰 단계 최종 결과."""

    source_label: str                       # 저장소 URL 또는 로컬 경로
    source_dir: Path                        # .sol 파일이 위치한 로컬 디렉터리
    repo_metadata: dict = field(default_factory=dict)
    sol_files: list[Path] = field(default_factory=list)
    contracts: list[ContractInfo] = field(default_factory=list)
    external_calls: list[ExternalCallInfo] = field(default_factory=list)
    pragma_versions: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def external_call_summary(self) -> dict[str, int]:
        """외부 호출 종류별 집계."""
        summary: dict[str, int] = {}
        for ec in self.external_calls:
            summary[ec.kind] = summary.get(ec.kind, 0) + 1
        return summary

    def to_dict(self) -> dict:
        """직렬화용 dict 반환."""
        return {
            "source": self.source_label,
            "metadata": self.repo_metadata,
            "sol_files": [str(p) for p in self.sol_files],
            "pragmas": self.pragma_versions,
            "contracts": [c.to_dict() for c in self.contracts],
            "external_calls": [ec.to_dict() for ec in self.external_calls],
            "external_call_summary": self.external_call_summary,
            "notes": self.notes,
        }


def param_type(param: str) -> str:
    """파라미터 선언에서 타입 부분만 추출한다.

    Args:
        param: `uint256 amount` 같은 파라미터 선언 문자열.

    Returns:
        타입 문자열 (예: `uint256`, `address payable`).
    """
    toks = [t for t in param.strip().split() if t]
    if not toks:
        return ""
    # storage 위치 키워드 제거
    toks = [t for t in toks if t not in ("memory", "calldata", "storage", "indexed")]
    if toks[0] == "address" and "payable" in toks:
        base = "address payable"
        rest = [t for t in toks[1:] if t != "payable"]
    else:
        base = toks[0]
        rest = toks[1:]
    if len(rest) >= 1:  # 마지막 토큰은 파라미터명으로 간주
        return base
    return base


class ReconAgent:
    """GitHub 저장소 / 로컬 디렉터리 정찰 에이전트."""

    def __init__(self, config: EngineConfig) -> None:
        self.config = config

    # ------------------------------------------------------------------
    # 공개 API
    # ------------------------------------------------------------------
    def analyze(
        self,
        repo_url: str | None = None,
        local_dir: str | Path | None = None,
    ) -> ReconResult:
        """저장소 또는 로컬 디렉터리를 정찰한다.

        Args:
            repo_url: GitHub 저장소 URL (local_dir 와 함께 사용 불가).
            local_dir: 로컬 Solidity 디렉터리.

        Returns:
            ReconResult.

        Raises:
            ReconError: 입력이 없거나 .sol 파일을 찾지 못한 경우.
        """
        if bool(repo_url) == bool(local_dir):
            raise ReconError("repo_url 또는 local_dir 중 정확히 하나를 지정해야 합니다.")
        self.config.ensure_dirs()

        if repo_url:
            metadata, source_dir = self._fetch_github_repo(repo_url)
            label = repo_url
        else:
            source_dir = Path(local_dir).resolve()  # type: ignore[arg-type]
            if not source_dir.is_dir():
                raise ReconError(f"로컬 디렉터리가 없습니다: {source_dir}")
            metadata = {"source_type": "local", "path": str(source_dir)}
            label = str(source_dir)

        sol_files = sorted(p for p in source_dir.rglob("*.sol") if p.is_file())
        if not sol_files:
            raise ReconError(f"Solidity 파일(.sol)을 찾지 못했습니다: {source_dir}")

        contracts, ext_calls, pragmas = self.parse_directory(source_dir)
        result = ReconResult(
            source_label=label,
            source_dir=source_dir,
            repo_metadata=metadata,
            sol_files=sol_files,
            contracts=contracts,
            external_calls=ext_calls,
            pragma_versions=pragmas,
        )
        logger.info(
            "[Recon] %s — 컨트랙트 %d개, 함수 %d개, 외부호출 %d회",
            label, len(contracts),
            sum(len(c.functions) for c in contracts), len(ext_calls),
        )
        return result

    # ------------------------------------------------------------------
    # GitHub 연동
    # ------------------------------------------------------------------
    def _fetch_github_repo(self, repo_url: str) -> tuple[dict, Path]:
        """PyGithub 로 저장소 메타데이터와 .sol 파일을 가져온다.

        Args:
            repo_url: GitHub 저장소 URL.

        Returns:
            (메타데이터 dict, 다운로드된 로컬 디렉터리)

        Raises:
            ReconError: URL 파싱 실패, 저장소 조회 실패 등.
        """
        try:
            from github import Github, Auth  # 지연 임포트 (오프라인 테스트 보호)
        except ImportError as exc:  # pragma: no cover
            raise ReconError("PyGithub 가 설치되어 있지 않습니다: pip install PyGithub") from exc

        match = _GITHUB_URL_RE.search(repo_url)
        if not match:
            raise ReconError(f"GitHub URL 파싱 실패: {repo_url}")
        owner, name = match.group(1), match.group(2)

        gh = (
            Github(auth=Auth.Token(self.config.github_token))
            if self.config.github_token
            else Github()
        )
        try:
            repo = gh.get_repo(f"{owner}/{name}")
            tree = repo.get_git_tree(repo.default_branch, recursive=True)
        except Exception as exc:
            raise ReconError(f"GitHub 저장소 조회 실패 ({owner}/{name}): {exc}") from exc

        blobs = [
            e for e in tree.tree
            if getattr(e, "type", "") == "blob" and e.path.endswith(".sol")
        ]
        metadata = {
            "source_type": "github",
            "full_name": repo.full_name,
            "html_url": repo.html_url,
            "description": repo.description or "",
            "default_branch": repo.default_branch,
            "stars": repo.stargazers_count,
            "language": repo.language,
            "pushed_at": str(repo.pushed_at) if repo.pushed_at else None,
        }

        target_dir = self.config.workdir / f"{owner}_{name}"
        if target_dir.exists():
            shutil.rmtree(target_dir)
        target_dir.mkdir(parents=True)

        fetched = 0
        for blob in blobs[: self.config.max_repo_sol_files]:
            try:
                content = repo.get_git_blob(blob.sha).content
                source = base64.b64decode(content).decode("utf-8", errors="replace")
                dest = target_dir / blob.path
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(source, encoding="utf-8")
                fetched += 1
            except Exception as exc:  # 개별 파일 실패는 전체를 중단시키지 않는다
                logger.warning("[Recon] blob 다운로드 실패 %s: %s", blob.path, exc)
        if fetched < len(blobs):
            note = f"{len(blobs)}개 중 {fetched}개 .sol 파일만 가져왔습니다 (상한/오류)."
            logger.warning("[Recon] %s", note)
            metadata["note"] = note
        return metadata, target_dir

    # ------------------------------------------------------------------
    # Solidity 정적 스캔 (정규식 기반 MVP 파서)
    # ------------------------------------------------------------------
    @staticmethod
    def parse_directory(
        source_dir: Path,
    ) -> tuple[list[ContractInfo], list[ExternalCallInfo], list[str]]:
        """디렉터리의 모든 .sol 파일을 정적 스캔한다.

        Args:
            source_dir: Solidity 소스 디렉터리.

        Returns:
            (컨트랙트 목록, 외부 호출 목록, pragma 버전 목록)
        """
        contracts: list[ContractInfo] = []
        ext_calls: list[ExternalCallInfo] = []
        pragmas: list[str] = []

        for path in sorted(source_dir.rglob("*.sol")):
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                logger.warning("[Recon] 파일 읽기 실패 %s: %s", path, exc)
                continue
            masked = mask_comments(source)
            lines = source.splitlines()

            m = _PRAGMA_RE.search(masked)
            if m and m.group(1).strip() not in pragmas:
                pragmas.append(m.group(1).strip())

            contracts.extend(_parse_contracts(path, masked))
            ext_calls.extend(_parse_external_calls(path, masked, lines, contracts))

        return contracts, ext_calls, pragmas


def _parse_contracts(path: Path, masked: str) -> list[ContractInfo]:
    """단일 파일에서 컨트랙트/함수 선언을 추출한다."""
    contracts: list[ContractInfo] = []
    masked_lines = masked.splitlines()

    for cm in _CONTRACT_RE.finditer(masked):
        kind, name, bases = cm.group(1), cm.group(2), cm.group(3) or ""
        start_line = masked[: cm.start()].count("\n") + 1
        info = ContractInfo(
            name=name,
            kind=kind,
            file=path,
            line=start_line,
            base_contracts=[b.strip() for b in bases.split(",") if b.strip()],
        )

        region = _contract_region(masked_lines, start_line)
        region_text = "\n".join(masked_lines[region[0] - 1 : region[1]])
        info.has_receive = bool(re.search(r"^\s*receive\s*\(", region_text, re.M))
        info.has_fallback = bool(re.search(r"^\s*fallback\s*\(", region_text, re.M))

        for fm in _FUNC_RE.finditer(region_text):
            fn = _parse_function(name, masked_lines, region[0], fm)
            if fn is not None:
                info.functions.append(fn)

        contracts.append(info)
    return contracts


def _contract_region(lines: list[str], start_line: int) -> tuple[int, int]:
    """컨트랙트 선언줄부터 대응하는 닫는 중괄호까지의 줄 범위를 반환한다."""
    depth = 0
    opened = False
    for idx in range(start_line - 1, len(lines)):
        for ch in lines[idx]:
            if ch == "{":
                depth += 1
                opened = True
            elif ch == "}":
                depth -= 1
        if opened and depth <= 0:
            return (start_line, idx + 1)
    return (start_line, len(lines))


def _parse_function(
    contract_name: str,
    masked_lines: list[str],
    region_offset: int,
    match: re.Match,
) -> FunctionInfo | None:
    """함수 선언 매치를 FunctionInfo 로 변환한다."""
    name, params_raw, tail = match.group(1), match.group(2), match.group(3) or ""
    # 'returns (...) ' 이후 부분은 한정자가 아니므로 분리
    tail_main = tail.split("returns")[0]

    vis_m = re.search(r"\b(external|public|internal|private)\b", tail_main)
    visibility = vis_m.group(1) if vis_m else "public"
    mut_m = re.search(r"\b(view|pure)\b", tail_main)
    mutability = mut_m.group(1) if mut_m else "nonpayable"
    payable = bool(re.search(r"\bpayable\b", tail_main))
    modifiers = [
        tok
        for tok in re.findall(r"\b([A-Za-z_]\w*)", tail_main)
        if tok not in _KEYWORDS
    ]

    abs_line = _absolute_line(masked_lines, region_offset, match)

    body_start, body_end = _function_body_span(masked_lines, abs_line)
    return FunctionInfo(
        name=name,
        contract=contract_name,
        params_raw=params_raw.strip(),
        params_types=[param_type(p) for p in split_top_level(params_raw)],
        returns_raw=(_RETURNS_RE.search(tail).group(1).strip() if _RETURNS_RE.search(tail) else ""),
        visibility=visibility,
        mutability=mutability,
        is_payable=payable,
        modifiers=modifiers,
        line=abs_line,
        body_start=body_start,
        body_end=body_end,
    )


def _absolute_line(masked_lines: list[str], region_offset: int, match: re.Match) -> int:
    """영역 기준 매치 위치를 파일 절대 라인 번호로 변환한다."""
    region_text = "\n".join(masked_lines[region_offset - 1 :])
    prefix = region_text[: match.start()]
    return region_offset + prefix.count("\n")


def _function_body_span(masked_lines: list[str], decl_line: int) -> tuple[int, int]:
    """함수 선언줄 이후 중괄호 균형으로 본문 범위를 계산한다."""
    depth, opened = 0, False
    for idx in range(decl_line - 1, len(masked_lines)):
        for ch in masked_lines[idx]:
            if ch == "{":
                depth += 1
                opened = True
            elif ch == "}":
                depth -= 1
        if opened and depth <= 0:
            return (decl_line, idx + 1)
        if not opened and ";" in masked_lines[idx] and idx > decl_line - 1:
            return (decl_line, idx + 1)  # 선언만 있는 경우 (interface 등)
    return (decl_line, len(masked_lines))


def _parse_external_calls(
    path: Path,
    masked: str,
    raw_lines: list[str],
    contracts: list[ContractInfo],
) -> list[ExternalCallInfo]:
    """파일 내 외부 호출 패턴(.call/.transfer/.send/.delegatecall)을 추출한다."""
    calls: list[ExternalCallInfo] = []
    masked_lines = masked.splitlines()

    for kind, pattern in _EXTERNAL_CALL_PATTERNS:
        for mm in pattern.finditer(masked):
            line_no = masked[: mm.start()].count("\n") + 1
            contract, func = _locate(masked_lines, line_no, contracts)
            snippet = raw_lines[line_no - 1] if line_no <= len(raw_lines) else ""
            calls.append(
                ExternalCallInfo(
                    kind=kind,
                    contract=contract,
                    function=func,
                    line=line_no,
                    snippet=snippet,
                )
            )
    return calls


def _locate(
    masked_lines: list[str],
    line_no: int,
    contracts: list[ContractInfo],
) -> tuple[str, str | None]:
    """라인이 속한 컨트랙트/함수 이름을 반환한다."""
    contract_name, func_name = "?", None
    for c in contracts:
        region = _contract_region(masked_lines, c.line)
        if region[0] <= line_no <= region[1]:
            contract_name = c.name
            for fn in c.functions:
                if fn.body_start <= line_no <= fn.body_end:
                    func_name = fn.name
                    break
            break
    return contract_name, func_name
