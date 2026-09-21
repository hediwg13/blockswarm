# 🛡️ Web3 Red Team Simulator (MVP)

GitHub 저장소 또는 로컬 디렉터리의 스마트컨트랙트를 분석해 취약점을 자동 탐지하고,
**로컬 Ganache 네트워크에서만** 모의 공격을 시뮬레이션한 뒤 HTML 보고서를 생성하는 레드팀 도구입니다.

> ⚠️ **면책**: 모든 공격은 로컬 Ganache 의 가상 자금으로만 실행됩니다.
> 실제 자산·메인넷·타인의 컨트랙트 대상 사용은 금지되며, 보안 진단/교육 목적으로만 사용하세요.

## 아키텍처

```
GitHub URL / 로컬 디렉터리
        │
        ▼
┌────────────┐   ┌────────────────┐   ┌──────────────┐   ┌────────────────┐
│ ReconAgent │──▶│ Vulnerability  │──▶│ ExploitAgent │──▶│ ReportGenerator│
│  (정찰)     │   │ Detector (탐지) │   │ (모의 공격)   │   │  (HTML 보고서)  │
└────────────┘   └────────────────┘   └──────────────┘   └────────────────┘
  ReconResult      DetectionResult      AttackResult       reports/*.html
```

- **ReconAgent**: PyGithub 로 메타데이터/`.sol` 수집, 정규식 파서로 컨트랙트·함수(시그니처/payable/modifier)·외부 호출 패턴 추출
- **VulnerabilityDetector**: Slither(서브프로세스 JSON) + 자체 휴리스틱(재진입·tx.origin·unchecked 산술·무권한 이더 인출·오버플로우 가드 부재) 이중 탐지, 심각도/공격 경로/수정 스니펫 부착
- **ExploitAgent**: 재진입 공격 컨트랙트 **자동 생성** → py-solc-x 컴파일 → Ganache 배포/펌딩/공격 실행 → 탈취 금액·가스·tx 해시 기록
- **ReportGenerator**: 외부 리소스 없는 자기완결 HTML (KPI·취약점 상세·공격 경로·수정 제안·실행 기록)

모든 공격 실행 전 `assert_local_rpc()` 가 localhost 이외 대상을 차단합니다.

## 빠른 시작

```bash
pip install -r requirements.txt

# 터미널 1 — 로컬 테스트넷 구동 (공격 시뮬레이션에 필요)
npx ganache --port 8545 --chain.chainId 1337 --wallet.totalAccounts 10

# 터미널 2 — 전체 파이프라인 (정찰 → 탐지 → 공격 → 보고서)
python main.py --local contracts
python main.py --repo https://github.com/<owner>/<repo>

# 옵션
python main.py --local contracts --no-exploit   # 탐지+보고서만 (Ganache 불필요)
python main.py --local contracts --json         # 결과를 JSON 으로 출력
python main.py --serve --port 8000              # FastAPI: POST /analyze, GET /report/{id}
```

- solc 는 최초 실행 시 py-solc-x 가 자동 설치합니다 (기본 0.8.19, `SOLC_VERSION` 으로 변경).
- Slither 가 설치되어 있으면 자동 활용, 없으면 휴리스틱만으로 동작합니다.
- GitHub 비인증 요청은 레이트리밋이 낮으므로 `GITHUB_TOKEN` 설정을 권장합니다.

## 테스트

```bash
python -m pytest tests -v
# Ganache 미구동 시 공격 통합 테스트는 자동 스킵, 나머지는 오프라인 통과
```

## 알려진 MVP 제약

- 공격 유형은 재진입(reentrancy)만 지원하며, 0-파라미터 취약 함수(`withdraw()` 형) 대상
- 익스플로잇 템플릿은 최대 재진입 횟수(`max_reentries`, 기본 10)로 무한 루프 방지
- Solidity 파서는 정규식 기반 — 매우 복잡한 문법(mapping 중첩 파라미터 등)은 Slither 결과로 보완
- web3.py v6 핀이 기준이나, Python 3.13+ 환경에서는 v7 로 폴백되며 양쪽 API 호환
