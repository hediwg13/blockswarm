# 🐝 BlockSwarm

해커톤 프로젝트 — **Web3 레드팀 시뮬레이터 엔진**과 그 실시간 관제 데시보드 **NEXUS MISSION CONTROL**을 포함하는 저장소입니다.

> ⚠️ 모든 공격 시뮬레이션은 **로컬 Ganache 개발 네트워크의 가상 자금**으로만 실행됩니다.
> 실제 자산·메인넷·타인의 컨트랙트 대상 사용은 금지되며, 보안 진단/교육 목적으로만 사용하세요.

## 📁 저장소 구조

```
blockswarm/
├── front/                        # NEXUS MISSION CONTROL 데모 대시보드
│   ├── index.html                # 단일 파일 관제 UI
│   ├── nexus-demo.mp4            # 데모 녹화 영상
│   └── record_demo.py            # Playwright 기반 데모 녹화 스크립트
│
└── web3-red-team-simulator/      # 레드팀 시뮬레이터 MVP 엔진
    ├── engine/
    │   ├── config.py             # 설정 관리 + 로컬 전용 보안 게이트
    │   ├── recon_agent.py        # GitHub/로컬 코드베이스 정찰
    │   ├── vuln_detector.py      # Slither + 휴리스틱 취약점 탐지
    │   ├── exploit_agent.py      # 재진입 공격 자동 생성·실행
    │   └── report_generator.py   # HTML 보고서 생성
    ├── contracts/vulnerable_bank.sol
    ├── tests/                    # 22개 테스트 (전부 통과)
    ├── main.py                   # CLI + FastAPI
    └── requirements.txt
```

## 🛡️ Web3 Red Team Simulator

GitHub 저장소 또는 로컬 디렉터리의 스마트컨트랙트를 분석해 취약점을 자동 탐지하고,
**로컬 Ganache에서만** 모의 공격을 시뮬레이션한 뒤 HTML 보고서를 생성합니다.

```
GitHub URL / 로컬 디렉터리
        │
        ▼
  ReconAgent ──▶ VulnerabilityDetector ──▶ ExploitAgent ──▶ ReportGenerator
   (정찰)          (Slither + 휴리스틱)       (모의 공격)        (HTML 보고서)
```

- **탐지**: 재진입(CRITICAL), tx.origin 인증, unchecked 산술 오버플로우, 무권한 이더 인출 등 — Slither 결과와 자체 휴리스틱을 결합해 심각도·공격 경로·수정 제안 스니펫까지 산출
- **공격 실증**: 탐지된 재진입 취약점에 대해 공격 컨트랙트를 **자동 생성**해 Ganache에 배포·실행 — 샘플 컨트랙트에서 **5.0 ETH 탈취 실증 성공**
- **보안 제약**: `assert_local_rpc()` 가 localhost 이외 대상의 공격을 원천 차단

### 빠른 시작

```bash
cd web3-red-team-simulator
pip install -r requirements.txt

# 터미널 1 — 로컬 테스트넷 (공격 시뮬레이션에 필요)
npx ganache --port 8545 --chain.chainId 1337 --wallet.totalAccounts 10

# 터미널 2 — 전체 파이프라인
python main.py --local contracts                # 로컬 디렉터리 분석 + 공격
python main.py --repo https://github.com/o/r    # GitHub 저장소 분석
python main.py --local contracts --no-exploit   # 탐지+보고서만 (Ganache 불필요)
python main.py --serve                          # FastAPI: POST /analyze, GET /report/{id}
```

### 테스트

```bash
python -m pytest tests -v   # 22 passed — Ganache 미구동 시 공격 통합 테스트만 자동 스킵
```

자세한 내용은 [`web3-red-team-simulator/README.md`](web3-red-team-simulator/README.md) 참고.

## 🖥️ NEXUS MISSION CONTROL (front)

단일 HTML 파일로 동작하는 실시간 관제 데시보드입니다. 브라우저에서 `front/index.html`을 열면 바로 실행되며,
`front/nexus-demo.mp4`로 데모 영상을 확인할 수 있습니다.

영상 재녹화가 필요하면:

```bash
pip install playwright imageio-ffmpeg
python front/record_demo.py    # Edge(headless) + Playwright로 25초 녹화 → mp4 변환
```
