"""Web3 Red Team Simulator 엔진 패키지.

모듈 구성:
    - config: 중앙 설정 관리 및 보안 제약 검증
    - recon_agent: GitHub/로컬 코드베이스 정찰
    - vuln_detector: Slither 정적 분석 + 휴리스틱 취약점 탐지
    - exploit_agent: 로컬 Ganache 모의 공격 시뮬레이션
    - report_generator: HTML 보고서 생성
"""

__version__ = "0.1.0"
