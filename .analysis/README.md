# Sigma 분석

## 메타 정보

| 항목 | 내용 |
|------|------|
| 저장소 | [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) |
| 주요 언어 | YAML (탐지 룰 정의) |
| 라이선스 | DRL 1.1 (Detection Rule License) — 탐지 룰 공유/사용 허용, Sigma 사양은 Public Domain |
| Stars | 8K+ |
| 분석일 | 2026-02-12 |
| 성격 | SIEM 벤더 중립적 탐지 룰 표준 포맷 + 커뮤니티 룰 저장소 (4,000+ 룰) |

## 핵심 인사이트

1. **SIEM 벤더 종속성 해결** — YAML 기반 표준 포맷으로 한 번 작성한 룰이 Splunk, ELK, QRadar 등 40+ SIEM으로 자동 변환. "로그 파일의 Snort"라는 포지셔닝
2. **3계층 탐지 구조 (Selection/Filter/Condition)** — 탐지 신호(selection), 오탐 제거(filter), 논리 결합(condition)을 명확히 분리하여 룰의 의도와 한계를 명시적으로 표현
3. **필드 연산자 체이닝** — `|contains|all|windash` 같은 조합 가능한 연산자로 복잡한 탐지 로직을 선언적으로 표현. SQL이나 정규식 없이도 높은 표현력 달성
4. **4단계 성숙도 + 5단계 심각도 체계** — experimental→test→stable 승격과 informational~critical 심각도로 룰의 신뢰도와 긴급성을 체계적으로 관리
5. **회귀 테스트 데이터로 실증 검증** — 실제 공격 이벤트 로그(EVTX)로 룰이 의도대로 동작하는지 자동 검증. Atomic Red Team과의 통합으로 시뮬레이션 기반 테스트

## 문서 구성

| 문서 | 내용 |
|------|------|
| [overview.md](./overview.md) | 프로젝트 철학, 차별점, 기술 스택 선택 이유 |
| [core-logic.md](./core-logic.md) | 룰 포맷 구조, 탐지 로직 패턴, 조건 문법 상세 |
| [architecture.md](./architecture.md) | 룰 분류 체계, 품질 관리 시스템, 커뮤니티 거버넌스 |
