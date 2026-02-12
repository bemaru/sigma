# Sigma — Overview

## 프로젝트 철학

Sigma는 **보안 탐지 지식의 표준화와 민주화**를 목표로 하는 프로젝트다. "파일 검사의 YARA, 네트워크 트래픽의 Snort"처럼, **로그 이벤트 분석을 위한 공개 표준 서명 포맷**을 제공한다.

**3대 핵심 철학:**

| 철학 | 의미 |
|------|------|
| 벤더 중립성 | 한 번 작성한 룰이 모든 SIEM에서 동작 |
| 지식 공유 | 커뮤니티가 만든 4,000+ 룰을 무료로 모든 조직에 제공 |
| 피어 리뷰 | 전문 Detection Engineer 커뮤니티의 검증을 거친 룰만 포함 |

**커뮤니티 거버넌스:**
- 명확한 유지보수자 구조 (Florian Roth 창시자, Nasreddine Bencherchali 일일 관리 등)
- PR 기반 기여 → 자동 검증 → 커뮤니티 리뷰 → 병합
- 룰 성숙도 체계로 품질과 시의성의 균형

## 해결하는 문제

각 SIEM(Splunk SPL, QRadar AQL, ELK KQL 등)이 고유한 쿼리 언어를 사용하기 때문에, 보안 분석가가 개발한 탐지 로직은 특정 SIEM에만 적용 가능했다.

**Sigma의 해결 메커니즘:**

```
Sigma 룰 (YAML) → Sigma Converter → Target SIEM Query (SPL, KQL, AQL, ...)
```

**기존 대안 대비 차별점:**

| 관점 | YARA | Snort/Suricata | 벤더별 쿼리 | Sigma |
|------|------|----------------|------------|-------|
| 대상 | 파일 시그니처 | 네트워크 패킷 | 로그 이벤트 | 로그 이벤트 |
| 벤더 중립 | Yes | Yes | No | Yes |
| 작성 난이도 | 중간 | 높음 | SIEM별 다름 | 낮음 (YAML) |
| 공유 생태계 | 파일 중심 | 네트워크 중심 | 벤더 종속 | 40+ SIEM 지원 |
| 메타데이터 | 제한적 | 제한적 | 없음 | ATT&CK, 오탐, 참조 |

## 기술 스택과 선택 이유

### YAML 포맷 선택

| 선택 이유 | 트레이드오프 |
|-----------|------------|
| 사람이 읽고 쓰기 쉬움 — 보안 분석가도 쿼리 언어 학습 없이 작성 | 형식 검증에 별도 도구(yamllint) 필요 |
| 주석과 들여쓰기로 구조 표현 | JSON 대비 파싱 비용 약간 높음 |
| 텍스트 기반으로 git 버전 관리에 적합 | 복잡한 로직 표현 시 중첩이 깊어질 수 있음 |
| 도구 에코시스템 풍부 (pySigma, sigma-cli 등) | — |

### 핵심 도구 체인

| 도구 | 역할 |
|------|------|
| **pySigma** | 룰 파싱/변환 Python 엔진 |
| **sigma-cli** | 명령행 변환 도구 |
| **pySigma-validators-sigmahq** | SigmaHQ 전용 검증 플러그인 |
| **yamllint** | YAML 문법 검증 (strict mode) |
| **Atomic Red Team** | 공격 시뮬레이션 기반 룰 검증 |

### 룰 스키마 구조

```yaml
# 메타데이터
title: [규칙 제목]
id: [UUID 고유 식별자]
status: [experimental|test|stable]
description: [상세 설명]
references: [참고 링크]
author: [작성자]
date: [생성일]
modified: [수정일]
tags: [ATT&CK 프레임워크 태그]

# 로그 소스 추상화
logsource:
    product: [windows|linux|macos|azure|aws|...]
    category: [process_creation|network_connection|...]
    service: [sysmon|security|...]

# 탐지 로직
detection:
    selection_*: [탐지 조건]
    filter_*: [오탐 제거 조건]
    condition: [논리 결합식]

# 운영 정보
falsepositives: [알려진 오탐 패턴]
level: [critical|high|medium|low|informational]
```

---

## 배울 점

1. **"로그의 Snort"라는 명확한 포지셔닝**: 기존 표준(YARA=파일, Snort=네트워크)의 빈 자리(로그=없음)를 정확히 식별하고 채움. 명확한 비유로 프로젝트의 가치를 즉시 이해 가능하게 함
2. **벤더 중립 포맷의 파급 효과**: 표준 포맷을 확립하면 생태계(40+ SIEM 통합, 상용 변환 플랫폼)가 자연스럽게 형성됨. 포맷 자체가 플랫폼이 됨
3. **거짓양성(falsepositives) 명시의 투명성**: 모든 룰에 알려진 오탐 패턴을 명시하여 운영팀의 기대를 설정하고 튜닝 지점을 제시
4. **MITRE ATT&CK 매핑의 필수화**: 모든 룰에 공격 기법을 태깅하여 "어떤 공격에 대한 방어 커버리지가 있는가?"를 정량적으로 평가 가능

## 적용 아이디어

| Sigma 패턴 | EDR AI 적용 |
|------------|-------------|
| YAML 기반 표준 포맷 | AI 분석 룰/프롬프트를 YAML 표준 포맷으로 정의하여 AI 모델 교체 시에도 분석 로직 재사용 |
| Logsource 추상화 | EDR 이벤트 소스(프로세스, 파일, 레지스트리, 네트워크)를 정규화된 필드명으로 추상화하여 에이전트 종속성 제거 |
| Selection/Filter/Condition 3계층 | AI 위협 분석에서도 "탐지 신호", "정상 패턴 제외", "최종 판단 조건"을 명확히 분리 |
| 성숙도 체계 | AI 분석 룰도 experimental→test→stable 승격 프로세스로 신뢰도 관리 |
| ATT&CK 태깅 | AI 분석 결과에 ATT&CK 기법을 자동 매핑하여 위협 컨텍스트 제공 |
| 회귀 테스트 데이터 | AI 탐지 룰을 실제 보안 이벤트 데이터로 자동 검증하는 CI/CD 파이프라인 |
