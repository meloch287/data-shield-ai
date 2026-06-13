<div align="center">

# 🛡️ Data Shield AI

本地 PII/密钥脱敏层。在文本离开本机之前屏蔽敏感数据。

[![CI](https://github.com/meloch287/data-shield-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/meloch287/data-shield-ai/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-1956%20passing-success.svg)](#测试)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](#footprint)
[![Detectors](https://img.shields.io/badge/detectors-90-orange.svg)](#检测器目录)

<a href="README.md">🇬🇧 English</a> &nbsp;·&nbsp;
<a href="README.ru.md">🇷🇺 Русский</a> &nbsp;·&nbsp;
<a href="README.zh-CN.md"><b>🇨🇳 中文</b></a>

</div>

```text
输入   →   Иван Петров, INN 7707083893, 卡号 4111 1111 1111 1111, 密钥 AKIAIOSFODNN7EXAMPLE
输出   →   [PERSON_1], INN [INN_1], 卡号 [CREDIT_CARD_1], 密钥 [AWS_ACCESS_KEY_1]
```

纯 Python 标准库，零依赖，不联网。90 个检测器，83 种数据类型。同一值 → 同一占位符；原始值不写入磁盘。

- [流程](#流程)
- [架构](#架构)
- [检测器目录](#检测器目录)
- [置信度模型](#置信度模型)
- [重叠消解](#重叠消解)
- [校验算法](#校验算法)
- [策略与可逆性](#策略与可逆性)
- [预设与结构化输入](#预设与结构化输入)
- [指标](#指标)
- [隐私模型](#隐私模型)
- [安装 / 使用 / API](#安装)
- [集成](#集成)
- [测试](#测试)

## 流程

```mermaid
flowchart LR
  subgraph DET["90 detectors run independently"]
    direction TB
    RX["regex + checksum validators"]
    KW["keyword-context base/boost"]
    NM["names gazetteer + heuristics"]
  end
  IN["input text"] --> DET
  DET -->|findings| FIL
  FIL["filter: confidence ≥ min,<br/>allowlist, only/exclude"] --> RES
  RES["resolve overlaps<br/>bytearray occupancy, O of n"] --> ALLOC
  ALLOC["allocate placeholders<br/>value to TYPE_n"] --> OUT["masked text + stats + report"]
```

每个检测器产出 `Finding(type, start, end, value, confidence, detector)`。引擎从不查看检测器内部——它只看到 `Finding`，因此新增检测器（包括 ML 插件）无需改动引擎。

## 架构

```mermaid
flowchart TD
  cli["cli.py<br/>redact · scan · stats · detectors"] --> api["api.py<br/>build_engine / redact / scan"]
  cfg["config.py<br/>.datashield.json"] --> api
  api --> reg["detectors/registry.py<br/>enable/disable, custom patterns"]
  api --> eng["engine.py<br/>RedactionEngine"]
  reg --> det["detectors/*"]
  det --> base["detectors/base.py<br/>RegexDetector · KeywordContextDetector"]
  det --> val["validators.py<br/>Luhn · INN · SNILS · IBAN · OGRN"]
  det --> data["data/names.py<br/>RU/EN gazetteer"]
  eng --> mask["masking.py<br/>PlaceholderAllocator"]
```

| 模块 | 职责 | LOC* |
|------|------|-----:|
| `engine.py` | 编排、重叠消解、报告 | ~140 |
| `detectors/base.py` | `Finding`、正则与上下文检测器 | ~140 |
| `detectors/{regex_intl,ru,extra,intl_ids,network,secrets,addresses,names}.py` | 90 个检测器 | ~900 |
| `detectors/{ml,gliner}_plugin.py` | 可选的惰性 ML 适配器 | ~200 |
| `validators.py` · `validators_intl.py` | Luhn / INN / IBAN / Verhoeff / mod-11/97 | ~280 |
| `strategies.py` · `formats.py` · `masking.py` | 策略、假名、占位符 | ~250 |
| `compliance.py` · `taxonomy.py` · `presets.py` | 严重度、法规、预设 | ~180 |
| `structured.py` · `normalize.py` · `streaming.py` · `batch.py` | 结构化/规范化/扩展 | ~280 |
| `integrations/*` | MCP、HTTP、日志过滤器 | ~250 |
| `config.py` · `api.py` · `cli.py` | 配置、公共 API、CLI | ~600 |

<sub>* 核心合计：<b>3400+</b> 行、37 个文件；测试：<b>17000+</b> 行、65 个文件。</sub>

## 检测器目录

90 个检测器 → 83 种占位符类型。`conf` = 置信度；`a→b` = 当上下文（25 字符窗口）中出现关键词时由基线提升。低于默认阈值 `0.70` 的命中会被丢弃，因此上下文相关的 ID 不会在裸数字上触发。

**国际**

| 检测器 | 类型 | conf | 校验 |
|--------|------|:----:|------|
| `email` | EMAIL | 0.98 | — |
| `phone_intl` | PHONE | 0.80 | 需前导 `+` |
| `credit_card` | CREDIT_CARD | 0.90 | Luhn + 拒绝前导 0/全同 |
| `iban` | IBAN | 0.95 | mod-97 |
| `ipv4` / `ipv6` | IP | 0.85 / 0.80 | 八位组范围 / `::` 形式 |
| `mac` / `mac_cisco` | MAC | 0.85 | — |

**俄罗斯**

| 检测器 | 类型 | conf | 校验 |
|--------|------|:----:|------|
| `inn` | INN | var→0.95 | 校验位（10/12） |
| `snils` | SNILS | 0.80→0.95 | 校验和 |
| `passport_ru` | PASSPORT_RU | 0.40→0.90 | 上下文 |
| `phone_ru` | PHONE_RU | 0.85 | — |
| `ogrn` / `ogrnip` | OGRN/OGRNIP | 0.85 | 校验位 |
| `kpp` `bic` `bank_account` `oms_policy` `driver_license_ru` | … | 0.40–0.55→0.90+ | 上下文 |
| `address_ru` | ADDRESS | 0.78 | 街道关键词 + 首字母大写名称 |
| `postal_code_ru` | POSTAL_CODE | 0.30→0.85 | 上下文（`индекс`） |

**身份 / 加密**

| 检测器 | 类型 | conf | 校验 |
|--------|------|:----:|------|
| `us_ssn` `uk_nino` | US_SSN / UK_NINO | 0.50→0.92 | 上下文相关 |
| `us_ein` | US_EIN | 0.40→0.90 | 上下文 |
| `eth_address` | ETH_ADDRESS | 0.95 | `0x` + 40 hex |
| `btc_address` | BTC_ADDRESS | 0.78 | base58 / bech32 |
| `names` | PERSON | 启发式 | 父称 · 上下文 · 词典配对 |

**国际 ID**（除注明外均经校验和验证）

| 检测器 | 类型 | conf | 校验 |
|--------|------|:----:|------|
| `aadhaar`（印度） | AADHAAR | 0.90 | Verhoeff |
| `pan_in`（印度） | PAN_IN | 0.85 | 形态 `AAAAA9999A` |
| `china_id` | CHINA_ID | 0.88 | mod-11 |
| `codice_fiscale`（IT） | CODICE_FISCALE | 0.90 | 校验字符 |
| `fr_nir`（法国） | FR_NIR | 0.88 | mod-97 |
| `dni_es` / `nie_es`（ES） | DNI_ES / NIE_ES | 0.80 | 校验字母 |
| `nhs_uk` | NHS_UK | 0.50→0.92 | mod-11，上下文 |
| `pesel_pl` `de_taxid` `aba_us` `us_passport` `us_itin` `uk_sort_code` `china_mobile` | … | 0.40–0.50→0.90+ | 上下文相关 |

**网络 / 基础设施**

`url_credentials`（屏蔽 `scheme://…@` 中的 `user:pass`）· `aws_arn` · `geo_coord`（上下文相关）。

**密钥**（0.85–0.99，具备可辨识前缀）

`aws_access_key` `aws_secret` `anthropic_key` `openai_key` `github_token` `github_pat` `gitlab_token` `huggingface_token` `npm_token` `google_oauth_secret` `digitalocean_token` `shopify_token` `square_token` `google_api_key` `slack_token` `stripe_key` `sendgrid_key` `twilio_sid` `mailgun_key` `telegram_bot` `discord_token` `ssh_pubkey` `jwt` `private_key` `password` `secret_assignment`

**可选**（默认关闭）：`high_entropy`（0.75）、`names_aggressive`（单个名字）、`ml`（Presidio）、`gliner`（ONNX NER）。

## 置信度模型

每个命中带有 `[0,1]` 的置信度。引擎保留 `confidence ≥ min_confidence`（默认 `0.70`）。

```mermaid
flowchart LR
  A["email 0.98<br/>private key 0.99<br/>API keys 0.95-0.97"] --> M{"≥ 0.70?"}
  B["card 0.90 · IBAN 0.95<br/>RU phone 0.85 · INN-12 0.72"] --> M
  C["passport 0.40 · SSN 0.50<br/>KPP/BIC 0.40-0.55<br/>bare INN-10 0.55"] --> M
  M -->|yes| K["masked"]
  M -->|"no (needs keyword nearby)"| S["kept"]
  C -. "+keyword in 25-char window" .-> P["boost to 0.90+"]
  P --> M
```

设计规则：结构上模糊的值（9–12 位数字、`NNN-NN-NNNN` 形式的代码）在邻近出现关键词（`ИНН`、`СНИЛС`、`SSN`、`БИК`…）之前保持在阈值**以下**。因此订单号、零件号不会被屏蔽，而真正带标签的 ID 会被屏蔽。

## 重叠消解

检测器独立运行并产生重叠候选（`+7…` 同时命中 `phone_ru` 与 `phone_intl`；ETH 地址内部的数字段命中 `credit_card`）。消解按优先级贪心进行：

```mermaid
flowchart TD
  S["sort candidates by<br/>(confidence ↓, length ↓, start ↑)"] --> L["bytearray occupied[max_end]"]
  L --> I{"next candidate"}
  I --> Q{"occupied.find(1, start, end) == -1 ?"}
  Q -->|free| ACC["mark span occupied · accept"]
  Q -->|overlap| SKIP["skip"]
  ACC --> I
  SKIP --> I
```

`occupied.find` 与切片赋值在 C 层执行，因此该过程关于文本长度约为 O(n)，而非成对区间检查的 O(k²)。在 2 MB、含 160 000 个不同命中的输入上：**7.2 秒 → 1.64 秒**。

## 校验算法

用校验和取代朴素正则匹配，以压制误报。

| 算法 | 适用于 | 校验 |
|------|--------|------|
| Luhn | 银行卡 | `Σ 各位(每隔一位加倍) mod 10 == 0`，拒绝前导 0/全同 |
| INN-10 | 法人税号 | 加权和 `mod 11 mod 10 == d[9]` |
| INN-12 | 个人税号 | 两位校验位 |
| SNILS | 养老金号 | `Σ d[i]·(9-i) mod 101` → 校验 |
| IBAN | 银行账户 | 前 4 位移到末尾，字母→数字，`mod 97 == 1` |
| OGRN/OGRNIP | 公司注册 | `int(前 n 位) mod (11/13) mod 10 == 末位` |

## 策略与可逆性

`redact()` 通过**策略**替换每个命中。设置 `reversible=True` 时还会记录一个
vault（`替换 → 原始`），以便对 AI 的回答进行反脱敏。

| 策略 | 示例输出 | 可逆 |
|------|----------|:----:|
| `placeholder`（默认） | `[CARD_1]` | 是 |
| `pseudonym` | `4574 9172 3643 9348`（通过 Luhn 的假值，保留格式） | 是 |
| `partial` | `**** **** **** 1111` | 否 |
| `hash` | `[CARD_3f9a1c2b80]` | 是 |
| `remove` | ``（删除） | 否 |

```python
r = redact("card 4111 1111 1111 1111", strategy="pseudonym", reversible=True)
r.masked_text   # 'card 4574 9172 3643 9348'  — 假值，通过 Luhn
r.restore()     # 'card 4111 1111 1111 1111'  — 精确逆变换
```

CLI：`datashield redact --strategy pseudonym --vault v.json`，然后
`… | datashield restore --vault v.json`。vault 保存原始值——请保存在本地。

## 预设与结构化输入

**合规预设**将检测限制为某一法规所关注的类型：

| 预设 | 范围 |
|------|------|
| `pci-dss` | 金融 + 密钥 |
| `hipaa` | 健康 + 人名 + 政府 ID + 联系方式 |
| `gdpr` | 广义个人数据 |
| `secrets-only` | 密钥/令牌/密码 |
| `ru-gov` | 俄罗斯政府要件 |
| `minimal` | 仅置信度 ≥ 0.9 |

```bash
datashield redact --preset pci-dss          # 仅屏蔽卡号与密钥
datashield redact --min-severity critical   # 仅屏蔽关键类型
```

每个类型都有**类别**与**严重度**（low/medium/high/critical），它们显示在
`datashield detectors`、`scan --json` 以及审计报告中，并可通过 `--min-severity` 使用。

**结构化输入**在保持结构不变的前提下屏蔽值——既按检测器，
*也*按敏感的键/列名（`password`、`token`、`ssn`、…）：

```bash
echo '{"name":"Ivan","password":"hunter2","age":30}' | datashield redact --format json-data
# {"name":"[PERSON_1]","password":"[REDACTED]","age":30}
datashield redact --format csv --in people.csv     # 敏感列 + 逐单元格检测
```

## 指标

单核，Python 3.14，热进程。吞吐随输入大小线性变化并稳定在 **~1.05 MB/s**；冷启动（导入 → 首次 redact）**~15 毫秒**（相比加载 ML 模型需数秒）。

```mermaid
xychart-beta
  title "Latency vs input size (lower is better)"
  x-axis ["1KB", "4KB", "16KB", "64KB", "256KB", "1MB"]
  y-axis "ms per call" 0 --> 1000
  bar [1.05, 3.9, 15.4, 61, 243, 955]
```

| 输入 | 毫秒/次 | MB/s |
|-----:|--------:|-----:|
| 1 KB | 1.05 | 1.02 |
| 4 KB | 3.90 | 1.03 |
| 16 KB | 15.4 | 1.04 |
| 64 KB | 61.0 | 1.05 |
| 256 KB | 243 | 1.05 |
| 1 MB | 955 | 1.05 |

```mermaid
xychart-beta
  title "Overlap resolution, 2MB / 160k findings (seconds)"
  x-axis ["before: O(k^2)", "after: O(n)"]
  y-axis "seconds" 0 --> 8
  bar [7.2, 1.64]
```

| 指标 | 值 |
|------|----|
| 检测器 / 类型 | 90 / 83 |
| 默认开启 | 86 |
| **精确率 / 召回率 / F1** | **1.00 / 1.00 / 1.00**（带标注的评测语料，0 误报） |
| 冷启动 | ~15 毫秒 |
| 吞吐 | ~1.05 MB/s |
| 测试 | **1956**（标准库 unittest），Python 3.9–3.13 全绿 |
| <a name="footprint"></a>运行时依赖 | **0** |

质量是测量出来的，而非断言出来的：`tools/eval/evaluate.py` 在带标注的语料
（`tools/eval/corpus.jsonl`，正例 + 诱饵）上运行引擎，而
`tests/test_eval_metrics.py` 在 CI 中要求精确率/召回率/F1 ≥ 0.95。版本字符串
（`1.2.3.4`）与长 OID 会被 IPv4 检测器抑制。语料之外已知的固有歧义
（独立的 4 段 OID，或被拆成冒号分隔十六进制对的哈希）仍可能被过度
屏蔽为 IP/MAC——这是表象问题，绝不会造成泄漏。

检测器经由并行对抗审计加固：精确率 / 召回率 / DoS 问题
（包括两处 ReDoS）被发现并修复，每个都由回归测试锁定
（`tests/test_adversarial_regression.py`）。

## 隐私模型

```mermaid
flowchart LR
  V["original value"] -->|in memory only| PH["placeholder [TYPE_n]"]
  V -. "--report only" .-> H["salted SHA-256<br/>(truncated)"]
  V -.->|never persisted| X["disk ✗ / network ✗"]
```

- 单向脱敏——无还原路径，无保险库。
- `--report` 写入 `{type, start, end, confidence, detector, value_sha256, preview}`——绝不写原始值。
- 隐私测试保证原始值不出现在任何报告中。

## 安装

```bash
git clone git@github.com:meloch287/data-shield-ai.git && cd data-shield-ai
bash install.sh        # Claude Code 技能 + `datashield` 命令
# 或无需安装：
python3 -m datashield redact --in input.txt
```

### 使用

```bash
echo "我的邮箱 a@b.com, INN 7707083893" | datashield redact   # -> [EMAIL_1], INN [INN_1]
datashield scan  --in f.txt        # 命中，不脱敏
datashield stats --in f.txt        # 按类型计数
datashield detectors               # 列出全部 75 个
```

参数：`--in/--out` · `--only T1,T2` · `--exclude T` · `--min-confidence X` · `--json` · `--report audit.json` · `--config path`。

### API

```python
from datashield import redact, scan
redact("phone +7 909 123 45 67").masked_text   # 'phone [PHONE_RU_1]'
[(f.type, f.confidence) for f in scan("a@b.com")]
```

### 配置（`.datashield.json`）

```json
{ "min_confidence": 0.7, "allowlist": ["example.com"],
  "enabled_detectors": ["names_aggressive", "gliner"],
  "custom_patterns": [{"name":"employee_id","type":"EMPLOYEE_ID","pattern":"EMP-\\d{6}","confidence":0.9}] }
```

## 集成

全部基于标准库，无额外依赖。

```bash
datashield mcp                      # MCP 服务器（stdio）——智能体调用 redact/scan
datashield serve --port 8765        # HTTP：POST /redact, /scan ; GET /health
datashield check  path/to/files     # 若发现敏感数据则以 1 退出（CI 门禁）
```

```python
# 屏蔽应用日志中的敏感数据
import logging
from datashield.integrations.logging_filter import RedactingFilter
logging.getLogger().addFilter(RedactingFilter())
```

- **MCP：** 将 `datashield mcp`（或 `datashield-mcp` 入口点）注册为 MCP
  服务器；它暴露 `redact` 与 `scan` 工具，使任何智能体在数据到达外部模型之前
  对其脱敏。
- **pre-commit：** 把本仓库作为钩子加入（`.pre-commit-hooks.yaml`，id
  `data-shield-ai`），以阻止包含 PII/密钥的提交。
- **GitHub Action：** `action.yml` 扫描仓库，并在发现命中时使构建失败。

## 测试

```bash
python3 -m unittest discover -s tests -t .     # 1956 个测试
python3 tools/benchmark.py                      # 吞吐
python3 tools/eval/evaluate.py                  # 语料上的精确率/召回率
```

## 许可证

[MIT](LICENSE) © Саша · <a href="README.md">English</a> · <a href="README.ru.md">Русский</a>
