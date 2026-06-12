<div align="center">

# 🛡️ Data Shield AI

### 位于你与 AI 之间的隐私防护层

在文本离开你的设备**之前**，于本地脱敏敏感数据。<br/>
无需联网。无依赖。纯 Python。

<br/>

[![CI](https://github.com/meloch287/data-shield-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/meloch287/data-shield-ai/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-701%20passing-success.svg)](#-测试)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](#)
[![Detectors](https://img.shields.io/badge/detectors-52-orange.svg)](#-功能特性)

<br/>

<b>🌐 其他语言：</b>
<br/>
<a href="README.md">🇬🇧 English</a> &nbsp;·&nbsp;
<a href="README.ru.md">🇷🇺 Русский</a> &nbsp;·&nbsp;
<a href="README.zh-CN.md"><b>🇨🇳 中文</b></a>

</div>

---

```text
输入   →   Иван Петров, INN 7707083893, 卡号 4111 1111 1111 1111, 密钥 AKIAIOSFODNN7EXAMPLE
输出   →   [PERSON_1], INN [INN_1], 卡号 [CREDIT_CARD_1], 密钥 [AWS_ACCESS_KEY_1]
```

当你把文本发送给外部 AI 时，个人信息、财务细节和各类密钥很容易随任务一起泄露。
**Data Shield AI** 会在发送前于本地将它们剔除，只把脱敏后的任务交给 AI。

## 📑 目录

- [功能特性](#-功能特性)
- [安装](#-安装)
- [使用](#-使用)
- [编程接口](#-编程接口)
- [配置](#-配置)
- [更高召回模式](#-更高召回模式)
- [速度](#-速度)
- [隐私](#-隐私)
- [测试](#-测试)

## ✨ 功能特性

- **无需 ML 的人名识别（PERSON）** — 俄语父称、上下文线索（“меня зовут…”、
  “Mr.”、“Dear”），以及来自内置词典的“名 + 姓”组合。冷启动约 15 毫秒，毫不拖慢。
- **俄罗斯地址（ADDRESS）** — 街道/大街/胡同；邮政编码。
- **俄罗斯** — INN（10/12 位校验）、SNILS、护照、手机号、OGRN/OGRNIP（校验位）、
  KPP、BIC、银行账户、医保单号（OMS）、驾照。
- **国际** — 电子邮件、电话、银行卡（**Luhn 校验**）、IBAN（mod-97）、
  IPv4/IPv6、MAC、美国 SSN/EIN、英国 NINO、ETH/BTC 加密钱包地址。
- **密钥** — AWS / OpenAI / Anthropic / GitHub / GitLab / Google / Slack /
  Stripe / HuggingFace / Shopify 等的密钥、JWT、私钥、`password=…`。
- **稳定占位符** — 同一值 → 同一占位符，AI 仍能理解“同一个人 / 同一张卡”，
  但看不到真实数据。
- **低误报** — 用校验和取代粗糙的正则。
- **默认隐私** — 原始值只存在于内存中；报告仅保存加盐哈希。
- **混合模式** — 可选的 ML 插件（Presidio 或轻量的 GLiNER），用于对自由文本中的
  人名/地址/机构名做更高召回的识别。
- **零依赖。** Python 3.9+，开箱即用 52 个检测器。

## 📦 安装

```bash
git clone git@github.com:meloch287/data-shield-ai.git
cd data-shield-ai
bash install.sh        # Claude Code 技能 + `datashield` 命令
```

或者无需安装，直接在仓库内使用：

```bash
python3 -m datashield redact --in input.txt
```

## 🚀 使用

```bash
# 脱敏（主命令）
echo "我的邮箱 a@b.com, INN 7707083893" | datashield redact
# -> 我的邮箱 [EMAIL_1], INN [INN_1]

datashield scan  --in dialog.txt    # 查看识别到的内容（不脱敏）
datashield stats --in dialog.txt    # 按类型汇总
datashield detectors                # 列出所有检测器
```

<details>
<summary><b>常用参数</b></summary>

| 参数 | 用途 |
|------|------|
| `--in / --out` | 用文件代替 stdin/stdout |
| `--only EMAIL,CREDIT_CARD` | 仅这些类型 |
| `--exclude IP` | 排除这些类型 |
| `--min-confidence 0.5` | 置信度阈值（识别更多） |
| `--json` | 机器可读输出 |
| `--report audit.json` | 不含原始值的审计（仅哈希） |
| `--config .datashield.json` | 自定义配置 |

</details>

## 🐍 编程接口

```python
from datashield import redact, scan

result = redact("phone +7 909 123 45 67")
print(result.masked_text)   # 'phone [PHONE_RU_1]'
print(result.stats)          # {'PHONE_RU': 1}

for f in scan("email a@b.com"):
    print(f.type, f.start, f.end, f.confidence)
```

## ⚙️ 配置

工作目录下的 `.datashield.json`（示例见 `.datashield.example.json`）：

```json
{
  "min_confidence": 0.7,
  "placeholder_template": "[{type}_{n}]",
  "allowlist": ["example.com"],
  "enabled_detectors": ["high_entropy"],
  "custom_patterns": [
    {"name": "employee_id", "type": "EMPLOYEE_ID", "pattern": "EMP-\\d{6}", "confidence": 0.9}
  ]
}
```

- `allowlist` — 永不脱敏的值/域名。
- `enabled_detectors` — 开启可选项（`high_entropy`、`names_aggressive`、
  `ml`、`gliner`）。
- `disabled_detectors` — 按名称或类型关闭某个检测器。
- `custom_patterns` — 你自己的正则表达式。

## 🎯 更高召回模式

**激进人名（无依赖）** — 以可能的同形词（`Vera`、`Roman`）为代价，脱敏单个已知
名字（`Ivan`、`John`）：

```json
{ "enabled_detectors": ["names_aggressive"] }
```

**通过 GLiNER 使用 ML（轻量，CPU 上的 ONNX）：**

```bash
pip install "data-shield-ai[gliner]"
```
然后 `{ "enabled_detectors": ["gliner"] }`。

**通过 Microsoft Presidio 使用 ML（最高召回）：**

```bash
pip install "data-shield-ai[ml]"
python3 -m spacy download en_core_web_lg
```
然后 `{ "enabled_detectors": ["ml"] }`。未安装相应包时，核心照常工作——插件只是
不增加任何识别结果。

## ⚡ 速度

冷启动约 15 毫秒，典型提示（1–3 KB）耗时 1–3 毫秒。ML 插件只加载一次模型；
零依赖的核心完全无需加载模型。基准测试：`python3 tools/benchmark.py`。

## 🔒 隐私

- 完全本地运行，不使用网络。
- 原始值仅存在于内存中，退出时清除。
- **单向脱敏** —— 不会还原原始值。
- `--report` 仅包含类型、位置和**加盐 SHA-256 哈希**。

## 🧪 测试

```bash
python3 -m unittest discover -s tests -t .
```

701 个测试，仅用标准库 `unittest`，在 Python 3.9–3.13 上全部通过。

## 📄 许可证

[MIT](LICENSE) © Саша

<div align="center"><sub>为隐私优先的 AI 工作流打造 · <a href="README.md">English</a> · <a href="README.ru.md">Русский</a></sub></div>
