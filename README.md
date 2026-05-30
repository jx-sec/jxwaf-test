# JXWAF Test

面向 WAF（Web Application Firewall）防护能力的自动化测试工具。内置 **477 项测试用例**，覆盖 17 类攻击场景，支持并发执行并生成可视化 Markdown 报告。

> 所有测试用例来自 [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)。

## 快速开始

```bash
pip install requests
python runner.py --url http://your-waf.com/endpoint
```

运行完成后输出结果：

```
测试完成: 477 项 | 通过: 392 项 | 未通过: 67 项 | 异常: 18 项 | 耗时: 45.2s
```

## 参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--url` | WAF 目标地址（必填） | — |
| `--concurrency` | 并发执行数 | 5 |
| `--timeout` | 单项测试超时（秒） | 15 |
| `--block-status` | 拦截判定状态码（可多个） | 403 |
| `--allow-status` | 白名单模式：非此列表均视为拦截 | — |
| `--output` | 报告输出目录 | `./reports/` |
| `--vuepress` | 生成 VuePress 兼容格式 | `false` |

### 示例

```bash
# 快速测试
python runner.py --url http://waf.example.com/api/test

# 高并发 + 自定义拦截码
python runner.py --url https://waf.example.com --concurrency 20 --block-status 403 406

# 白名单模式 + 指定报告路径
python runner.py --url http://waf.example.com --allow-status 200 301 --output /tmp/reports
```

## 测试用例来源

测试用例按攻击类型分拆为 36 个文件，文件所在目录决定发送方式：

| 目录 | HTTP 方法 | 发送位置 | 用例数 | 覆盖场景 |
|------|-----------|----------|:------:|----------|
| `payloads/url/` | GET | `?input={payload}` | 43 | LFI、目录穿越、WAF 绕过 |
| `payloads/body/` | POST | `text/plain` Body | 432 | SQL 注入、XSS、命令注入、反序列化等 |
| `payloads/header/` | GET | `X-WAF-Test` Header | — | 预留扩展 |

## 覆盖的攻击类型

| 序号 | 攻击类型 | 用例数 |
|:----:|----------|:------:|
| 01 | SQL 注入（通用 + MySQL + MSSQL + PostgreSQL + Oracle + SQLite） | 105 |
| 02 | XSS（基础 + 按上下文分类） | 37 |
| 03 | 命令注入 | 20 |
| 04 | 文件包含（LFI） | 11 |
| 05 | 目录穿越 | 12 |
| 06 | 模板注入（SSTI — Jinja2/Twig/Freemarker/Velocity/ERB） | 18 |
| 07 | XXE（文件读取 / OOB / DoS / SSRF） | 14 |
| 08 | SSI 注入 | 12 |
| 09 | 原型污染 | 12 |
| 10 | XSLT 注入 | 12 |
| 11 | 反序列化（Java / PHP / Python / .NET / Node.js / Ruby） | 44 |
| 12 | 文件上传绕过 | 16 |
| 13 | WAF 绕过 — SQL 注入（通用 + 数据库特定） | 36 |
| 14 | WAF 绕过 — XSS | 19 |
| 15 | WAF 绕过 — 命令注入 | 18 |
| 16 | WAF 绕过 — XXE / 上传 / LFI / 路径 / 通用 | 56 |
| 17 | XPath 注入 / GraphQL 注入 / LaTeX 注入 | 35 |

> 共 **477 项测试用例**，覆盖 17 类攻击场景

## 测试用例格式

每个文件由若干测试用例组成，格式为 `# 描述 + Payload`。描述以 `#` 开头，Payload 紧跟其后。支持 `# @key: value` 元指令覆盖默认方法、Body 等行为：

```
# SQL 注入 - 联合查询注入（提取数据库版本、用户名、表名）
' UNION SELECT 1,version(),user(),database(),5-- -
# SQL 注入 - 时间盲注（延时5秒）
' AND (SELECT SLEEP(5))--
# LFI - php://input POST 原始数据执行代码
# @method: POST
# @body: <?php system('id');?>
php://input
```

## 报告

运行完成后在 `reports/` 生成 Markdown 报告，包含 6 个章节：

| 章节 | 内容 |
|------|------|
| 测试概览 | 目标地址、总测试项数、拦截/漏报/异常统计、综合拦截率 |
| 覆盖分类 | 各攻击类型的测试项数量 |
| 分类拦截率 | 每个类型的可视化柱状图 `████░░░░` |
| 测试详情 | 逐条用例的 🛡️ 拦截 / ⚠️ 漏报 / ❌ 异常 状态 |
| 漏报汇总 | 所有未拦截用例清单，建议重点审查 |
| 异常记录 | 超时、连接失败等异常用例详情 |

支持 `--vuepress` 生成带 Frontmatter 的 VuePress 兼容格式。

## 项目结构

```
.
├── runner.py                  # 测试引擎
├── payloads/
│   ├── url/                   # GET 方式（4 文件, 43 用例）
│   ├── body/                  # POST 方式（32 文件, 434 用例）
│   └── header/                # Header 方式（预留扩展）
└── reports/                   # 报告输出（gitignore）
```

## 依赖

- Python >= 3.7
- [requests](https://pypi.org/project/requests/)

## 注意事项

- 所有测试用例仅用于安全评估，请在获得授权的目标上使用
- 文件上传类用例为「文件名 + 攻击内容」组合，可直接用于 multipart 上传测试

## License

MIT
