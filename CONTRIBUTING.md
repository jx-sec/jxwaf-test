# Contributing

感谢你对 WAF Test Tool 的关注。

## 添加新的测试用例

测试用例是 `.txt` 文件，放置在 `payloads/` 对应目录中：

| 目录 | 发送方式 | 适用场景 |
|------|----------|----------|
| `payloads/url/` | GET `?input={payload}` | URL 参数注入、LFI、SSRF |
| `payloads/body/` | POST `text/plain` | SQL 注入、XSS、命令注入等 |
| `payloads/header/` | GET + Header | Header 注入 |

### 文件格式

```
# 用例描述（一句话说明这个测试项的目的）
payload-content
# 可选的元指令（覆盖默认行为）
# @method: POST
# @body: custom-body-content
payload-content
```

### 规则

- 每个用例由 `# 描述` + 1 行或多行 Payload 组成
- 描述行以 `# ` 开头，Payload 紧跟其后
- 空行分隔不同用例
- 元指令 `# @key: value` 支持覆盖 HTTP 方法、Body、Header 等
- 文件名格式建议 `{序号}_{攻击类型}.txt`

## 报告 Bug

请在 GitHub Issues 中提交，附带以下信息：

- Python 版本
- 完整的命令行参数
- 错误输出或堆栈信息
- 目标 WAF 返回的 HTTP 状态码（如适用）
