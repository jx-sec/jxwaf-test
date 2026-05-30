#!/usr/bin/env python3
"""
WAF 防护能力测试工具 - 独立版
针对精选测试项目进行自动化测试，生成 Markdown 报告

用法:
    python runner.py --url http://your-waf-site.com/endpoint

依赖:
    pip install requests
"""

import os
import re
import sys
import time
import argparse
import warnings

import requests

warnings.filterwarnings("ignore", message=".*urllib3.*")
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

__version__ = "1.0.0"


@dataclass
class Config:
    waf_api_url: str
    concurrency: int = 5
    timeout: int = 15
    blocked_status_codes: List[int] = field(default_factory=lambda: [403])
    allow_status_codes: List[int] = field(default_factory=list)
    user_agent: str = "WAF-Test-Tool/1.0"


@dataclass
class TestResult:
    category: str
    description: str
    payload: str
    blocked: bool
    status_code: int
    error: Optional[str] = None
    request_method: str = "GET"
    request_body: Optional[str] = None


SEND_METHOD = {
    "url": "GET",
    "body": "POST",
    "header": "HEADER",
}


def load_payloads(payloads_dir: str) -> Dict[str, List[Tuple[str, str, str, str, Dict]]]:
    result: Dict[str, List[Tuple[str, str, str, str, Dict]]] = {}

    for send_dir in ("url", "body", "header"):
        subdir = os.path.join(payloads_dir, send_dir)
        if not os.path.isdir(subdir):
            continue
        files = sorted([f for f in os.listdir(subdir) if os.path.isfile(os.path.join(subdir, f))])

        for fname in files:
            fpath = os.path.join(subdir, fname)
            entries: List[Tuple[str, str, str, str, Dict]] = []
            current_note = ""
            directives: Dict[str, str] = {}
            category_name = fname.replace(".txt", "")

            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    payload_lines = []
                    for line in f:
                        stripped = line.strip()
                        if not stripped:
                            if payload_lines and current_note:
                                entries.append((current_note, "\n".join(payload_lines), category_name, send_dir, dict(directives)))
                                current_note = ""
                                directives = {}
                                payload_lines = []
                            continue
                        if stripped.startswith("# @"):
                            m = re.match(r'#\s*@(\w+):\s*(.*)', stripped)
                            if m:
                                directives[m.group(1)] = m.group(2)
                        elif stripped.startswith("# ") or stripped == "#":
                            if payload_lines and current_note:
                                entries.append((current_note, "\n".join(payload_lines), category_name, send_dir, dict(directives)))
                                current_note = ""
                                directives = {}
                                payload_lines = []
                            current_note = stripped.lstrip("#").strip()
                        elif current_note:
                            payload_lines.append(stripped)
                    if payload_lines and current_note:
                        entries.append((current_note, "\n".join(payload_lines), category_name, send_dir, dict(directives)))
            except Exception as e:
                print(f"  [警告] 读取失败: {fpath} - {e}")

            if entries:
                result[fname] = entries
                method = SEND_METHOD.get(send_dir, "POST")
                print(f"[加载] [{method}] {fname}: {len(entries)} 条测试项目")
            else:
                print(f"[加载] {fname}: 0 条测试项目 (跳过)")

    return result


def _default_method(send_dir: str, directives: Dict[str, str]) -> str:
    return directives.get("method", "GET" if send_dir in ("url", "header") else "POST").upper()


def test_single_payload(config: Config, category_fname: str,
                        description: str, payload: str, send_dir: str,
                        directives: Dict[str, str]) -> TestResult:
    method = _default_method(send_dir, directives)
    try:
        req_params = {}
        req_headers = {"User-Agent": config.user_agent}
        req_body = None

        if directives.get("header"):
            parts = directives["header"].split(":", 1)
            if len(parts) == 2:
                req_headers[parts[0].strip()] = parts[1].strip()

        if directives.get("url"):
            req_params["input"] = directives["url"]
        elif send_dir == "url":
            req_params["input"] = payload

        if directives.get("body"):
            req_body = directives["body"].encode("utf-8")
        elif send_dir == "body":
            req_body = payload.encode("utf-8")

        if send_dir == "header":
            req_headers["X-WAF-Test"] = payload

        if req_body is not None and "Content-Type" not in req_headers:
            req_headers["Content-Type"] = "text/plain"

        if method == "POST" or req_body is not None:
            resp = requests.post(
                config.waf_api_url,
                params=req_params,
                data=req_body,
                headers=req_headers,
                timeout=config.timeout,
                allow_redirects=False,
            )
        else:
            resp = requests.get(
                config.waf_api_url,
                params=req_params,
                headers=req_headers,
                timeout=config.timeout,
                allow_redirects=False,
            )

        if config.allow_status_codes:
            blocked = resp.status_code not in config.allow_status_codes
        else:
            blocked = resp.status_code in config.blocked_status_codes
        return TestResult(
            category=category_fname,
            description=description,
            payload=payload,
            blocked=blocked,
            status_code=resp.status_code,
            request_method=method,
            request_body=directives.get("body"),
        )
    except requests.exceptions.Timeout:
        return TestResult(
            category=category_fname, description=description,
            payload=payload, blocked=False, status_code=0, error="请求超时",
            request_method=method,
            request_body=directives.get("body"),
        )
    except requests.exceptions.ConnectionError as e:
        return TestResult(
            category=category_fname, description=description,
            payload=payload, blocked=False, status_code=0, error=f"连接失败: {e}",
            request_method=method,
            request_body=directives.get("body"),
        )
    except Exception as e:
        return TestResult(
            category=category_fname, description=description,
            payload=payload, blocked=False, status_code=0, error=str(e),
            request_method=method,
            request_body=directives.get("body"),
        )


def run_tests(config: Config, all_payloads: Dict[str, List[Tuple[str, str, str, str, Dict]]]
              ) -> List[TestResult]:
    tasks = []
    for fname, entries in all_payloads.items():
        for desc, payload, cat, send_dir, directives in entries:
            tasks.append((fname, desc, payload, send_dir, directives))

    total = len(tasks)
    print(f"\n{'='*60}")
    print(f"开始测试: 共 {total} 条测试项目, 并发数 {config.concurrency}")
    print(f"WAF API: {config.waf_api_url}")
    if config.allow_status_codes:
        block_criteria = f"非 HTTP {config.allow_status_codes} 均拦截"
    else:
        block_criteria = f"HTTP {config.blocked_status_codes}"
    print(f"拦截判定: {block_criteria}")
    print(f"{'='*60}\n")

    results: List[TestResult] = []
    completed = 0
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=config.concurrency) as executor:
        futures = {
            executor.submit(test_single_payload, config, fname, desc, p, sd, d): (fname, desc, p)
            for fname, desc, p, sd, d in tasks
        }
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            completed += 1
            if completed % 10 == 0 or completed == total:
                blocked_count = sum(1 for r in results if r.blocked)
                elapsed = time.time() - start_time
                passed_count = blocked_count
                print(f"  进度: {completed}/{total} | 通过: {passed_count} | "
                      f"耗时: {elapsed:.1f}s")

    elapsed = time.time() - start_time
    passed = sum(1 for r in results if r.blocked)
    failed = sum(1 for r in results if not r.blocked and not r.error)
    errored = sum(1 for r in results if r.error)
    print(f"\n测试完成: {total} 项 | 通过: {passed} 项 | 未通过: {failed} 项 | "
          f"异常: {errored} 项 | 耗时: {elapsed:.1f}s\n")
    return results


def escape_md(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", "\\n").replace("\r", "\\r")


def truncate(text: str, max_len: int = 150) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + "..."


def category_label(fname: str) -> str:
    """从文件名提取分类名"""
    parts = fname.replace(".txt", "").split("_", 1)
    if len(parts) > 1:
        return parts[1].replace("_", " ")
    return fname.replace(".txt", "").replace("_", " ")


def generate_report(config: Config, results: List[TestResult],
                    output_path: str,
                    vuepress: bool = False) -> None:
    report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(results)
    blocked = sum(1 for r in results if r.blocked)
    errors = sum(1 for r in results if r.error)

    cat_results: Dict[str, List[TestResult]] = {}
    for r in results:
        cat_results.setdefault(r.category, []).append(r)

    lines = []

    if vuepress:
        lines.append("---")
        lines.append(f"title: WAF 防护能力测试报告")
        lines.append(f"date: {report_time}")
        lines.append(f"target: {config.waf_api_url}")
        lines.append("---")
        lines.append("")

    lines.append("# WAF 防护能力测试报告")
    lines.append("")
    lines.append(f"> **报告由 jxwaf-test 生成于 {report_time}**  ")
    lines.append(f"> **测试项目来源**: [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 1. 测试概览")
    lines.append("")
    lines.append(f"| 指标 | 数值 |")
    lines.append(f"|------|------|")
    lines.append(f"| WAF 目标地址 | `{config.waf_api_url}` |")
    lines.append(f"| 测试项目分类数 | {len(cat_results)} |")
    lines.append(f"| 测试项目总数 | {total} |")
    failed = total - blocked - errors
    lines.append(f"| 通过（成功拦截） | {blocked} |")
    lines.append(f"| 未通过（漏报） | {failed} |")
    lines.append(f"| 请求异常 | {errors} |")
    pass_rate = f"{blocked / total * 100:.1f}%" if total > 0 else "—"
    lines.append(f"| 综合通过率 | **{pass_rate}** |")
    if config.allow_status_codes:
        lines.append(f"| 拦截判定标准 | 非 HTTP {config.allow_status_codes} 均拦截 |")
    else:
        lines.append(f"| 拦截判定标准 | HTTP {config.blocked_status_codes} |")
    lines.append("")

    lines.append("## 2. 测试覆盖分类")
    lines.append("")
    lines.append("> 以下为本次测试覆盖的攻击类型及所属大类")
    lines.append("")
    lines.append("| 分类 | 项目数 | 所属大类 |")
    lines.append("|------|--------|----------|")
    sorted_cats = sorted(cat_results.items(), key=lambda x: x[0])
    for cat_fname, cat_res in sorted_cats:
        cat_total = len(cat_res)
        tags = []
        cat_label = category_label(cat_fname)
        if "sql" in cat_label.lower() or "sqli" in cat_label.lower():
            tags.append("SQL 注入")
        if "xss" in cat_label.lower():
            tags.append("XSS")
        if "command" in cat_label.lower() or "cmd" in cat_label.lower():
            tags.append("命令注入")
        if "ssti" in cat_label.lower():
            tags.append("服务端注入")
        if "ssi" in cat_label.lower():
            tags.append("服务端注入")
        if "xslt" in cat_label.lower():
            tags.append("服务端注入")
        if "xxe" in cat_label.lower():
            tags.append("XXE")
        if "nosql" in cat_label.lower():
            tags.append("NoSQL 注入")
        if "deserial" in cat_label.lower():
            tags.append("反序列化")
        if "file_inclusion" in cat_label.lower() or "lfi" in cat_label.lower():
            tags.append("文件包含")
        if "directory_traversal" in cat_label.lower():
            tags.append("目录穿越")
        if "ssrf" in cat_label.lower():
            tags.append("SSRF")
        if "open_redirect" in cat_label.lower():
            tags.append("开放重定向")
        if "crlf" in cat_label.lower():
            tags.append("CRLF 注入")
        if "file_upload" in cat_label.lower() or "upload" in cat_label.lower():
            tags.append("文件上传")
        if "prototype" in cat_label.lower():
            tags.append("原型污染")
        if "waf_bypass" in cat_label.lower() or "bypass" in cat_label.lower():
            tags.append("WAF 绕过")
        if "ldap" in cat_label.lower():
            tags.append("其他注入")
        if "xpath" in cat_label.lower():
            tags.append("其他注入")
        if "graphql" in cat_label.lower():
            tags.append("其他注入")
        if "csv" in cat_label.lower():
            tags.append("其他注入")
        if "latex" in cat_label.lower():
            tags.append("其他注入")
        tag_str = "、".join(tags) if tags else "其他"
        lines.append(f"| {cat_label} | {cat_total} | {tag_str} |")
    lines.append("")

    lines.append("---")
    lines.append("")

    lines.append("## 3. 分类通过率汇总")
    lines.append("")
    lines.append("| 分类 | 项目数 | 通过 | 未通过 | 异常 | 通过率 |")
    lines.append("|------|--------|------|--------|------|--------|")
    for cat_fname, cat_res in sorted_cats:
        cat_total = len(cat_res)
        cat_blocked = sum(1 for r in cat_res if r.blocked)
        cat_unblocked = sum(1 for r in cat_res if not r.blocked and not r.error)
        cat_error = sum(1 for r in cat_res if r.error)
        rate = cat_blocked / cat_total * 100 if cat_total > 0 else 0
        bar = "█" * int(rate / 5) + "░" * (20 - int(rate / 5))
        lines.append(f"| {category_label(cat_fname)} | {cat_total} | {cat_blocked} | "
                     f"{cat_unblocked} | {cat_error} | {bar} **{rate:.1f}%** |")
    lines.append("")
    if total > 0:
        lines.append(f"**综合通过率**: {blocked}/{total} = **{blocked / total * 100:.1f}%**")
    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append("## 4. 分类测试详情")
    lines.append("")
    lines.append("> 状态: 🛡️ 通过  |  ⚠️ 未通过  |  ❌ 异常")
    lines.append("")

    for idx, (cat_fname, cat_res) in enumerate(sorted_cats, 1):
        cat_total = len(cat_res)
        cat_blocked = sum(1 for r in cat_res if r.blocked)
        rate = cat_blocked / cat_total * 100 if cat_total > 0 else 0
        cat_label = category_label(cat_fname)
        anchor = cat_label.replace(" ", "-").replace("/", "-").lower()
        lines.append(f"### 4.{idx} {cat_label}")
        lines.append("")
        lines.append(f"- **项目数**: {cat_total}  |  **通过**: {cat_blocked}  |  **通过率**: {rate:.1f}%")
        lines.append("")
        lines.append("| 状态 | 方法 | 项目描述 | Payload | HTTP 状态码 |")
        lines.append("|------|------|----------|---------|-------------|")

        for r in cat_res:
            if r.blocked:
                status = "🛡️"
            elif r.error:
                status = "❌"
            else:
                status = "⚠️"
            status_detail = r.error if r.error else str(r.status_code)
            payload_display = f"`{escape_md(truncate(r.payload))}`"
            if r.request_body:
                payload_display += f" + Body: `{escape_md(truncate(r.request_body, 80))}`"
            lines.append(f"| {status} | {r.request_method} | {r.description} | "
                         f"{payload_display} | {status_detail} |")
        lines.append("")

    unblocked_list = [r for r in results if not r.blocked and not r.error]
    if unblocked_list:
        lines.append("---")
        lines.append("")
        lines.append("## 5. 未通过测试项目汇总")
        lines.append("")
        lines.append(f"以下 **{len(unblocked_list)}** 条项目未通过检测，建议重点审查：")
        lines.append("")
        lines.append("| 分类 | 描述 | Payload | 状态码 |")
        lines.append("|------|------|---------|--------|")
        for r in unblocked_list:
            payload_display = escape_md(truncate(r.payload, 200))
            if r.request_body:
                payload_display += f" + Body: `{escape_md(truncate(r.request_body, 80))}`"
            lines.append(f"| {category_label(r.category)} | {r.description} | "
                         f"`{payload_display}` | {r.status_code} |")
        lines.append("")

    error_list = [r for r in results if r.error]
    if error_list:
        lines.append("---")
        lines.append("")
        lines.append("## 6. 请求异常记录")
        lines.append("")
        lines.append(f"共 **{len(error_list)}** 条项目发送异常：")
        lines.append("")
        for r in error_list:
            lines.append(f"- `{escape_md(truncate(r.payload))}` | {r.description} | {r.error}")
        lines.append("")

    lines.append("---")
    lines.append("")

    report_content = "\n".join(lines)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_content)
    print(f"报告已生成: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="WAF 防护能力测试工具 - 独立版 (精选测试项目)"
    )
    parser.add_argument("--url", required=True, help="WAF 目标 URL (如 http://waf-site.com/endpoint)")
    parser.add_argument("--concurrency", type=int, default=5,
                        help="并发请求数 (默认: 5)")
    parser.add_argument("--timeout", type=int, default=15,
                        help="单次请求超时秒数 (默认: 15)")
    parser.add_argument("--block-status", type=int, nargs="+", default=[403],
                        help="拦截判定的 HTTP 状态码 (默认: 403)")
    parser.add_argument("--allow-status", type=int, nargs="+", default=[],
                        help="允许的 HTTP 状态码，非此列表全部视为拦截 (如 --allow-status 200)")
    parser.add_argument("--output", default=None, help="报告输出路径")
    parser.add_argument("--vuepress", action="store_true",
                        help="生成 VuePress 兼容格式报告（含 Frontmatter）")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    payloads_dir = os.path.join(script_dir, "payloads")
    if not os.path.isdir(payloads_dir):
        print(f"[错误] payloads 目录不存在: {payloads_dir}")
        sys.exit(1)

    config = Config(
        waf_api_url=args.url,
        concurrency=args.concurrency,
        timeout=args.timeout,
        blocked_status_codes=args.block_status,
        allow_status_codes=args.allow_status,
    )

    output_dir = args.output or os.path.join(script_dir, "reports")
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(output_dir, f"WAF_TEST_REPORT_{timestamp}.md")

    print(f"{'='*60}")
    print(f"WAF 防护能力测试工具 (独立版)")
    print(f"{'='*60}")
    print(f"WAF API: {config.waf_api_url}")
    print(f"并发数: {config.concurrency}")
    if config.allow_status_codes:
        print(f"拦截判定: 非 HTTP {config.allow_status_codes} 均拦截")
    else:
        print(f"拦截判定: HTTP {config.blocked_status_codes}")
    print(f"报告输出: {output_path}")
    print(f"{'='*60}\n")

    all_payloads = load_payloads(payloads_dir)
    if not all_payloads:
        print("[错误] 未收集到任何测试项目")
        sys.exit(1)

    total_poc = sum(len(v) for v in all_payloads.values())
    print(f"\n共 {total_poc} 条测试项目，覆盖 {len(all_payloads)} 个分类\n")

    results = run_tests(config, all_payloads)
    generate_report(config, results, output_path, vuepress=args.vuepress)


if __name__ == "__main__":
    main()
