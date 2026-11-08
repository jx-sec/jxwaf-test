#!/bin/bash
# 定位手动 curl 返回 403 的真实触发因素
# 用户原始命令中 URL / Origin / Referer 均被字面反引号包裹 (markdown 代码格式残留)

UA='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36'
COOKIE='jxwaf_devid=8265a96b981896d32d24e3c925f9469ecee22b6fef53e01e148b2a8c9ff668061ec5449d3529038cb3c53c7d6cf7cac9; jxwaf_admin_professional_name=test; jxwaf_session=91cffae5-fd06-4152-a4ab-09c0a6bb585b; jxwaf_admin_standard_name=test'
# 52 字节 payload + 4x CRLF = 60 字节, 与用户请求 Content-Length: 60 一致
BODY=$'<style>input[type=password][value^="a"]{...}</style>\r\n\r\n\r\n\r\n'
CLEAN='http://159.75.101.239/get_web_attack_ip_ranking'
BTURL='`http://159.75.101.239/get_web_attack_ip_ranking`'

BASE=(-X POST -H 'Host: 159.75.101.239' -H 'Accept-Language: zh-CN,zh;q=0.9'
  -H 'Accept: application/json, text/plain, */*' -H 'Content-Type: application/json'
  -H "User-Agent: $UA" -H 'Accept-Encoding: gzip, deflate, br' -H 'Connection: keep-alive'
  -b "$COOKIE" --data-binary "$BODY")

echo "== A. 用户原始命令: URL/Origin/Referer 均带反引号 =="
curl --path-as-is -s -k -o /dev/null -w "A: %{http_code}\n" "${BASE[@]}" \
  -H 'Content-Length: 60' \
  -H 'Origin: `http://159.75.101.239`' -H 'Referer: `http://159.75.101.239/`' \
  "$BTURL"

echo "== B. A 的实际请求行/请求头 (-v 抓取) =="
curl --path-as-is -s -k -v -o /dev/null "${BASE[@]}" \
  -H 'Content-Length: 60' \
  -H 'Origin: `http://159.75.101.239`' -H 'Referer: `http://159.75.101.239/`' \
  "$BTURL" 2>&1 | grep -E '^> ' || echo "(curl 报错, 见下方原始输出)"
curl --path-as-is -s -k -o /dev/null "${BASE[@]}" \
  -H 'Content-Length: 60' \
  -H 'Origin: `http://159.75.101.239`' -H 'Referer: `http://159.75.101.239/`' \
  "$BTURL" 2>&1 | head -2

echo "== C. 仅 URL 带反引号 (Origin/Referer 干净) =="
curl --path-as-is -s -k -o /dev/null -w "C: %{http_code}\n" "${BASE[@]}" \
  -H 'Content-Length: 60' -H 'Origin: http://159.75.101.239' -H 'Referer: http://159.75.101.239/' \
  "$BTURL"

echo "== D. 仅 Origin+Referer 带反引号 (URL 干净) =="
curl --path-as-is -s -k -o /dev/null -w "D: %{http_code}\n" "${BASE[@]}" \
  -H 'Content-Length: 60' \
  -H 'Origin: `http://159.75.101.239`' -H 'Referer: `http://159.75.101.239/`' \
  "$CLEAN"

echo "== E. 仅 Referer 带反引号 =="
curl --path-as-is -s -k -o /dev/null -w "E: %{http_code}\n" "${BASE[@]}" \
  -H 'Content-Length: 60' -H 'Origin: http://159.75.101.239' -H 'Referer: `http://159.75.101.239/`' \
  "$CLEAN"

echo "== F. 仅 Origin 带反引号 =="
curl --path-as-is -s -k -o /dev/null -w "F: %{http_code}\n" "${BASE[@]}" \
  -H 'Content-Length: 60' -H 'Origin: `http://159.75.101.239`' -H 'Referer: http://159.75.101.239/' \
  "$CLEAN"

echo "== G. 全干净对照 (无反引号, 无显式 Content-Length) =="
curl --path-as-is -s -k -o /dev/null -w "G: %{http_code}\n" "${BASE[@]}" \
  -H 'Origin: http://159.75.101.239' -H 'Referer: http://159.75.101.239/' \
  "$CLEAN"
