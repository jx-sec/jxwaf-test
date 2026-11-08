#!/bin/bash
# 纯 curl 重测全部 POC (完全不依赖 runner.py / python)
# 目的: 验证 48 条漏报是否为程序问题
cd "$(dirname "$0")"
URL='http://159.75.101.239/get_web_attack_ip_ranking'
UA='WAF-Test-Tool/1.0'

AWK_PARSER='
function emit() { if (note != "" && n > 0) printf "%s\t%s\t%d\t%d\t%s\n", dir, note, n, dflag, payload }
BEGIN { note=""; payload=""; n=0; dflag=0 }
{
  s=$0; gsub(/^[ \t]+/, "", s); gsub(/[ \t]+$/, "", s)
  if (s == "") { emit(); note=""; payload=""; n=0; dflag=0; next }
  if (s ~ /^# @/) { dflag=1; next }
  if (s ~ /^#/) { emit(); note=""; payload=""; n=0; dflag=0; t=s; sub(/^#+[ \t]*/, "", t); gsub(/\t/, " ", t); note=t; next }
  if (note != "") { if (n>0) payload = payload "\\n"; payload = payload s; n++ }
}
END { emit() }
'

echo "== 0. 补查: 反引号 URL 的 curl 报错信息 =="
curl -X POST -o /dev/null '`http://159.75.101.239/get_web_attack_ip_ranking`' 2>&1 | head -2

results_file=$(mktemp)
for sd in url body; do
  for f in payloads/$sd/*.txt; do
    [ -e "$f" ] || continue
    awk -v dir="$sd" "$AWK_PARSER" "$f"
  done
done > "$results_file"

total=0 miss=0 skip=0
echo "== 1. 纯 curl 全量重测 (拦截=403) =="
while IFS=$'\t' read -r d note nlines dflag payload; do
  if [ "$dflag" = "1" ]; then skip=$((skip+1)); continue; fi
  if [ "$nlines" -gt 1 ]; then payload=${payload//\\n/$'\n'}; fi
  total=$((total+1))
  if [ "$d" = "url" ]; then
    code=$(curl -s -o /dev/null -w '%{http_code}' -G --data-urlencode "input=$payload" -H "User-Agent: $UA" --max-time 15 "$URL")
  else
    code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "User-Agent: $UA" -H 'Content-Type: text/plain' --data-binary "$payload" --max-time 15 "$URL")
  fi
  if [ "$code" != "403" ]; then
    miss=$((miss+1))
    echo "MISS($code) [$d] $note :: ${payload:0:90}"
  fi
done < "$results_file"
rm -f "$results_file"
echo "==== 总计: $total | 未拦截: $miss | 跳过(含@指令): $skip ===="
