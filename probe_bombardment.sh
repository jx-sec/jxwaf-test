#!/bin/bash
# 验证: 攻击高频期间是否存在 IP 级全量拦截 (解释用户 19:27:18 的 403)
URL='http://159.75.101.239/get_web_attack_ip_ranking'
CT='Content-Type: application/json'
CSS='<style>input[type=password][value^="a"]{...}</style>'
HARM='{"page":1,"size":10}'
SQLI="1' OR '1'='1' --"

probe() { curl -s -o /dev/null -w "%{http_code}" -X POST -H "$CT" --data "$1" "$URL"; }

echo "基线: css=$(probe "$CSS") harm=$(probe "$HARM") sqli=$(probe "$SQLI")"

bombard() {  # $1=payload $2=秒数
  local end=$((SECONDS+$2))
  while [ $SECONDS -lt $end ]; do
    for i in $(seq 1 10); do curl -s -o /dev/null -X POST -H "$CT" --data "$1" "$URL" & done
    wait
  done
}

echo "-- 阶段1: 无害请求轰炸 20s, 期间探测 --"
bombard "$HARM" 20 &
BG=$!
sleep 5
echo "  [轰炸中] css=$(probe "$CSS") harm=$(probe "$HARM")"
sleep 5
echo "  [轰炸中] css=$(probe "$CSS") harm=$(probe "$HARM")"
wait $BG

echo "-- 阶段2: SQLi 攻击轰炸 20s, 期间探测 --"
bombard "$SQLI" 20 &
BG=$!
sleep 5
echo "  [轰炸中] css=$(probe "$CSS") harm=$(probe "$HARM")"
sleep 5
echo "  [轰炸中] css=$(probe "$CSS") harm=$(probe "$HARM")"
wait $BG

echo "轰炸结束后: css=$(probe "$CSS") harm=$(probe "$HARM")"
