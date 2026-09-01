#!/bin/sh
#
# 実モジュールを使った E2E テストを一括で実行する。
#
#   NGINX_SRC=/path/to/nginx-1.26.2 ./test/run-e2e.sh
#
# NGINX_SRC を指定するとモジュールのビルドから行う。すでにビルド済みの場合は
# NGINX_BIN と OIDC_MODULE で nginx 実行ファイルと .so を直接指定できる。
#
set -e

REPO_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TEST_DIR="$REPO_DIR/test"
WORK_DIR="${WORK_DIR:-$TEST_DIR/.e2e}"

NGINX_BIN="${NGINX_BIN:-}"
OIDC_MODULE="${OIDC_MODULE:-}"

if [ -n "$NGINX_SRC" ]; then
    echo "==> building the module in $NGINX_SRC"
    ( cd "$NGINX_SRC" \
      && ./configure --with-compat --with-http_ssl_module \
                     --add-dynamic-module="$REPO_DIR" >/dev/null \
      && make -j"$(nproc 2>/dev/null || echo 2)" >/dev/null )
    NGINX_BIN="$NGINX_SRC/objs/nginx"
    OIDC_MODULE="$NGINX_SRC/objs/ngx_http_oidc_module.so"
    MIME_TYPES="$NGINX_SRC/conf/mime.types"
fi

[ -n "$NGINX_BIN" ]    || { echo "NGINX_SRC or NGINX_BIN must be set" >&2; exit 1; }
[ -n "$OIDC_MODULE" ]  || { echo "NGINX_SRC or OIDC_MODULE must be set" >&2; exit 1; }
MIME_TYPES="${MIME_TYPES:-/etc/nginx/mime.types}"

# Playwright の Chromium。npx playwright install 済みなら未設定でよい。
if [ -z "$PLAYWRIGHT_CHROMIUM_PATH" ] && [ -x /opt/pw-browsers/chromium ]; then
    PLAYWRIGHT_CHROMIUM_PATH=/opt/pw-browsers/chromium
fi
export PLAYWRIGHT_CHROMIUM_PATH

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR/conf" "$WORK_DIR/logs"
cp "$MIME_TYPES" "$WORK_DIR/conf/mime.types"

sed "s#^load_module .*#load_module $OIDC_MODULE;#" \
    "$TEST_DIR/nginx.conf" > "$WORK_DIR/conf/nginx-store.conf"

# セッションストアを無効にした（Cookie にクレームを載せる）構成
sed "s|^\( *\)oidc_session_store |\1# oidc_session_store |" \
    "$WORK_DIR/conf/nginx-store.conf" > "$WORK_DIR/conf/nginx-cookie.conf"

# セッションを Redis に置く構成
sed "s|^\( *\)oidc_session_store .*|\1oidc_session_store redis;|" \
    "$WORK_DIR/conf/nginx-store.conf" > "$WORK_DIR/conf/nginx-redis.conf"

# Redis Sentinel 経由でマスターを解決する構成
sed "s|^\( *\)oidc_session_store redis;|\1oidc_session_store redis;\n\1oidc_redis_sentinel 127.0.0.1:26399;\n\1oidc_redis_master oidc-test;|" \
    "$WORK_DIR/conf/nginx-redis.conf" > "$WORK_DIR/conf/nginx-sentinel.conf"

# Redis Cluster に接続する構成（種となるノードは 7000、残りは MOVED で学習する）
sed -e "s|^\( *\)oidc_session_store redis;|\1oidc_session_store redis;\n\1oidc_redis_cluster on;|" \
    -e "s|^\( *\)oidc_redis_pass .*|\1oidc_redis_pass 127.0.0.1:7000;|" \
    "$WORK_DIR/conf/nginx-redis.conf" > "$WORK_DIR/conf/nginx-cluster.conf"

# private_key_jwt 用のクライアント鍵
openssl genrsa -out "$WORK_DIR/conf/client-key.pem" 2048 2>/dev/null
openssl rsa -in "$WORK_DIR/conf/client-key.pem" -pubout \
        -out "$WORK_DIR/conf/client-pub.pem" 2>/dev/null

# DPoP 用の EC 鍵
openssl ecparam -name prime256v1 -genkey -noout \
        -out "$WORK_DIR/conf/dpop-key.pem" 2>/dev/null

# mTLS 用の CA・サーバー証明書・クライアント証明書
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
        -subj "/CN=oidc-test-ca" \
        -keyout "$WORK_DIR/conf/ca-key.pem" \
        -out "$WORK_DIR/conf/ca-cert.pem" 2>/dev/null

openssl req -newkey rsa:2048 -nodes -subj "/CN=127.0.0.1" \
        -keyout "$WORK_DIR/conf/idp-key.pem" \
        -out "$WORK_DIR/conf/idp.csr" 2>/dev/null
openssl x509 -req -in "$WORK_DIR/conf/idp.csr" -days 2 \
        -CA "$WORK_DIR/conf/ca-cert.pem" -CAkey "$WORK_DIR/conf/ca-key.pem" \
        -CAcreateserial -extfile /dev/stdin \
        -out "$WORK_DIR/conf/idp-cert.pem" 2>/dev/null <<'EXT'
subjectAltName = IP:127.0.0.1
EXT

openssl req -newkey rsa:2048 -nodes -subj "/CN=test-client-id" \
        -keyout "$WORK_DIR/conf/client-key-tls.pem" \
        -out "$WORK_DIR/conf/client.csr" 2>/dev/null
openssl x509 -req -in "$WORK_DIR/conf/client.csr" -days 2 \
        -CA "$WORK_DIR/conf/ca-cert.pem" -CAkey "$WORK_DIR/conf/ca-key.pem" \
        -CAcreateserial -out "$WORK_DIR/conf/client-cert.pem" 2>/dev/null

stop_nginx() {
    [ -n "$RUNNING_CONF" ] || return 0
    "$NGINX_BIN" -p "$WORK_DIR" -c "$RUNNING_CONF" -s stop 2>/dev/null || true
    RUNNING_CONF=
    sleep 1
}

cleanup() {
    [ -n "$IDP_PID" ] && kill "$IDP_PID" 2>/dev/null || true
    [ -n "$IDP_B_PID" ] && kill "$IDP_B_PID" 2>/dev/null || true
    [ -n "$IDP_M_PID" ] && kill "$IDP_M_PID" 2>/dev/null || true
    [ -n "$REDIS_PID" ] && kill "$REDIS_PID" 2>/dev/null || true
    [ -n "$SENTINEL_PID" ] && kill "$SENTINEL_PID" 2>/dev/null || true
    for port in 7000 7001 7002; do
        redis-cli -p $port shutdown nosave 2>/dev/null || true
    done
    stop_nginx
}
trap cleanup EXIT INT TERM

echo "==> checking the configuration"
"$NGINX_BIN" -p "$WORK_DIR" -c "$WORK_DIR/conf/nginx-store.conf" -t
"$NGINX_BIN" -p "$WORK_DIR" -c "$WORK_DIR/conf/nginx-cookie.conf" -t
"$NGINX_BIN" -p "$WORK_DIR" -c "$WORK_DIR/conf/nginx-redis.conf" -t
"$NGINX_BIN" -p "$WORK_DIR" -c "$WORK_DIR/conf/nginx-sentinel.conf" -t
"$NGINX_BIN" -p "$WORK_DIR" -c "$WORK_DIR/conf/nginx-cluster.conf" -t

echo "==> starting redis"
redis-server --port 6399 --save '' --appendonly no --dir "$WORK_DIR" \
             --logfile "$WORK_DIR/logs/redis.log" --daemonize no &
REDIS_PID=$!

i=0
while [ $i -lt 50 ]; do
    if redis-cli -p 6399 ping >/dev/null 2>&1; then break; fi
    i=$((i + 1))
    sleep 0.2
done
[ $i -lt 50 ] || { echo "redis did not start" >&2; cat "$WORK_DIR/logs/redis.log"; exit 1; }

echo "==> starting redis-sentinel"
mkdir -p "$WORK_DIR/sentinel"
cat > "$WORK_DIR/sentinel/sentinel.conf" <<SENTINEL
port 26399
dir $WORK_DIR/sentinel
sentinel monitor oidc-test 127.0.0.1 6399 1
sentinel down-after-milliseconds oidc-test 2000
sentinel failover-timeout oidc-test 5000
SENTINEL
redis-server "$WORK_DIR/sentinel/sentinel.conf" --sentinel \
             --logfile "$WORK_DIR/logs/sentinel.log" &
SENTINEL_PID=$!

i=0
while [ $i -lt 50 ]; do
    if redis-cli -p 26399 sentinel get-master-addr-by-name oidc-test 2>/dev/null \
       | grep -q 6399; then break; fi
    i=$((i + 1))
    sleep 0.2
done
[ $i -lt 50 ] || { echo "redis-sentinel did not start" >&2; \
                   cat "$WORK_DIR/logs/sentinel.log"; exit 1; }

echo "==> starting the redis cluster"
for port in 7000 7001 7002; do
    mkdir -p "$WORK_DIR/cluster-$port"
    redis-server --port $port --cluster-enabled yes \
                 --cluster-config-file "nodes.conf" \
                 --cluster-node-timeout 2000 \
                 --save '' --appendonly no --dir "$WORK_DIR/cluster-$port" \
                 --logfile "$WORK_DIR/logs/cluster-$port.log" --daemonize no &
done

i=0
while [ $i -lt 50 ]; do
    if redis-cli -p 7000 ping >/dev/null 2>&1 \
       && redis-cli -p 7001 ping >/dev/null 2>&1 \
       && redis-cli -p 7002 ping >/dev/null 2>&1; then break; fi
    i=$((i + 1))
    sleep 0.2
done
[ $i -lt 50 ] || { echo "the redis cluster nodes did not start" >&2; exit 1; }

redis-cli --cluster create 127.0.0.1:7000 127.0.0.1:7001 127.0.0.1:7002 \
          --cluster-yes > "$WORK_DIR/logs/cluster-create.log" 2>&1

i=0
while [ $i -lt 100 ]; do
    if redis-cli -p 7000 cluster info 2>/dev/null | grep -q "cluster_state:ok"; then
        break
    fi
    i=$((i + 1))
    sleep 0.2
done
[ $i -lt 100 ] || { echo "the redis cluster did not form" >&2; \
                    cat "$WORK_DIR/logs/cluster-create.log"; exit 1; }

echo "==> starting the mock IdP"
( cd "$TEST_DIR" \
  && MOCK_IDP_CLIENT_PUBKEY="$WORK_DIR/conf/client-pub.pem" \
     node mock-idp.js > "$WORK_DIR/logs/idp.log" 2>&1 ) &
IDP_PID=$!

i=0
while [ $i -lt 50 ]; do
    if curl -fsS http://127.0.0.1:3000/certs >/dev/null 2>&1; then break; fi
    i=$((i + 1))
    sleep 0.2
done
[ $i -lt 50 ] || { echo "the mock IdP did not start" >&2; cat "$WORK_DIR/logs/idp.log"; exit 1; }

echo "==> starting the second mock IdP (tenant-b)"
( cd "$TEST_DIR" \
  && MOCK_IDP_PORT=3001 \
     MOCK_IDP_ISSUER=http://127.0.0.1:3001 \
     MOCK_IDP_CLIENT_ID=tenant-b-client \
     MOCK_IDP_CLIENT_SECRET=tenant-b-secret \
     MOCK_IDP_ALG=ES256 \
     node mock-idp.js > "$WORK_DIR/logs/idp-b.log" 2>&1 ) &
IDP_B_PID=$!

i=0
while [ $i -lt 50 ]; do
    if curl -fsS http://127.0.0.1:3001/certs >/dev/null 2>&1; then break; fi
    i=$((i + 1))
    sleep 0.2
done
[ $i -lt 50 ] || { echo "the second mock IdP did not start" >&2; cat "$WORK_DIR/logs/idp-b.log"; exit 1; }

echo "==> starting the mTLS mock IdP"
( cd "$TEST_DIR" \
  && MOCK_IDP_PORT=3002 \
     MOCK_IDP_ISSUER=https://127.0.0.1:3002 \
     MOCK_IDP_TLS_CERT="$WORK_DIR/conf/idp-cert.pem" \
     MOCK_IDP_TLS_KEY="$WORK_DIR/conf/idp-key.pem" \
     MOCK_IDP_TLS_CA="$WORK_DIR/conf/ca-cert.pem" \
     node mock-idp.js > "$WORK_DIR/logs/idp-mtls.log" 2>&1 ) &
IDP_M_PID=$!

i=0
while [ $i -lt 50 ]; do
    if curl -fsSk https://127.0.0.1:3002/certs >/dev/null 2>&1; then break; fi
    i=$((i + 1))
    sleep 0.2
done
[ $i -lt 50 ] || { echo "the mTLS mock IdP did not start" >&2; cat "$WORK_DIR/logs/idp-mtls.log"; exit 1; }

STATUS=0

for MODE in store redis sentinel cluster cookie; do
    redis-cli -p 6399 flushall >/dev/null 2>&1 || true
    for port in 7000 7001 7002; do
        redis-cli -p $port flushall >/dev/null 2>&1 || true
    done
    echo "==> starting NGINX (session mode: $MODE)"
    RUNNING_CONF="$WORK_DIR/conf/nginx-$MODE.conf"
    "$NGINX_BIN" -p "$WORK_DIR" -c "$RUNNING_CONF"

    echo "==> running the Playwright tests (session mode: $MODE)"
    if ! ( cd "$TEST_DIR" \
           && PLAYWRIGHT_CHROMIUM_PATH="$PLAYWRIGHT_CHROMIUM_PATH" \
              OIDC_TEST_MODE="$MODE" npx playwright test ); then
        STATUS=1
    fi

    stop_nginx

    [ $STATUS -eq 0 ] || break
done

if [ $STATUS -ne 0 ]; then
    echo "---- nginx error.log ----"
    tail -50 "$WORK_DIR/logs/error.log" || true
    echo "---- mock idp log ----"
    tail -50 "$WORK_DIR/logs/idp.log" || true
    echo "---- mock idp (tenant-b) log ----"
    tail -50 "$WORK_DIR/logs/idp-b.log" || true
    echo "---- mock idp (mtls) log ----"
    tail -30 "$WORK_DIR/logs/idp-mtls.log" || true
    echo "---- redis log ----"
    tail -20 "$WORK_DIR/logs/redis.log" || true
    echo "---- redis sentinel log ----"
    tail -20 "$WORK_DIR/logs/sentinel.log" || true
fi

exit $STATUS
