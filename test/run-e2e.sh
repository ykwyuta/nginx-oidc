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
      && ./configure --with-compat --add-dynamic-module="$REPO_DIR" >/dev/null \
      && make -j"$(nproc 2>/dev/null || echo 2)" >/dev/null )
    NGINX_BIN="$NGINX_SRC/objs/nginx"
    OIDC_MODULE="$NGINX_SRC/objs/ngx_http_oidc_module.so"
    MIME_TYPES="$NGINX_SRC/conf/mime.types"
fi

[ -n "$NGINX_BIN" ]    || { echo "NGINX_SRC or NGINX_BIN must be set" >&2; exit 1; }
[ -n "$OIDC_MODULE" ]  || { echo "NGINX_SRC or OIDC_MODULE must be set" >&2; exit 1; }
MIME_TYPES="${MIME_TYPES:-/etc/nginx/mime.types}"

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR/conf" "$WORK_DIR/logs"
cp "$MIME_TYPES" "$WORK_DIR/conf/mime.types"

sed "s#^load_module .*#load_module $OIDC_MODULE;#" \
    "$TEST_DIR/nginx.conf" > "$WORK_DIR/conf/nginx-store.conf"

# セッションストアを無効にした（Cookie にクレームを載せる）構成も用意する
sed "s|^\( *\)oidc_session_store |\1# oidc_session_store |" \
    "$WORK_DIR/conf/nginx-store.conf" > "$WORK_DIR/conf/nginx-cookie.conf"

stop_nginx() {
    [ -n "$RUNNING_CONF" ] || return 0
    "$NGINX_BIN" -p "$WORK_DIR" -c "$RUNNING_CONF" -s stop 2>/dev/null || true
    RUNNING_CONF=
    sleep 1
}

cleanup() {
    [ -n "$IDP_PID" ] && kill "$IDP_PID" 2>/dev/null || true
    [ -n "$IDP_B_PID" ] && kill "$IDP_B_PID" 2>/dev/null || true
    stop_nginx
}
trap cleanup EXIT INT TERM

echo "==> checking the configuration"
"$NGINX_BIN" -p "$WORK_DIR" -c "$WORK_DIR/conf/nginx-store.conf" -t
"$NGINX_BIN" -p "$WORK_DIR" -c "$WORK_DIR/conf/nginx-cookie.conf" -t

echo "==> starting the mock IdP"
( cd "$TEST_DIR" && node mock-idp.js > "$WORK_DIR/logs/idp.log" 2>&1 ) &
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

STATUS=0

for MODE in store cookie; do
    echo "==> starting NGINX (session mode: $MODE)"
    RUNNING_CONF="$WORK_DIR/conf/nginx-$MODE.conf"
    "$NGINX_BIN" -p "$WORK_DIR" -c "$RUNNING_CONF"

    echo "==> running the Playwright tests (session mode: $MODE)"
    if ! ( cd "$TEST_DIR" && OIDC_TEST_MODE="$MODE" npx playwright test ); then
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
fi

exit $STATUS
