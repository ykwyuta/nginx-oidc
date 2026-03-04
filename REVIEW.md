# nginx-oidc モジュール コードレビュー

> 対象ファイル: `ngx_http_oidc_module.c`（1,116 行）
> レビュー日: 2026-03-04

---

## 概要

`ngx_http_oidc_module` は NGINX Open Source に OpenID Connect (OIDC) 認証を追加する C 言語製ダイナミックモジュールです。NGINX Plus 専用だった OIDC 連携機能を OSS 版で実現することを目的としています。

外部ライブラリとして **Jansson**（JSON パース）、**OpenSSL**（乱数生成・HMAC-SHA256）、**libjwt**（JWT デコード・署名検証）の 3 つに依存しています。

---

## データ構造

```
ngx_http_oidc_main_conf_t        ← プロセス全体で共有される設定・キャッシュ
ngx_http_oidc_loc_conf_t         ← nginx.conf のロケーション単位ディレクティブ
ngx_http_oidc_ctx_t              ← リクエストごとの状態管理
ngx_http_oidc_provider_metadata_t ← IdP ディスカバリで取得したエンドポイント情報
ngx_http_oidc_claims_t           ← JWT から取り出したクレーム（sub / email / name）
```

| 構造体 | ライフタイム | 用途 |
|--------|------------|------|
| `main_conf` | ワーカープロセス全体（`ngx_cycle->pool`） | メタデータキャッシュ・HMAC 鍵 |
| `loc_conf` | 設定ファイル読み込み時に確定 | ディレクティブ値 |
| `ctx` | リクエストプール（`r->pool`） | 認証ステートマシン |
| `metadata` | `ngx_cycle->pool`（永続） | エンドポイント URL |

---

## 設定ディレクティブ

| ディレクティブ | 型 | スコープ | 説明 |
|--------------|-----|---------|------|
| `auth_oidc` | flag（on/off） | http/server/location | OIDC 認証の有効化 |
| `oidc_provider` | 文字列 | http/server/location | IdP のベース URL |
| `oidc_client_id` | 文字列 | http/server/location | OAuth 2.0 クライアント ID |
| `oidc_client_secret` | 文字列 | http/server/location | OAuth 2.0 クライアントシークレット |
| `oidc_redirect_uri` | 文字列 | http/server/location | OAuth 2.0 リダイレクト URI（フル URL またはパスのみ） |

---

## 処理の全体フロー

```
[NGINX 起動]
    │
    └─ ngx_http_oidc_init()
         ├─ NGINX 変数を登録: $oidc_claim_sub / $oidc_claim_email / $oidc_claim_name
         └─ ACCESS_PHASE に ngx_http_oidc_access_handler を登録

[HTTP リクエスト受信]
    │
    └─ ngx_http_oidc_access_handler()                     ← メインハンドラ
         │
         ├─ auth_oidc が off または未設定 → NGX_DECLINED（素通り）
         ├─ サブリクエスト自身 (r != r->main) → NGX_DECLINED（ループ防止）
         │
         ├─ ctx 生成または取得（r->pool に確保）
         ├─ mcf->metadata があれば ctx->metadata にコピー（キャッシュ利用）
         │
         ├─ [A] ctx->metadata == NULL の場合
         │    ├─ discovery_attempted が立っている → 500 エラー（同一リクエスト内でのリトライ防止）
         │    └─ ngx_http_oidc_start_discovery()
         │         ├─ /_oidc_discovery?url=<provider>/.well-known/openid-configuration
         │         │   へサブリクエスト発行（NGX_HTTP_SUBREQUEST_IN_MEMORY）
         │         ├─ ctx->discovery_attempted = 1
         │         └─ NGX_AGAIN を返す（非同期待機）
         │               │
         │               ▼ サブリクエスト完了コールバック
         │          ngx_http_oidc_discovery_handler()
         │               ├─ HTTP ステータス確認（200 以外はエラー）
         │               ├─ upstream バッファからレスポンスボディ取得
         │               ├─ ngx_http_oidc_parse_discovery_json()
         │               │    ├─ JSON パース（Jansson）
         │               │    └─ authorization_endpoint / token_endpoint / jwks_uri を抽出
         │               │       → mcf->metadata に格納（ngx_cycle->pool）
         │               ├─ ctx->metadata = mcf->metadata
         │               └─ r->parent->write_event_handler = ngx_http_core_run_phases
         │                  （親リクエストを再開）
         │
         └─ [B] ctx->metadata != NULL の場合
              │
              ├─ redirect_uri からパス部分を抽出（http:// / https:// プレフィックスを除去）
              │
              ├─ [B-1] リクエスト URI == redirect_uri のパス（IdP からのコールバック）
              │    ├─ ctx->token_attempted が立っている → NGX_DECLINED（後処理フェーズへ）
              │    ├─ クエリパラメータ "code" を取得
              │    └─ ngx_http_oidc_start_token_request()
              │         ├─ code / client_id / client_secret / redirect_uri を URL エンコード
              │         ├─ /_oidc_token へサブリクエスト発行（POST ボディとして渡す）
              │         ├─ ctx->token_attempted = 1
              │         └─ NGX_AGAIN を返す（非同期待機）
              │               │
              │               ▼ サブリクエスト完了コールバック
              │          ngx_http_oidc_token_handler()
              │               ├─ HTTP ステータス確認
              │               ├─ JSON パースして id_token / access_token を抽出
              │               ├─ ctx->id_token に id_token を格納（r->parent->pool）
              │               └─ ngx_http_oidc_start_jwks_request(r->parent)
              │                    ├─ /_oidc_jwks?url=<jwks_uri> へサブリクエスト発行
              │                    └─ NGX_OK を返す（この時点では NGX_AGAIN 不要）
              │                          │
              │                          ▼ サブリクエスト完了コールバック
              │                     ngx_http_oidc_jwks_handler()
              │                          ├─ JWKS JSON レスポンスを取得
              │                          ├─ jwt_decode() で JWT 署名検証（libjwt）
              │                          ├─ exp クレーム確認（有効期限チェック）
              │                          ├─ Cookie から oidc_nonce を取得
              │                          ├─ JWT の nonce クレームと Cookie を比較（リプレイ攻撃防止）
              │                          ├─ sub / email / name クレームを ctx->claims に格納
              │                          ├─ HMAC-SHA256 でセッション Cookie を生成
              │                          │   形式: oidc_auth=<HEX(HMAC)><sub>:<timestamp>
              │                          ├─ Set-Cookie: oidc_auth=... (HttpOnly; Path=/)
              │                          ├─ Set-Cookie: oidc_state= (削除)
              │                          ├─ Set-Cookie: oidc_nonce= (削除)
              │                          ├─ Location: / (302 リダイレクト)
              │                          └─ r->parent->write_event_handler = ngx_http_core_run_phases
              │
              └─ [B-2] コールバック以外のパス（保護対象リソース）
                   ├─ Cookie ヘッダを走査して "oidc_auth=" を探索（境界チェック付き）
                   ├─ Cookie が存在し len > 64 の場合
                   │    ├─ mcf->hmac_secret で HMAC-SHA256 を再計算
                   │    ├─ Cookie の先頭 64 文字（16 進 MAC）と比較
                   │    └─ 一致すれば authenticated = 1、sub をペイロードから抽出
                   │
                   ├─ authenticated == 0 の場合
                   │    └─ ngx_http_oidc_redirect_to_idp()
                   │         ├─ RAND_bytes で 32 バイトの state / nonce を生成（16 進 64 文字）
                   │         ├─ authorization_endpoint への 302 リダイレクト URL を構築
                   │         │   ?response_type=code&scope=openid&client_id=...&redirect_uri=...
                   │         │   &state=...&nonce=...
                   │         ├─ Set-Cookie: oidc_state=... (HttpOnly)
                   │         ├─ Set-Cookie: oidc_nonce=... (HttpOnly)
                   │         └─ NGX_HTTP_MOVED_TEMPORARILY を返す（302）
                   │
                   └─ authenticated == 1 の場合 → NGX_DECLINED（バックエンドへ）

[NGINX 変数 get_handler（各リクエストで呼び出し）]
    ├─ $oidc_claim_sub   → ctx->claims.sub
    ├─ $oidc_claim_email → ctx->claims.email
    └─ $oidc_claim_name  → ctx->claims.name
```

---

## セキュリティ実装の概要

### state / nonce のランダム生成

```c
// ngx_http_oidc_redirect_to_idp(), L722
u_char state_buf[32];
if (RAND_bytes(state_buf, 32) != 1) { ... }
ngx_hex_dump(state_hex, state_buf, 32);
```

OpenSSL の `RAND_bytes` で暗号論的乱数 32 バイトを生成し、16 進 64 文字に変換して使用しています。

### HMAC-SHA256 セッション Cookie

```c
// ngx_http_oidc_jwks_handler(), L553
HMAC(EVP_sha256(), mcf->hmac_secret, sizeof(mcf->hmac_secret),
     payload.data, payload.len, mac, &mac_len);
```

Cookie 形式: `oidc_auth=<MAC(64 hex)><sub>:<timestamp>`
Cookie 検証時は MAC を再計算して比較し、改ざん検知を行います。

### JWT 検証フロー

libjwt の `jwt_decode()` に JWKS の JSON データを直接渡すことで、署名アルゴリズムと鍵の照合を行います。その後、`exp`（有効期限）と `nonce`（リプレイ防止）を手動で確認しています。

---

## 改善点

現在の実装は Phase 4（JWT 検証・Cookie 発行）まで完了しており、以前のレビューで指摘された多くの問題（ハードコードされた state/nonce、Cookie の存在確認のみの認証、JWT 未検証）は解消されています。以下は現時点で残存する問題です。

---

### 🔴 重大（セキュリティ）

#### 1. state パラメータの検証が未実装（CSRF 防止が不完全）

```c
// ngx_http_oidc_access_handler(), L897-902
if (ngx_http_arg(r, code_key.data, code_key.len, &code_value) == NGX_OK) {
    return ngx_http_oidc_start_token_request(r, conf, &code_value);
}
```

IdP からのコールバックで `code` パラメータは取得していますが、同時に返ってくる `state` パラメータを `oidc_state` Cookie の値と比較していません。攻撃者が悪意ある `code` を含む URL へユーザーを誘導する CSRF 攻撃が成立します。

**対策**: コールバック処理の冒頭で `ngx_http_arg(r, "state", ...)` を取得し、`oidc_state` Cookie と一致するか確認する必要があります。

---

#### 2. HMAC 鍵がワーカープロセス間で共有されない

```c
// ngx_http_oidc_jwks_handler(), L533-537
if (!mcf->secret_initialized) {
    if (RAND_bytes(mcf->hmac_secret, sizeof(mcf->hmac_secret)) == 1) {
        mcf->secret_initialized = 1;
    }
}
```

`mcf->hmac_secret` は各ワーカープロセスが独自に生成します。ワーカー 1 が発行したセッション Cookie はワーカー 2 では検証に失敗し、ユーザーが再認証を求められます。また NGINX リロード後も Cookie は無効になります。

**対策**: `ngx_shared_memory_add` を使って共有メモリゾーンに鍵を格納するか、起動時に設定ファイルから鍵を読み込む仕組みが必要です。

---

#### 3. JWT 検証失敗時にリクエストが素通りする

```c
// ngx_http_oidc_jwks_handler(), L617-619
if (r->parent) {
    r->parent->write_event_handler = ngx_http_core_run_phases;
}
return NGX_OK;
```

nonce 不一致や JWT の署名検証失敗でも、最終的に親リクエストが再開されます。親リクエストが再開されると `ctx->token_attempted == 1` のため `NGX_DECLINED`（L891）が返り、認証なしでバックエンドへ到達します。

**対策**: 検証失敗時は親リクエストに `NGX_HTTP_UNAUTHORIZED` などのエラーレスポンスを返す必要があります。`r->parent` に対して `ngx_http_finalize_request(r->parent, NGX_HTTP_FORBIDDEN)` を呼ぶ等の処理が必要です。

---

### 🟠 重要（設計上の問題）

#### 4. 後続リクエストで `$oidc_claim_email` / `$oidc_claim_name` が常に空

セッション Cookie には `sub` とタイムスタンプのみが格納されます。Cookie 検証後に抽出できるのは `sub` のみで（L970-978）、`email` と `name` は初回認証時のフロー（JWKS コールバック）でしか取得できません。

```c
// ngx_http_oidc_access_handler(), L970-978
u_char *colon = (u_char *)ngx_strchr(payload, ':');
if (colon) {
    ctx->claims.sub.len = colon - payload;
    // email, name は取り出せない
}
```

Cookie に `sub` 以外のクレームを含める、または UserInfo エンドポイントを呼び出すなどの仕組みが必要です。

---

#### 5. 認証後のリダイレクト先が常に `/` に固定

```c
// ngx_http_oidc_jwks_handler(), L600
ngx_str_set(&location->value, "/");
```

ユーザーが `/dashboard` にアクセスして認証フローに入っても、認証完了後は常にルート `/` に戻されます。元の URL を Cookie や state パラメータに保存して、認証後に復元する必要があります。

---

#### 6. メタデータの有効期限が実装されていない

```c
// ngx_http_oidc_main_conf_t
time_t discovery_expires;  // フィールドは存在するが...

// ngx_http_oidc_access_handler(), L849
if (mcf && mcf->metadata != NULL) {
    ctx->metadata = mcf->metadata;  // 有効期限チェックなし
}
```

`discovery_expires` フィールドは定義されていますが、値の設定も参照もされていません。IdP のエンドポイントが変更されても NGINX 再起動まで古いメタデータが使われ続けます。

---

#### 7. `ngx_http_oidc_token_handler` のエラーパスで親リクエストが適切にエラー終了しない

```c
// ngx_http_oidc_token_handler(), L369-374
if (r->parent) {
    r->parent->write_event_handler = ngx_http_core_run_phases;
}
return NGX_OK;
```

id_token が取得できなかった場合など、エラー時も親リクエストを再開してしまいます。再開後 `ctx->token_attempted == 1` が立っているため `NGX_DECLINED` が返り、認証なしでバックエンドに到達します。

---

### 🟡 軽微（コード品質）

#### 8. クレーム文字列の NULL 終端が欠如

```c
// ngx_http_oidc_jwks_handler(), L515-517
ctx->claims.sub.len = ngx_strlen(sub);
ctx->claims.sub.data = ngx_palloc(r->parent->pool, ctx->claims.sub.len); // +1 なし
ngx_memcpy(ctx->claims.sub.data, sub, ctx->claims.sub.len);
```

`email`、`name` も同様。`ngx_str_t` として長さ付きで扱う限り問題はありませんが、C 文字列として渡す可能性のある関数（`ngx_strlen` 等）が呼ばれた場合に未定義動作になります。`ngx_palloc(pool, len + 1)` としてゼロバイトを付与するのが NGINX の慣習です。

---

#### 9. Cookie 削除に `SameSite` 属性がない

```c
// ngx_http_oidc_jwks_handler(), L583
ngx_str_set(&clear_state->value,
    "oidc_state=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/");
```

発行時（認証開始時）の Cookie に `SameSite=Lax` または `SameSite=None; Secure` が設定されていないため、クロスサイトリクエストでの Cookie 送信挙動がブラウザ依存になります。特に `oidc_auth` セッション Cookie に `SameSite=Lax` を付けることが推奨されます。

---

#### 10. ディスカバリ JSON でフィールドが取得できなかった場合のチェックがない

```c
// ngx_http_oidc_parse_discovery_json(), L184-215
json_t *auth_end = json_object_get(root, "authorization_endpoint");
if (json_is_string(auth_end)) {
    // 取得できた場合のみコピー
}
// 取得できなかった場合 metadata フィールドは len=0 のまま
```

必須フィールド（`authorization_endpoint`, `token_endpoint`, `jwks_uri`）が JSON に含まれていなくても `NGX_OK` が返ります。後続の `ngx_http_oidc_redirect_to_idp` で `auth_endpoint->len == 0` チェック（L734）があるため 500 エラーにはなりますが、エラーの発生箇所が分かりにくくなっています。JSON パース関数内で必須フィールドの有無を検証すべきです。

---

#### 11. `ngx_http_oidc_start_jwks_request` が `NGX_OK` を返す設計の不整合

```c
// ngx_http_oidc_token_handler(), L354
return ngx_http_oidc_start_jwks_request(r->parent);
```

`ngx_http_oidc_start_discovery` と `ngx_http_oidc_start_token_request` は `NGX_AGAIN` を返して非同期待機を示しますが、`ngx_http_oidc_start_jwks_request` は `NGX_OK` を返します。これはトークンハンドラがコールバック内で呼ばれる（親リクエストはすでに停止中）という違いによるものですが、コードの一貫性が低下しています。コメントによる説明が必要です。

---

## 実装フェーズの現状まとめ

| フェーズ | 内容 | 状態 |
|---------|------|------|
| Phase 1 | ディレクティブ定義・設定パース | ✅ 完了 |
| Phase 2 | OIDC Discovery（非同期 HTTP） | ✅ 完了 |
| Phase 3 | 認証フロー・トークン交換 | ✅ 完了 |
| Phase 4 | JWT 署名検証・Cookie 発行 | ✅ 完了（ただし上記の問題あり） |
| Phase 5 | テスト・最適化・共有メモリキャッシュ | ❌ 未実装 |

---

## まとめ

前回のレビュー時点と比べて実装が大きく前進しており、以下の重要な問題が解消されています。

- ✅ `state` / `nonce` のランダム生成（`RAND_bytes` 使用）
- ✅ JWT 署名検証・有効期限チェック・nonce 検証（Phase 4 完了）
- ✅ HMAC-SHA256 署名付きセッション Cookie の発行と検証
- ✅ `auth_oidc` に `ngx_flag_t` を使用（型安全な on/off 判定）
- ✅ メタデータのプロセスレベルキャッシュ（`ngx_cycle->pool` 使用）
- ✅ `redirect_uri` のフル URL / パス両対応

ただし**現状ではまだ本番環境での使用は推奨できません**。優先度の高い対応事項は以下の通りです。

1. **`state` パラメータの検証実装**（CSRF 防止の完成）
2. **JWT/トークン検証失敗時の適切なエラーレスポンス**（認証バイパス防止）
3. **HMAC 鍵の共有メモリへの格納**（マルチワーカー対応）
4. **認証後リダイレクト先の保存・復元**（UX 改善）
5. **`$oidc_claim_email` / `$oidc_claim_name` の後続リクエストへの対応**
