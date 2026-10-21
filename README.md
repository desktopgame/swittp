# swittp

`/switch` をサービス選択画面として予約し、それ以外のパスを選択中のサービスのルートへ中継する、小さなローカル用 HTTP リバースプロキシです。Go 標準ライブラリのみを使います。

例えば `http://127.0.0.1:8787/assets/app.js?v=1` は、選択したサービスが `http://127.0.0.1:3000` なら、その `/assets/app.js?v=1` へ転送されます。上流にサブパス対応を要求しません。

## 起動

Go 1.23 以上が必要です。このプロジェクトは Go 1.27.1 / Windows amd64 で開発しました。

```powershell
cd C:\Users\dot\Work\swittp
Copy-Item config.example.json config.json
# config.json を編集して、信頼できるサービスだけを登録する
go run . -config config.json
```

ブラウザで `http://127.0.0.1:8787/switch` を開き、サービスを選択してください。選択後は `/` に移動します。終了は端末で Ctrl+C。バックエンドは別途利用者が起動するもので、swittp はサービスの起動・停止を行いません。

ビルドして実行する場合:

```powershell
go build -o swittp.exe .
.\swittp.exe -config config.json
```

サンプルの 3000 / 8080 番ポートは例示です。実在するユーザーサービスには接続して検証していません。設定ファイルは Git 管理対象外です。

## 設定と動作

- `listen`: 省略時 `127.0.0.1:8787`。明示的なループバック IP と 1～65535 のポートが必要です。`0.0.0.0` や LAN/Tailscale アドレスでは起動できません。
- `external_origins`: 省略時は空配列でローカル専用。例: `["https://your-device.your-tailnet.ts.net"]`。外側のブラウザ URL の Origin を完全一致で許可します。小文字の `http://` または `https://` とホスト、必要なら非標準ポートを指定します。末尾 `/`、パス、クエリ、フラグメント、ユーザー情報、ワイルドカード、重複 Host は不可。既定ポート（HTTP の `:80`、HTTPS の `:443`）は省略してください。同じ Host に HTTP と HTTPS を同時登録することはできません。
- `services`: `id`、表示用の `name`、転送先の `url`。ID は英数字・ハイフン・アンダースコアの 1～64 文字で、一意にします。クライアントから URL を指定して転送先を追加することはできません。
- URL は `http` / `https` のルートのみ。ユーザー情報、サブパス、クエリ、フラグメントは不可。設定ファイルを編集できる人を信頼する前提です。上流 URL はループバックに限定していませんが、サンプルはループバックのみです。
- HTTP メソッド、本文、エスケープ済みパス、クエリを中継します。転送先の Host を使用し、環境変数の HTTP プロキシは使用しません。
- `/switch` と `/switch/` は管理画面、`POST /switch/select` は選択変更です。`/switch/` 以下はすべて予約し、不明な管理パスは 404 にします。上流が同じパスを使う場合はアクセスできません。`/switchboard` は通常どおり上流に送ります。
- 未選択のブラウザナビゲーション（GET/HEAD で navigate または Accept に text/html）は `/switch` へ 303。それ以外は 409。元のページへの自動復帰は行いません。
- 選択はランダムなセッション ID とアクセスした Origin にひも付け、メモリ内に保持します。`swittp_session` Cookie は HttpOnly、SameSite=Strict、Path=/、Domain 未指定。設定上 HTTPS の外部 Origin では Secure を付けます。ローカルおよび明示設定した HTTP Origin では付けません。別 Origin へのセッション流用は拒否します。同じホストの別ポートでは Cookie 自体を共有するブラウザ仕様のため、複数ポートを使うと再選択が必要になり得ます。セッションは作成から 12 時間、最大 1024 件。再起動で選択は失われます。上流の同名 Set-Cookie は除きます。
- セッション Cookie は上流に送りません。それ以外のアプリ Cookie、Authorization などは通常どおり転送します。
- リクエスト Host は待ち受けアドレス、同じポートの `localhost`、または `external_origins` の Host だけを許可します。Origin がある場合は、その Host に対応した設定上の Origin と完全一致が必要です。別の許可済み Origin であっても使い回せません。cross-site の Fetch Metadata も拒否します。
- 選択変更には POST、同一 Origin ヘッダー、セッション内の CSRF トークンが必要です。外部サイトの CORS アクセスを許可しません。受信した `Forwarded`、`X-Forwarded-*`、`X-Real-IP` は除去します。明示登録した外部 Host では、設定から `X-Forwarded-Host` と `X-Forwarded-Proto` を作り直します。ローカル Host ではこれらを付けません。利用者の IP や認証情報は転送ヘッダーから推測しません。
- 上流に接続できない場合は 502。レスポンスヘッダー待ちは最大 30 秒。SSE は即時フラッシュし、WebSocket は ReverseProxy の Upgrade トンネルを使用します。ストリーミングを妨げる全体の書き込みタイムアウトは設けていません。

## 重要な制約

これは**等しく信頼できるアプリを手元で切り替えるプロトタイプ**です。アプリの隔離、認証基盤、ネットワーク公開向けの製品ではありません。

1. **すべてのアプリが同じブラウザオリジンを共有します。** Cookie、localStorage、IndexedDB、HTTP キャッシュ、Service Worker、ブラウザ権限などが衝突・共有され得ます。上流 Cookie をサーバー側で分離保存する機能はありません。他の上流向け Cookie や Authorization が次のサービスへ送られる可能性もあります。異なる信頼領域、重要なアカウント、秘密情報を扱うアプリを混在させないでください。試用は専用ブラウザプロファイルが適しています。
2. **タブは選択を共有します。** 切り替え後、古いタブの API 呼び出しやフォーム送信も新しい上流へ届き得ます。進行中の HTTP リクエスト、SSE、WebSocket は元の上流への接続を続けます。切り替え時に他のタブを閉じるか再読み込みしてください。
3. **CSRF 対策は同一オリジンの上流アプリから管理画面を守れません。** 上流の JavaScript は管理画面を読み、選択変更できます。HttpOnly も、この信頼境界を作るものではありません。ローカルの他プロセスからの利用も認証していません。
4. レスポンスに `Cache-Control: no-store` を指定し、上流へ `If-None-Match` / `If-Modified-Since` を送らないことで以前の上流のキャッシュ再利用を抑制します。ただし既存キャッシュ、独自の Cache API、Service Worker の横取りは解消できません。**ブラウザデータの自動削除はしません。** 上流からの `Clear-Site-Data` も除去します。
5. 絶対 URL、外部向けリダイレクト、Cookie の Domain / Path、上流が返す CSP、Origin 検証、OAuth コールバックなどは書き換えません。上流にはプロキシの Origin が届くため、許可 Origin の設定が必要なことがあります。上流の専用 URL に移動してしまう場合もあります。「どのサービスでも完全に透過的に切り替えられる」とは保証しません。
6. 外部 Origin の登録は認証ではありません。外側のプロキシには、設定した HTTPS の終端、元の Host の保持、利用者のアクセス制御を任せます。swittp は受信ヘッダーから TLS や Tailscale 利用者を認証しません。ループバックへ接続できるプロセスは Host を指定できるため、ローカルプロセスも信頼する前提です。認証されていないインターネット公開や Funnel は想定していません。CSRF があっても公開用の認証基盤が完成したことにはなりません。

## Tailscale Serve で使う場合

Tailscale Serve の HTTPS 終端から、元の Host を保ったまま `http://127.0.0.1:8787` に中継する構成に対応します。Serve は tailnet 内で共有する機能です。利用できる人を既存の tailnet アクセス制御で限定してください。詳細は [Serve の公式説明](https://tailscale.com/docs/features/tailscale-serve) を参照してください。

1. 未作成の場合だけ `config.tailscale.example.json` を `config.json` にコピーします。既存の設定は上書きせず編集してください。
2. `external_origins` の `https://your-device.your-tailnet.ts.net` を、実際にブラウザで開く HTTPS Origin に置き換えます。`/switch` や末尾 `/` は含めません。上流サービスも自分の環境に合わせます。
3. 修正版をビルドして swittp を起動します。更新時は利用者が既存プロセスを終了してから起動してください。

```powershell
go build -o swittp.exe .
.\swittp.exe -config config.json
```

別端末での Serve 設定例（既に設定済みなら重ねて実行する必要はありません）:

```powershell
tailscale serve --bg 8787
```

ブラウザで `https://実際の端末名.実際のtailnet.ts.net/switch` を開きます。swittp 全体をルートに置くため `--set-path /switch` は使いません。`listen` を Tailscale IP に変更する必要はありません。Host の書き換えや Origin の削除で検証を回避しないでください。

上流には上流自身の Host と、ブラウザの元の Origin が届きます。外部 HTTPS の情報は上記の2つの転送ヘッダーで伝えますが、それを利用するかは上流アプリ次第です。上流側にも正しい外部 URL・信頼するプロキシ・許可 Origin の設定が必要な場合があります。Origin、Location、HTML 内の URL は自動で書き換えません。

開発時の検証は HTTP ループバックの模擬プロキシで外部 Host/Origin を渡す統合テストです。実際の Tailscale やブラウザの TLS・Cookie 挙動を検証したものではありません。利用者の実ホスト名と実行時設定は変更していません。

## 検証

```powershell
gofmt -w main.go main_test.go
go test ./...
go test -race ./...
go vet ./...
go build ./...
```

テストは `httptest` による一時的なループバック上流だけを使います。ルーティング、パスと生クエリ、選択とセッション分離、期限、並行操作、不正 ID、Host/Origin/CSRF、Cookie と転送ヘッダー、上流エラー、SSE の初回データ到着、WebSocket の 101 と双方向フレームを確認します。

Windows の race 検証には CGO と対応 C コンパイラが必要です。利用できない環境では通常テストとビルドを実行し、race 未実行と区別してください。新しいツールの自動インストールはしません。

初回の ThinkPad 上の検証結果:

- `gofmt`、`go test -count=1 ./...`（全 9 テストとサブテスト）、`go vet ./...`、`go build -o swittp.exe .` は成功。
- `go test -race ./...` は検証未完了。標準状態は CGO 無効。既存 clang 18 は Windows リンカーの COMDAT エラー、既存 Zig 0.16 は `WaitOnAddress` などの未解決シンボルでリンク失敗。`-lsynchronization` を補っても、そのライブラリが同ツールチェーンにありませんでした。race テスト本体は実行できていません。
- Go / OS の永続設定変更やツールの追加インストールはしていません。

## 管理画面の Origin エラーの修正

管理画面の `Referrer-Policy` は `same-origin` とします。以前の `no-referrer` は、通常のフォーム POST の `Origin` を `null` にするため、正しいセッションと CSRF トークンがあっても選択操作が拒否される原因になります。POST 必須、Origin 検証、CSRF トークン検証は維持しています。

この回帰テストは HTTP ヘッダーを明示して送るモックテストです。拒否された POST が選択を変更せず、正常な POST が 303 を返して続くルート GET が上流に届くことを確認しています。実ブラウザでの再現確認は未完了です。後続の外部 Host 対応は `external_origins` で明示設定します。
