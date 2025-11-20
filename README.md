# encript_tool

AES-256-GCM暗号化とArgon2鍵導出を使用したセキュアな暗号化ツール。CLIとGUIの両方のインターフェースを提供します。

## 特徴

- **強力な暗号化**: AES-256-GCM認証付き暗号化
- **安全な鍵導出**: 設定可能なパラメータを持つArgon2パスワードハッシング
- **複数のインターフェース**: コマンドライン（CLI）とグラフィカルユーザーインターフェース（GUI）
- **柔軟な入力**: 文字列またはファイルの暗号化・復号化に対応
- **ストリーミング対応**: 大容量ファイルを効率的に処理するストリーミングモード
- **設定管理**: TOML設定ファイルによるカスタマイズ可能な設定
- **パスワードオプション**: 直接入力、環境変数、対話型プロンプトに対応

## インストール

### ソースからビルド

```bash
# リポジトリをクローン
git clone https://github.com/WatanabeYuito21/encript_tool.git
cd encript_tool

# CLI版をビルド
cargo build --release

# GUI対応版をビルド
cargo build --release --features gui
```

コンパイルされたバイナリは `target/release/encript_tool` に生成されます。

## 使い方

### CLIモード

#### 文字列の暗号化

```bash
# 引数から暗号化
encript_tool encrypt "Hello, World!" -p mypassword

# 標準入力から暗号化
echo "秘密のメッセージ" | encript_tool encrypt -p mypassword

# 環境変数からパスワードを読み取る
export CRYPT_PASSWORD="mypassword"
encript_tool encrypt "Hello, World!" --password-env CRYPT_PASSWORD

# 詳細な処理過程を表示
encript_tool encrypt "Hello, World!" -p mypassword -v
```

#### 文字列の復号化

```bash
# 引数から復号化
encript_tool decrypt "暗号化されたbase64文字列" -p mypassword

# 標準入力から復号化
echo "暗号化されたbase64文字列" | encript_tool decrypt -p mypassword
```

#### ファイルの暗号化

```bash
# 基本的なファイル暗号化
encript_tool encrypt-file input.txt -p mypassword

# 出力ファイルを指定
encript_tool encrypt-file input.txt -o encrypted.enc -p mypassword

# 暗号化後に元ファイルを削除
encript_tool encrypt-file input.txt -p mypassword --delete-original

# 大容量ファイル用のストリーミングモードを使用
encript_tool encrypt-file largefile.zip -p mypassword --streaming
```

#### ファイルの復号化

```bash
# 基本的なファイル復号化
encript_tool decrypt-file encrypted.enc -p mypassword

# 出力ファイルを指定
encript_tool decrypt-file encrypted.enc -o output.txt -p mypassword

# 復号化後に暗号化ファイルを削除
encript_tool decrypt-file encrypted.enc -p mypassword --delete-encrypted

# 大容量ファイル用のストリーミングモードを使用
encript_tool decrypt-file largefile.enc -p mypassword --streaming
```

### GUIモード

GUIアプリケーションを起動：

```bash
# GUIフィーチャーでビルドした場合
encript_tool gui

# または専用のGUIバイナリを実行
encript_tool_gui
```

GUIでは以下の機能を直感的に使用できます：
- 文字列の暗号化・復号化
- ファイルの暗号化・復号化
- 暗号化プロセスのリアルタイム可視化

### 設定管理

```bash
# デフォルト設定ファイルを作成
encript_tool config init

# 現在の設定を表示
encript_tool config show

# 設定ファイルのパスを表示
encript_tool config path

# 設定をデフォルトにリセット
encript_tool config reset

# カスタム設定ファイルを使用
encript_tool --config /path/to/config.toml encrypt "text" -p password
```

## 設定ファイル

設定ファイルは以下の場所に保存されます：
- Linux/macOS: `~/.config/encript_tool/config.toml`
- Windows: `%APPDATA%\encript_tool\config.toml`

設定例：

```toml
version = "1.0"
default_format = "base64"
default_verbose = false
default_password_env = "CRYPT_PASSWORD"

[argon2]
memory_cost = 65536      # メモリ使用量（KB単位、64 MB）
time_cost = 3            # イテレーション回数
parallelism = 4          # 並列スレッド数
```

### Argon2パラメータ

- **memory_cost**: 使用するメモリ量（KiB単位）。値を大きくするとセキュリティが向上しますが、より多くのRAMが必要です
- **time_cost**: イテレーション回数。値を大きくするとセキュリティが向上しますが、処理時間が長くなります
- **parallelism**: 並列スレッド数。CPUのコア数に合わせることを推奨します

## セキュリティ機能

- **AES-256-GCM**: 機密性と完全性の両方を提供する業界標準の認証付き暗号化
- **Argon2**: GPU/ASIC攻撃に耐性のあるメモリハード鍵導出関数
- **ランダムナンス**: 各暗号化で一意の96ビットランダムナンスを使用
- **認証付き暗号化**: 組み込みの完全性検証により改ざんを防止
- **安全な削除**: 暗号化後に元ファイルを削除するオプション

## ビルド

```bash
# CLIのみをビルド
cargo build --release

# GUIを含めてビルド
cargo build --release --features gui

# テストを実行
cargo test

# 詳細ログを有効にして実行
RUST_LOG=debug cargo run -- encrypt "test" -p password -v
```

## 依存関係

主な依存ライブラリ：
- `aes-gcm` - AES-GCM暗号化
- `argon2` - Argon2鍵導出
- `clap` - コマンドライン引数解析
- `eframe` / `egui` - GUIフレームワーク（オプション）
- `base64` - Base64エンコード・デコード

## ライセンス

このプロジェクトはオープンソースです。適切なライセンスファイルを追加してください。

## セキュリティに関する考慮事項

- **パスワードの強度**: 強力で一意なパスワードを使用してください（最低12文字を推奨）
- **鍵の保管**: パスワードを平文やバージョン管理システムに保存しないでください
- **メモリセキュリティ**: 機密データは明示的にメモリから消去されません
- **サイドチャネル**: この実装はサイドチャネル攻撃に対して強化されていません
- **監査状況**: このツールは正式なセキュリティ監査を受けていません

高いセキュリティが求められる本番環境での使用には、以下を検討してください：
- ハードウェアセキュリティモジュール（HSM）の使用
- 追加の鍵管理手法の実装
- セキュリティ監査の実施
- 組織のセキュリティポリシーへの準拠

## コントリビューション

コントリビューションを歓迎します！コードはRustのベストプラクティスに従い、適切なテストを含めてください。

## 謝辞

このツールはRustで構築され、RustCryptoプロジェクトの確立された暗号化ライブラリを活用しています。
