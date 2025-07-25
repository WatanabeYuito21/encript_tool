use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::{Context, Result, anyhow};
use argon2::Argon2;
use base64::{Engine as _, engine::general_purpose};
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
};

/// 設定ファイルの構造
#[derive(Debug, Serialize, Deserialize)]
struct Config {
    /// デフォルトの出力形式
    pub default_format: OutputFormat,
    /// 詳細出力をデフォルトで有効にするか
    pub default_verbose: bool,
    /// デフォルトの環境変数名
    pub default_password_env: Option<String>,
    /// 設定ファイルのバージョン
    pub version: String,
    /// Argon2設定
    pub argon2: Argon2Config,
}

#[derive(Debug, Serialize, Deserialize)]
struct Argon2Config {
    /// メモリ使用量 (KB)
    pub memory_cost: u32,
    /// 時間コスト(繰り返し回数)
    pub time_cost: u32,
    /// 並列度
    pub parallelism: u32,
}

impl Default for Argon2Config {
    fn default() -> Self {
        Self {
            memory_cost: 65536, // 64MB
            time_cost: 3,       // 3回繰り返し
            parallelism: 4,     // 4並列
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
enum OutputFormat {
    Base64,
    Hex,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            default_format: OutputFormat::Base64,
            default_verbose: false,
            default_password_env: Some("MYCRYPT_PASSWORD".to_string()),
            version: "2.0".to_string(),
            argon2: Argon2Config::default(),
        }
    }
}

/// シンプルな文字列暗号化ツール
#[derive(Parser)]
#[command(name = "mycrypt")]
#[command(about = "A simple string encryption tool using AES-GCM")]
#[command(version = "0.1.0")]
#[command(long_about = "このツールはAES-GCM暗号化を使用して文字列を安全に暗号化・復号化します。")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// 設定ファイルのパスを指定
    #[arg(long, global = true)]
    config: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// 文字列を暗号化する
    Encrypt {
        /// 暗号化するテキスト（指定しない場合は標準入力から読み取り）
        text: Option<String>,

        /// 暗号化用のパスワード
        #[arg(short, long)]
        password: Option<String>,

        /// 環境変数からパスワードを読み取る
        #[arg(long)]
        password_env: Option<String>,

        /// 詳細な処理過程を表示
        #[arg(short, long)]
        verbose: bool,

        /// 改行を出力しない
        #[arg(short, long)]
        no_newline: bool,
    },
    /// 暗号化された文字列を復号化する
    Decrypt {
        /// 復号化する暗号文（指定しない場合は標準入力から読み取り）
        text: Option<String>,

        /// 復号化用のパスワード
        #[arg(short, long)]
        password: Option<String>,

        /// 環境変数からパスワードを読み取る
        #[arg(long)]
        password_env: Option<String>,

        /// 詳細な処理過程を表示
        #[arg(short, long)]
        verbose: bool,

        /// 改行を出力しない
        #[arg(short, long)]
        no_newline: bool,
    },
    /// ファイルを暗号化する
    EncryptFile {
        /// 暗号化するファイルパス
        input: PathBuf,

        /// 出力ファイルパス(指定しない場合は 元ファイル名.enc)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// 暗号化用のパスワード
        #[arg(short, long)]
        password: Option<String>,

        /// 環境変数からパスワードを読み取る
        #[arg(long)]
        password_env: Option<String>,

        /// 詳細処理過程表示
        #[arg(short, long)]
        verbose: bool,

        /// 暗号化後に元ファイルを削除
        #[arg(long)]
        delete_original: bool,

        /// ストリーミング処理を使用（大容量ファイル用）
        #[arg(long)]
        streaming: bool,
    },
    /// 暗号化されたファイルを複合化する
    DecryptFile {
        /// 複合化するファイルのパス
        input: PathBuf,

        /// 出力ファイルのパス(指定しない場合は自動決定)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// 複合化用のパスワード
        #[arg(short, long)]
        password: Option<String>,

        /// 環境変数からパスワードを読み取る
        #[arg(long)]
        password_env: Option<String>,

        /// 詳細な処理過程を表示
        #[arg(short, long)]
        verbose: bool,

        /// 複合化後に暗号化ファイルを削除
        #[arg(long)]
        delete_encrypted: bool,

        /// ストリーミング処理を使用（大容量ファイル用）
        #[arg(long)]
        streaming: bool,
    },
    /// 設定ファイルを管理する
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// デフォルト設定ファイルを作成
    Init,
    /// 現在の設定を表示
    Show,
    /// 設定ファイルのパスを表示
    Path,
    /// 設定ファイルを削除
    Reset,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // 設定ファイルを読み込み
    let config = load_config(cli.config.as_ref())?;

    match &cli.command {
        Commands::Encrypt {
            text,
            password,
            password_env,
            verbose,
            no_newline,
        } => {
            let input_text = get_input_text(text)?;
            let password = get_password_with_config(password, password_env, &config)?;
            let verbose = *verbose || config.default_verbose;

            let encrypted = encrypt_string(&input_text, &password, &config, verbose)?;

            if *no_newline {
                print!("{encrypted}");
            } else {
                println!("{encrypted}");
            }
        }

        Commands::Decrypt {
            text,
            password,
            password_env,
            verbose,
            no_newline,
        } => {
            let input_text = get_input_text(text)?;
            let password = get_password_with_config(password, password_env, &config)?;
            let verbose = *verbose || config.default_verbose;

            let decrypted = decrypt_string(&input_text, &password, &config, verbose)?;

            if *no_newline {
                print!("{decrypted}");
            } else {
                println!("{decrypted}");
            }
        }
        Commands::EncryptFile {
            input,
            output,
            password,
            password_env,
            verbose,
            delete_original,
            streaming,
        } => {
            let password = get_password_with_config(password, password_env, &config)?;
            let verbose = *verbose || config.default_verbose;

            let output_path = determine_output_path(input, output, true)?;

            if *streaming {
                encrypt_file_streaming(input, &output_path, &password, &config, verbose)?;
            } else {
                encrypt_file(input, &output_path, &password, &config, verbose)?;
            }

            if *delete_original {
                fs::remove_file(input)
                    .with_context(|| format!("元ファイルの削除に失敗: {}", input.display()))?;
                if verbose {
                    println!("元ファイルを削除しました: {}", input.display());
                }
            }

            println!("ファイル暗号化完了: {}", output_path.display());
        }

        Commands::DecryptFile {
            input,
            output,
            password,
            password_env,
            verbose,
            delete_encrypted,
            streaming,
        } => {
            let password = get_password_with_config(password, password_env, &config)?;
            let verbose = *verbose || config.default_verbose;

            let output_path = determine_output_path(input, output, false)?;
            if *streaming {
                decrypt_file_streaming(input, &output_path, &password, &config, verbose)?;
            } else {
                decrypt_file(input, &output_path, &password, &config, verbose)?;
            }

            if *delete_encrypted {
                fs::remove_file(input)
                    .with_context(|| format!("暗号化ファイルの削除に失敗: {}", input.display()))?;
                if verbose {
                    println!("暗号化ファイルを削除しました: {}", input.display());
                }
            }

            println!("ファイル複合化完了: {}", output_path.display());
        }

        Commands::Config { action } => {
            handle_config_command(action, cli.config.as_ref())?;
        }
    }

    Ok(())
}

/// 入力テキストを取得（引数または標準入力）
fn get_input_text(text: &Option<String>) -> Result<String> {
    match text {
        Some(t) => Ok(t.clone()),
        None => {
            let mut buffer = String::new();
            io::stdin()
                .read_to_string(&mut buffer)
                .context("標準入力の読み取りに失敗しました")?;
            Ok(buffer.trim().to_string())
        }
    }
}

/// パスワードを取得（設定ファイル対応版）
fn get_password_with_config(
    password: &Option<String>,
    password_env: &Option<String>,
    config: &Config,
) -> Result<String> {
    if let Some(pwd) = password {
        return Ok(pwd.clone());
    }

    // 引数で指定された環境変数を優先
    if let Some(env_var) = password_env {
        return std::env::var(env_var)
            .with_context(|| format!("環境変数 {env_var} が見つかりません"));
    }

    // 設定ファイルのデフォルト環境変数を使用
    if let Some(env_var) = &config.default_password_env {
        if let Ok(pwd) = std::env::var(env_var) {
            return Ok(pwd);
        }
    }

    // パスワードプロンプトを表示
    eprint!("パスワードを入力してください: ");
    io::stderr().flush()?;

    let mut password = String::new();
    io::stdin()
        .read_line(&mut password)
        .context("パスワードの読み取りに失敗しました")?;

    Ok(password.trim().to_string())
}

/// 設定ファイルを読み込み
fn load_config(config_path: Option<&PathBuf>) -> Result<Config> {
    let path = match config_path {
        Some(p) => p.clone(),
        None => get_default_config_path()?,
    };

    if !path.exists() {
        // デフォルト設定で、環境変数は設定されている可能性を考慮
        let default_config = Config::default();
        return Ok(default_config);
    }

    let content = fs::read_to_string(&path)
        .with_context(|| format!("設定ファイルの読み取りに失敗: {}", path.display()))?;

    let config: Config = toml::from_str(&content)
        .with_context(|| format!("設定ファイルの解析に失敗: {}", path.display()))?;

    Ok(config)
}

/// デフォルトの設定ファイルパスを取得
fn get_default_config_path() -> Result<PathBuf> {
    let config_dir =
        dirs::config_dir().ok_or_else(|| anyhow!("設定ディレクトリが見つかりません"))?;

    let app_config_dir = config_dir.join("mycrypt");
    Ok(app_config_dir.join("config.toml"))
}

/// 設定コマンドを処理
fn handle_config_command(action: &ConfigAction, config_path: Option<&PathBuf>) -> Result<()> {
    match action {
        ConfigAction::Init => {
            let path = match config_path {
                Some(p) => p.clone(),
                None => get_default_config_path()?,
            };

            // ディレクトリを作成
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).with_context(|| {
                    format!("設定ディレクトリの作成に失敗: {}", parent.display())
                })?;
            }

            // デフォルト設定を作成
            let config = Config::default();
            let toml_content =
                toml::to_string_pretty(&config).context("設定ファイルの生成に失敗しました")?;

            fs::write(&path, toml_content)
                .with_context(|| format!("設定ファイルの書き込みに失敗: {}", path.display()))?;

            println!("設定ファイルを作成しました: {}", path.display());
        }

        ConfigAction::Show => {
            let config = load_config(config_path)?;
            println!("現在の設定:");
            println!("  デフォルト形式: {:?}", config.default_format);
            println!("  デフォルト詳細表示: {}", config.default_verbose);
            println!("  デフォルト環境変数: {:?}", config.default_password_env);
            println!("  設定バージョン: {}", config.version);
        }

        ConfigAction::Path => {
            let path = match config_path {
                Some(p) => p.clone(),
                None => get_default_config_path()?,
            };
            println!("設定ファイルパス: {}", path.display());
            if path.exists() {
                println!("（ファイルは存在します）");
            } else {
                println!("（ファイルは存在しません - 'config init' で作成できます）");
            }
        }

        ConfigAction::Reset => {
            let path = match config_path {
                Some(p) => p.clone(),
                None => get_default_config_path()?,
            };

            if path.exists() {
                fs::remove_file(&path)
                    .with_context(|| format!("設定ファイルの削除に失敗: {}", path.display()))?;
                println!("設定ファイルを削除しました: {}", path.display());
            } else {
                println!("設定ファイルは存在しません: {}", path.display());
            }
        }
    }

    Ok(())
}

/// 出力ファイルのパスを決定
fn determine_output_path(
    input: &Path,
    output: &Option<PathBuf>,
    is_encrypt: bool,
) -> Result<PathBuf> {
    match output {
        Some(path) => Ok(path.clone()),
        None => {
            if is_encrypt {
                // 暗号化の場合:.enc拡張子の追加
                let mut path = input.to_path_buf();
                let new_name = format!(
                    "{}.enc",
                    input
                        .file_name()
                        .and_then(|s| s.to_str())
                        .ok_or_else(|| anyhow!("無効なファイル名"))?
                );
                path.set_file_name(new_name);
                Ok(path)
            } else {
                // 複合化の場合:.enc拡張子の除去
                let path = input.to_path_buf();
                if let Some(stem) = path.file_stem() {
                    let mut new_path = path.clone();
                    new_path.set_file_name(stem);
                    Ok(new_path)
                } else {
                    Err(anyhow!("暗号化ファイルの拡張子が不正です"))
                }
            }
        }
    }
}

/// ファイルの暗号化
fn encrypt_file(
    input_path: &PathBuf,
    output_path: &PathBuf,
    password: &str,
    config: &Config,
    verbose: bool,
) -> Result<()> {
    if verbose {
        println!("=== ファイル暗号化開始 ===");
        println!("入力ファイル: {}", input_path.display());
        println!("出力ファイル: {}", output_path.display());
    }

    // ファイルサイズ取得
    let metadata = fs::metadata(input_path)
        .with_context(|| format!("ファイル情報の取得に失敗: {}", input_path.display()))?;
    let file_size = metadata.len();

    if verbose {
        println!("ファイルサイズ: {file_size} バイト");
    }

    // キーとナンスを生成
    let key = generate_key_from_password(password, config, verbose)?;
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    if verbose {
        println!("キー生成完了");
        println!("ナンス: {}", base64_encode(&nonce_bytes));
    }

    // AES暗号化エンジンを初期化
    let cipher = Aes256Gcm::new(&key.into());

    // ファイルを読み込み
    let input_data = fs::read(input_path)
        .with_context(|| format!("ファイル読み込みに失敗: {}", input_path.display()))?;

    if verbose {
        println!("ファイル読み込み完了: {} バイト", input_data.len());
    }

    // 暗号化実施
    let ciphertext = cipher
        .encrypt(nonce, input_data.as_slice())
        .map_err(|e| anyhow!("ファイル暗号化に失敗: {e}"))?;

    if verbose {
        println!("暗号化完了: {} バイト", ciphertext.len());
    }

    // 出力データを構成(ナンス + 暗号文)
    let mut output_data = nonce_bytes.to_vec();
    output_data.extend_from_slice(&ciphertext);

    // ファイルに書き込み
    fs::write(output_path, &output_data)
        .with_context(|| format!("出力ファイルの書き込みに失敗: {}", output_path.display()))?;

    if verbose {
        println!("ファイル書き込み完了: {} バイト", output_data.len());
        println!("=== ファイル暗号化完了 ===");
    }

    Ok(())
}

/// ストリーミング処理でファイルを暗号化(大容量ファイル対応)
fn encrypt_file_streaming(
    input_path: &PathBuf,
    output_path: &PathBuf,
    password: &str,
    config: &Config,
    verbose: bool,
) -> Result<()> {
    const CHUNK_SIZE: usize = 64 * 1024; // 64KB のチャンク

    if verbose {
        println!("=== ストリーミング暗号化開始 ===");
        println!("入力ファイル: {}", input_path.display());
        println!("出力ファイル: {}", output_path.display());
        println!("チャンクサイズ: {} KB", CHUNK_SIZE / 1024);
    }

    // ファイルサイズの取得
    let metadata = fs::metadata(input_path)
        .with_context(|| format!("ファイル情報の取得に失敗: {}", input_path.display()))?;
    let file_size = metadata.len();

    if verbose {
        println!(
            "ファイルサイズ: {file_size} バイト ({:.2} MB)",
            file_size as f64 / 1_048_576.0
        );
    }

    // プログレスバーを設定
    let progress = ProgressBar::new(file_size);
    progress.set_style(
        ProgressStyle::default_bar()
            .template( "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .progress_chars("#>-")
        );

    // キーを生成
    let key = generate_key_from_password(password, config, verbose)?;

    if verbose {
        println!("キー生成完了");
    }

    // ファイルを開く
    let mut input_file = BufReader::new(
        File::open(input_path)
            .with_context(|| format!("入力ファイルのオープンに失敗: {}", input_path.display()))?,
    );

    let mut output_file = BufWriter::new(
        File::create(output_path)
            .with_context(|| format!("出力ファイルの作成に失敗: {}", output_path.display()))?,
    );

    // ファイルヘッダーを書き込み(マジックナンバー + チャンクサイズ)
    let header = b"GCMSTREAM";
    output_file
        .write_all(header)
        .context("ヘッダーの書き込みに失敗")?;
    output_file
        .write_all(&(CHUNK_SIZE as u32).to_le_bytes())
        .context("チャンクサイズの書き込みに失敗")?;

    if verbose {
        println!("AES-GCM暗号エンジンを準備完了");
        println!("ストリーミング処理開始...");
    }

    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut processed_bytes = 0u64;
    let mut chunk_counter = 0u64;

    loop {
        let bytes_read = input_file
            .read(&mut buffer)
            .context("ファイル読み込み中にエラーが発生")?;

        if bytes_read == 0 {
            break; //EOF
        }

        // チャンク毎にユニークなナンス生成
        let mut nonce_bytes = [0u8; 12];
        // チャンクカウンターを最初の8バイトに設定
        let counter_bytes = chunk_counter.to_le_bytes();
        nonce_bytes[0..8].copy_from_slice(&counter_bytes);
        // 残りの4バイトにランダム要素を追加
        let mut random_part = [0u8; 4];
        rand::rng().fill_bytes(&mut random_part);
        nonce_bytes[8..12].copy_from_slice(&random_part);

        let nonce = Nonce::from_slice(&nonce_bytes);

        // AES_GCM暗号化エンジンを初期化(チャンク毎に新しいインスタンス)
        let cipher = Aes256Gcm::new(&key.into());

        // データを暗号化
        let chunk_data = &buffer[..bytes_read];
        let encrypted_chunk = cipher
            .encrypt(nonce, chunk_data)
            .map_err(|e| anyhow!("チャンク暗号化に失敗: {e}"))?;

        // チャンクデータを書き込み: ナンス(12) + 暗号化データ長(4) + 暗号化データ
        output_file
            .write_all(&nonce_bytes)
            .context("ナンスの書き込みに失敗")?;
        output_file
            .write_all(&(encrypted_chunk.len() as u32).to_le_bytes())
            .context("チャンク長の書き込みに失敗")?;
        output_file
            .write_all(&encrypted_chunk)
            .context("暗号化チャンクの書き込みに失敗")?;

        processed_bytes += bytes_read as u64;
        chunk_counter += 1;
        progress.set_position(processed_bytes);
    }

    // バッファをフラッシュ
    output_file
        .flush()
        .context("出力ファイルのフラッシュに失敗")?;

    progress.finish_with_message("暗号化完了");

    if verbose {
        println!("処理済みバイト数: {processed_bytes} バイト");
        println!("処理済みチャンク数: {chunk_counter}");
        println!("=== ストリーミング暗号化完了 ===");
    }

    Ok(())
}

/// ファイルを復号化
fn decrypt_file(
    input_path: &PathBuf,
    output_path: &PathBuf,
    password: &str,
    config: &Config,
    verbose: bool,
) -> Result<()> {
    if verbose {
        println!("=== ファイル復号化開始 ===");
        println!("入力ファイル: {}", input_path.display());
        println!("出力ファイル: {}", output_path.display());
    }

    // 暗号化ファイルを読み込み
    let encrypted_data = fs::read(input_path)
        .with_context(|| format!("暗号化ファイルの読み込みに失敗: {}", input_path.display()))?;

    if verbose {
        println!(
            "暗号化ファイル読み込み完了: {} バイト",
            encrypted_data.len()
        );
    }

    if encrypted_data.len() < 12 {
        return Err(anyhow!("暗号化ファイルが不正です（サイズが小さすぎます）"));
    }

    // ナンスと暗号文を分離
    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    if verbose {
        println!("ナンス抽出: {}", base64_encode(nonce_bytes));
        println!("暗号文サイズ: {} バイト", ciphertext.len());
    }

    // キーを再生成
    let key = generate_key_from_password(password, config, verbose)?;
    let cipher = Aes256Gcm::new(&key.into());

    if verbose {
        println!("復号化エンジン初期化完了");
    }

    // 復号化実行
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("ファイル復号化に失敗: {e}"))?;

    if verbose {
        println!("復号化完了: {} バイト", plaintext.len());
    }

    // ファイルに書き込み
    fs::write(output_path, &plaintext)
        .with_context(|| format!("出力ファイルの書き込みに失敗: {}", output_path.display()))?;

    if verbose {
        println!("ファイル書き込み完了");
        println!("=== ファイル復号化完了 ===");
    }

    Ok(())
}

/// ストリーミング処理でファイルを復号化（大容量ファイル対応）
fn decrypt_file_streaming(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    config: &Config,
    verbose: bool,
) -> Result<()> {
    if verbose {
        println!("=== ストリーミング復号化開始 ===");
        println!("入力ファイル: {}", input_path.display());
        println!("出力ファイル: {}", output_path.display());
    }

    // ファイルサイズを取得
    let metadata = fs::metadata(input_path)
        .with_context(|| format!("ファイル情報の取得に失敗: {}", input_path.display()))?;
    let file_size = metadata.len();

    if file_size < 17 {
        // ヘッダー(9) + チャンクサイズ(4) + 最小チャンク(4) = 17
        return Err(anyhow!("暗号化ファイルが不正です（サイズが小さすぎます）"));
    }

    if verbose {
        println!(
            "ファイルサイズ: {} バイト ({:.2} MB)",
            file_size,
            file_size as f64 / 1_048_576.0
        );
    }

    // キーの生成
    let key = generate_key_from_password(password, config, verbose)?;

    // ファイルを開く
    let mut input_file = BufReader::new(
        File::open(input_path)
            .with_context(|| format!("入力ファイルのオープンに失敗: {}", input_path.display()))?,
    );

    let mut output_file = BufWriter::new(
        File::create(output_path)
            .with_context(|| format!("出力ファイルの作成に失敗: {}", output_path.display()))?,
    );

    // ヘッダーを読み込み
    let mut header = [0u8; 9];
    input_file
        .read_exact(&mut header)
        .context("ヘッダーの読み込みに失敗")?;

    if &header != b"GCMSTREAM" {
        return Err(anyhow!("無効なファイル形式です。"));
    }

    // チャンクサイズの読み込み
    let mut chunk_size_bytes = [0u8; 4];
    input_file
        .read_exact(&mut chunk_size_bytes)
        .context("チャンクサイズの読み込みに失敗")?;
    let _chunk_size = u32::from_le_bytes(chunk_size_bytes) as usize;

    if verbose {
        println!("ファイル形式確認完了");
        println!("AES-GCM複合エンジン準備完了");
        println!("ストリーミング処理開始...");
    }

    // 進捗バーを設定（IVの16バイトを除いた実際のデータサイズ）
    let data_size = file_size - 13; // header(9) + chunk(4)
    let progress = ProgressBar::new(data_size);
    progress.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .progress_chars("#>-")
    );

    // チャンクごとに処理
    let mut processed_bytes = 0u64;
    let mut chunk_counter = 0u64;

    // チャンクごとに複合化
    loop {
        // ナンスの読み込み
        let mut nonce_bytes = [0u8; 12];
        match input_file.read_exact(&mut nonce_bytes) {
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                break; // EOF
            }
            Err(e) => return Err(anyhow!("ナンス読み込みエラー: {}", e)),
        }
        let nonce = Nonce::from_slice(&nonce_bytes);

        // 暗号化データ長を読み込み
        let mut encrypted_len_bytes = [0u8; 4];
        input_file
            .read_exact(&mut encrypted_len_bytes)
            .context("暗号化データ長の読み込みに失敗")?;
        let encrypted_len = u32::from_le_bytes(encrypted_len_bytes) as usize;

        // 暗号化データを読み込み
        let mut encrypted_chunk = vec![0u8; encrypted_len];
        input_file
            .read_exact(&mut encrypted_chunk)
            .context("暗号化チャンクの読み込みに失敗")?;

        //AES-GCM複合化エンジンを初期化(チャンクごとに新しいインスタンス)
        let cipher = Aes256Gcm::new(&key.into());

        // データを複合化
        let decrypted_chunk = cipher
            .decrypt(nonce, encrypted_chunk.as_slice())
            .map_err(|e| anyhow!("チャンク複合化に失敗: {e}"))?;

        // 複合化されたデータを書き込み
        output_file
            .write_all(&decrypted_chunk)
            .context("複合化データの書き込み中にエラーが発生")?;

        processed_bytes += (12 + 4 + encrypted_len) as u64; // nonce + length + data
        chunk_counter += 1;
        progress.set_position(processed_bytes);
    }

    // バッファをフラッシュ
    output_file
        .flush()
        .context("出力ファイルのフラッシュに失敗")?;

    progress.finish_with_message("復号化完了");

    if verbose {
        println!("処理済みチャンク数: {chunk_counter}");
        println!("=== ストリーミング復号化完了 ===");
    }

    Ok(())
}

/// AES-GCMで暗号化
fn encrypt_string(text: &str, password: &str, config: &Config, verbose: bool) -> Result<String> {
    if verbose {
        println!("=== 暗号化処理開始 ===");
        println!("元のテキスト: {text}");
        println!("テキスト長: {} 文字", text.chars().count());
    }

    // ステップ1: パスワードから32バイトキーを生成
    let key = generate_key_from_password(password, config, verbose)?;
    if verbose {
        println!("キー生成完了 (32バイト)");
    }

    // ステップ2: ランダムナンス生成（毎回異なる）
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    if verbose {
        println!("ナンス生成: {}", base64_encode(&nonce_bytes));
    }

    // ステップ3: AES暗号化エンジンを初期化
    let cipher = Aes256Gcm::new(&key.into());
    if verbose {
        println!("AES暗号エンジン初期化完了");
    }

    // ステップ4: 実際の暗号化実行
    let ciphertext = cipher
        .encrypt(nonce, text.as_bytes())
        .map_err(|e| anyhow!("暗号化に失敗: {e}"))?;
    if verbose {
        println!("暗号化完了。データ長: {} バイト", ciphertext.len());
    }

    // ステップ5: ナンス + 暗号文を結合
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    if verbose {
        println!("ナンスと暗号文を結合。総データ長: {} バイト", result.len());
    }

    // ステップ6: Base64エンコードして返す
    let encoded = base64_encode(&result);
    if verbose {
        println!("Base64エンコード完了");
        println!("=== 暗号化処理完了 ===");
    }

    Ok(encoded)
}

/// AES-GCMで復号化
fn decrypt_string(
    encrypted_text: &str,
    password: &str,
    config: &Config,
    verbose: bool,
) -> Result<String> {
    if verbose {
        println!("=== 復号化処理開始 ===");
        println!("暗号文長: {} 文字", encrypted_text.len());
    }

    // ステップ1: Base64デコード
    let data = general_purpose::STANDARD
        .decode(encrypted_text)
        .context("Base64デコードに失敗しました")?;
    if verbose {
        println!("Base64デコード完了。データ長: {} バイト", data.len());
    }

    if data.len() < 12 {
        return Err(anyhow!("データが短すぎます（最低12バイトのナンスが必要）"));
    }

    // ステップ2: ナンスと暗号文を分離
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    if verbose {
        println!("ナンス抽出: {}", base64_encode(nonce_bytes));
        println!("暗号文長: {} バイト", ciphertext.len());
    }

    // ステップ3: パスワードからキーを再生成
    let key = generate_key_from_password(password, config, verbose)?;
    if verbose {
        println!("キー再生成完了");
    }

    // ステップ4: AES復号化エンジンを初期化
    let cipher = Aes256Gcm::new(&key.into());
    if verbose {
        println!("AES復号エンジン初期化完了");
    }

    // ステップ5: 復号化実行
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("復号化に失敗: {e}"))?;
    if verbose {
        println!("復号化完了。データ長: {} バイト", plaintext.len());
    }

    // ステップ6: UTF-8文字列に変換
    let result = String::from_utf8(plaintext).context("UTF-8変換に失敗しました")?;

    if verbose {
        println!("文字列変換完了: {} 文字", result.chars().count());
        println!("=== 復号化処理完了 ===");
    }

    Ok(result)
}

/// Argon2を使用してパスワードから安全なキーを導出
fn derive_key_with_argon2(
    password: &str,
    salt: &[u8],
    config: &Argon2Config,
    verbose: bool,
) -> Result<[u8; 32]> {
    if verbose {
        println!("=== Argon2キー導出開始 ===");
        println!("パラメータ:");
        println!("  メモリ使用量: {} KB", config.memory_cost);
        println!("  時間コスト: {}", config.time_cost);
        println!("  並列度: {}", config.parallelism);
        println!("  ソルト: {}", base64_encode(salt));
    }

    // Argon2パラメータを設定
    let params = argon2::Params::new(
        config.memory_cost,
        config.time_cost,
        config.parallelism,
        Some(32), // 出力長: 32バイト
    )
    .map_err(|e| anyhow!("Argon2パラメータの設定に失敗: {}", e))?;

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id, // 最も安全な variant
        argon2::Version::V0x13,      // 最新バージョン
        params,
    );

    // キー導出を実行
    let start_time = std::time::Instant::now();

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("Argon2キー導出に失敗: {}", e))?;

    let duration = start_time.elapsed();

    if verbose {
        println!("キー導出完了 - 処理時間: {:.2}秒", duration.as_secs_f64());
        println!("=== Argon2キー導出完了 ===");
    }

    Ok(key)
}

/// パスワード空32バイトキーを生成(Argon2使用)
fn generate_key_from_password(password: &str, config: &Config, verbose: bool) -> Result<[u8; 32]> {
    // ソルトを生成
    let mut salt = [0u8; 16];
    let password_hash = std::collections::hash_map::DefaultHasher::new();
    use std::hash::{Hash, Hasher};
    let mut hasher = password_hash;
    password.hash(&mut hasher);
    let hash_value = hasher.finish();

    // ハッシュ値からソルトを生成
    let hash_bytes = hash_value.to_le_bytes();
    salt[..8].copy_from_slice(&hash_bytes);
    salt[8..16].copy_from_slice(&hash_bytes);

    derive_key_with_argon2(password, &salt, &config.argon2, verbose)
}

/// Base64エンコードのヘルパー関数
fn base64_encode(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}
