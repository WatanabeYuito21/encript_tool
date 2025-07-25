use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
    aes::Aes256,
};
use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose};
use clap::{Parser, Subcommand};
use ctr::{
    Ctr128BE,
    cipher::{KeyIvInit, StreamCipher},
};
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
            version: "1.0".to_string(),
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

            let encrypted = aes_encrypt(&input_text, &password, verbose)?;

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

            let decrypted = aes_decrypt(&input_text, &password, verbose)?;

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
                encrypt_file_streaming(input, &output_path, &password, verbose)?;
            } else {
                encrypt_file(input, &output_path, &password, verbose)?;
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
                decrypt_file_streaming(input, &output_path, &password, verbose)?;
            } else {
                decrypt_file(input, &output_path, &password, verbose)?;
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
    let key = generate_key_from_password(password);
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

    // キーとIVを生成
    let key = generate_key_from_password(password);
    let mut iv = [0u8; 16]; //AES-CTRではIVは16バイト
    rand::rng().fill_bytes(&mut iv);

    if verbose {
        println!("キー生成完了");
        println!("IV: {}", base64_encode(&iv));
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

    // IVをファイルの先頭に書き込み
    output_file.write_all(&iv).context("IVの書き込みに失敗")?;

    // AES-CTR暗号化エンジンを初期化
    type Aes256Ctr = Ctr128BE<Aes256>;
    let mut cipher = Aes256Ctr::new(&key.into(), &iv.into());

    if verbose {
        println!("AES-CTR暗号エンジンを初期化完了");
        println!("ストリーミング処理開始...");
    }

    // チャンクごとに処理
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut processed_bytes = 0u64;

    loop {
        let bytes_read = input_file
            .read(&mut buffer)
            .context("ファイル読み込み中にエラーが発生")?;

        if bytes_read == 0 {
            break; //EOF
        }

        // データを暗号化
        let mut chunk = buffer[..bytes_read].to_vec();
        cipher.apply_keystream(&mut chunk);

        // 暗号化されたデータを書き込み
        output_file
            .write_all(&chunk)
            .context("暗号化データの書き込み中にエラーが発生")?;

        processed_bytes += bytes_read as u64;
        progress.set_position(processed_bytes);
    }

    // バッファをフラッシュ
    output_file
        .flush()
        .context("出力ファイルのフラッシュに失敗")?;

    progress.finish_with_message("暗号化完了");

    if verbose {
        println!("処理済みバイト数: {processed_bytes} バイト");
        println!("=== ストリーミング暗号化完了 ===");
    }

    Ok(())
}

/// ファイルを復号化
fn decrypt_file(
    input_path: &PathBuf,
    output_path: &PathBuf,
    password: &str,
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
    let key = generate_key_from_password(password);
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
    input_path: &PathBuf,
    output_path: &PathBuf,
    password: &str,
    verbose: bool,
) -> Result<()> {
    const CHUNK_SIZE: usize = 64 * 1024; // 64KB のチャンク

    if verbose {
        println!("=== ストリーミング復号化開始 ===");
        println!("入力ファイル: {}", input_path.display());
        println!("出力ファイル: {}", output_path.display());
        println!("チャンクサイズ: {} KB", CHUNK_SIZE / 1024);
    }

    // ファイルサイズを取得
    let metadata = fs::metadata(input_path)
        .with_context(|| format!("ファイル情報の取得に失敗: {}", input_path.display()))?;
    let file_size = metadata.len();

    if file_size < 16 {
        return Err(anyhow!("暗号化ファイルが不正です（サイズが小さすぎます）"));
    }

    if verbose {
        println!(
            "ファイルサイズ: {} バイト ({:.2} MB)",
            file_size,
            file_size as f64 / 1_048_576.0
        );
    }

    // 進捗バーを設定（IVの16バイトを除いた実際のデータサイズ）
    let data_size = file_size - 16;
    let progress = ProgressBar::new(data_size);
    progress.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .progress_chars("#>-")
    );

    // キーの生成
    let key = generate_key_from_password(password);

    // ファイルを開く
    let mut input_file = BufReader::new(
        File::open(input_path)
            .with_context(|| format!("入力ファイルのオープンに失敗: {}", input_path.display()))?,
    );

    let mut output_file = BufWriter::new(
        File::create(output_path)
            .with_context(|| format!("出力ファイルの作成に失敗: {}", output_path.display()))?,
    );

    // IVを読み込み
    let mut iv = [0u8; 16];
    input_file
        .read_exact(&mut iv)
        .context("IVの読み込みに失敗")?;

    if verbose {
        println!("IV: {}", base64_encode(&iv));
    }

    // AES-CTR復号化エンジンを初期化
    type Aes256Ctr = Ctr128BE<Aes256>;
    let mut cipher = Aes256Ctr::new(&key.into(), &iv.into());

    if verbose {
        println!("AES-CTR復号エンジン初期化完了");
        println!("ストリーミング処理開始...");
    }

    // チャンクごとに処理
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut processed_bytes = 0u64;

    loop {
        let bytes_read = input_file
            .read(&mut buffer)
            .context("ファイル読み込み中にエラーが発生")?;

        if bytes_read == 0 {
            break; // EOF
        }

        // データを復号化
        let mut chunk = buffer[..bytes_read].to_vec();
        cipher.apply_keystream(&mut chunk);

        // 復号化されたデータを書き込み
        output_file
            .write_all(&chunk)
            .context("復号化データの書き込み中にエラーが発生")?;

        processed_bytes += bytes_read as u64;
        progress.set_position(processed_bytes);
    }

    // バッファをフラッシュ
    output_file
        .flush()
        .context("出力ファイルのフラッシュに失敗")?;

    progress.finish_with_message("復号化完了");

    if verbose {
        println!("処理済みバイト数: {processed_bytes} バイト");
        println!("=== ストリーミング復号化完了 ===");
    }

    Ok(())
}

/// AES-GCMで暗号化
fn aes_encrypt(text: &str, password: &str, verbose: bool) -> Result<String> {
    if verbose {
        println!("=== 暗号化処理開始 ===");
        println!("元のテキスト: {text}");
        println!("テキスト長: {} 文字", text.chars().count());
    }

    // ステップ1: パスワードから32バイトキーを生成
    let key = generate_key_from_password(password);
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
fn aes_decrypt(encrypted_text: &str, password: &str, verbose: bool) -> Result<String> {
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
    let key = generate_key_from_password(password);
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

/// パスワードから32バイトキーを生成
fn generate_key_from_password(password: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    let password_bytes = password.as_bytes();

    for (i, &byte) in password_bytes.iter().cycle().take(32).enumerate() {
        key[i] = byte;
    }

    key
}

/// Base64エンコードのヘルパー関数
fn base64_encode(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}
