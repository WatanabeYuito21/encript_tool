use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose};
use clap::{Parser, Subcommand};
use rand::RngCore;
use std::io::{self, Read, Write};

#[derive(Parser)]
#[command(name = "encrypt_tool")]
#[command(about = "A simple string encryption tool using AES-GCM")]
#[command(version = "0.1.0")]
#[command(long_about = "このツールはAES-GCM暗号化を使用して文字列を安全に暗号化・複合化します。")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 文字列を暗号化する
    Encrypt {
        /// 暗号化するテキスト(指定しない場合は標準入力から読み取り)
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
    /// 暗号化された文字列を複合化する
    Decrypt {
        /// 複合化する暗号文(指定しない場合は標準入力から読み取り)
        text: Option<String>,

        /// 複合化用のパスワード
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
}

fn main() -> Result<()> {
    // コマンドライン引数を取得
    let cli = Cli::parse();

    match &cli.command {
        Commands::Encrypt {
            text,
            password,
            password_env,
            verbose,
            no_newline,
        } => {
            let input_text = get_input_text(text)?;
            let password = get_password(password, password_env)?;

            let encrypted = aes_encrypt(&input_text, &password, *verbose)?;

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
            let password = get_password(password, password_env)?;

            let decrypted = aes_decrypt(&input_text, &password, *verbose)?;

            if *no_newline {
                print!("{decrypted}");
            } else {
                println!("{decrypted}");
            }
        }
    }

    Ok(())
}

/// 入力テキストを取得(引数 or 標準入力)
fn get_input_text(text: &Option<String>) -> Result<String> {
    match text {
        Some(t) => Ok(t.clone()),
        None => {
            let mut buffer = String::new();
            io::stdin()
                .read_to_string(&mut buffer)
                .context("標準入力の読み取りに失敗しました。")?;
            Ok(buffer.trim().to_string())
        }
    }
}

/// パスワードを取得(引数、環境変数、またはプロンプト)
fn get_password(password: &Option<String>, password_env: &Option<String>) -> Result<String> {
    if let Some(pwd) = password {
        return Ok(pwd.clone());
    }

    if let Some(env_var) = password_env {
        return std::env::var(env_var)
            .with_context(|| format!("環境変数 {env_var} が見つかりません"));
    }

    // パスワードプロンプトを表示
    eprint!("パスワードを入力してください: ");
    io::stderr().flush()?;

    let mut password = String::new();
    io::stdin()
        .read_line(&mut password)
        .context("パスワードの読み取りに失敗しました。")?;

    Ok(password.trim().to_string())
}

/// AES-GCMで暗号化
fn aes_encrypt(text: &str, password: &str, verbose: bool) -> Result<String> {
    if verbose {
        println!("=== 暗号化処理開始 ===");
        println!("元のテキスト: {text}");
        println!("テキスト長: {} 文字", text.chars().count());
        println!("パスワード: {password}");
    }

    // パスワードから32バイトキーの生成
    let key = generate_key_from_password(password);
    if verbose {
        println!("キー生成完了(32Byte)");
    }

    // ランダムナンスの生成
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    if verbose {
        println!("ナンス生成: {}", base64_encode(&nonce_bytes));
    }

    // AES暗号化エンジンの初期化
    let cipher = Aes256Gcm::new(&key.into());
    if verbose {
        println!("AES暗号エンジン初期化完了");
    }

    // 暗号化実施
    let ciphertext = cipher
        .encrypt(nonce, text.as_bytes())
        .map_err(|e| anyhow!("暗号化に失敗: {e}"))?;
    if verbose {
        println!("暗号化完了。データ長: {} バイト", ciphertext.len());
    }

    // ナンス + 暗号文を結合
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    if verbose {
        println!("ナンス暗号文を結合。総データ長: {} バイト", result.len());
    }

    // Base64エンコードして返却
    let encoded = base64_encode(&result);
    if verbose {
        println!("Base64エンコード完了");
        println!("=== 暗号化処理完了 ===");
    }

    Ok(encoded)
}

/// AES-GCMで複合化
fn aes_decrypt(encrypted_text: &str, password: &str, verbose: bool) -> Result<String> {
    if verbose {
        println!("=== 複合化開始 ===");
        println!("暗号文: {encrypted_text}");
        println!("暗号文長: {} 文字", encrypted_text.len());
        println!("パスワード: {password}");
    }

    // Base64デコード
    let data = general_purpose::STANDARD
        .decode(encrypted_text)
        .context("Base64デコードに失敗しました。")?;
    if verbose {
        println!("Base64デコード完了。データ長: {} バイト", data.len());
    }

    if data.len() < 12 {
        return Err(anyhow!("データが短すぎます(最低12バイトのナンスが必要)"));
    }

    // ナンスと暗号文を分離
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    if verbose {
        println!("ナンス抽出: {}", base64_encode(nonce_bytes));
        println!("暗号文長: {} バイト", ciphertext.len());
    }

    // パスワードからキーを再生成
    let key = generate_key_from_password(password);
    if verbose {
        println!("キー再生成完了");
    }

    // AES複合化エンジンを初期化
    let cipher = Aes256Gcm::new(&key.into());
    if verbose {
        println!("AES復号エンジン初期化完了");
    }

    // 複合化
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("複合化に失敗: {e}"))?;
    if verbose {
        println!("複合化完了。データ長: {} バイト", plaintext.len());
    }

    // UTF-8文字列に変換
    let result = String::from_utf8(plaintext).context("UTF-8変換に失敗しました。")?;

    if verbose {
        println!("文字列変換完了: {} 文字", result.chars().count());
        println!("=== 複合化処理完了 ===");
    }

    Ok(result)
}

/// パスワードから32バイトキーの生成
fn generate_key_from_password(password: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    let password_bytes = password.as_bytes();

    for (i, &byte) in password_bytes.iter().cycle().take(32).enumerate() {
        key[i] = byte;
    }

    key
}

/// Base64エンコードのヘルパー
fn base64_encode(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}
