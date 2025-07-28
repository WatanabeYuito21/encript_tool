use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use encript_tool::{
    config::{
        Config, create_config_file, delete_config_file, get_default_config_path, load_config,
    },
    crypto::{decrypt_string, encrypt_string},
    file_ops::{
        decrypt_file_standard, decrypt_file_streaming, determine_output_path,
        encrypt_file_standard, encrypt_file_streaming,
    },
};
use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

/// AES-GCM暗号化ツール
#[derive(Parser)]
#[command(name = "mycrypt")]
#[command(about = "A simple encryption tool using AES-GCM")]
#[command(version = "0.1.0")]
#[command(
    long_about = "このツールはAES-GCM暗号化を使用して文字列やファイルを安全に暗号化・復号化します。"
)]
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
    /// 暗号化されたファイルを復号化する
    DecryptFile {
        /// 復号化するファイルのパス
        input: PathBuf,

        /// 出力ファイルのパス(指定しない場合は自動決定)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// 復号化用のパスワード
        #[arg(short, long)]
        password: Option<String>,

        /// 環境変数からパスワードを読み取る
        #[arg(long)]
        password_env: Option<String>,

        /// 詳細な処理過程を表示
        #[arg(short, long)]
        verbose: bool,

        /// 復号化後に暗号化ファイルを削除
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
    let config = load_config(cli.config.as_deref())?;

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
                encrypt_file_standard(input, &output_path, &password, &config, verbose)?;
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
                decrypt_file_standard(input, &output_path, &password, &config, verbose)?;
            }

            if *delete_encrypted {
                fs::remove_file(input)
                    .with_context(|| format!("暗号化ファイルの削除に失敗: {}", input.display()))?;
                if verbose {
                    println!("暗号化ファイルを削除しました: {}", input.display());
                }
            }

            println!("ファイル復号化完了: {}", output_path.display());
        }

        Commands::Config { action } => {
            handle_config_command(action, cli.config.as_deref())?;
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

/// 設定コマンドを処理
fn handle_config_command(action: &ConfigAction, config_path: Option<&Path>) -> Result<()> {
    match action {
        ConfigAction::Init => {
            let path = match config_path {
                Some(p) => p.to_path_buf(),
                None => get_default_config_path()?,
            };

            create_config_file(&path)?;
            println!("設定ファイルを作成しました: {}", path.display());
        }

        ConfigAction::Show => {
            let config = load_config(config_path)?;
            println!("現在の設定:");
            println!("  デフォルト形式: {:?}", config.default_format);
            println!("  デフォルト詳細表示: {}", config.default_verbose);
            println!("  デフォルト環境変数: {:?}", config.default_password_env);
            println!("  設定バージョン: {}", config.version);
            println!("  Argon2設定:");
            println!("    メモリ使用量: {} KB", config.argon2.memory_cost);
            println!("    時間コスト: {}", config.argon2.time_cost);
            println!("    並列度: {}", config.argon2.parallelism);
        }

        ConfigAction::Path => {
            let path = match config_path {
                Some(p) => p.to_path_buf(),
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
                Some(p) => p.to_path_buf(),
                None => get_default_config_path()?,
            };

            delete_config_file(&path)?;
            println!("設定ファイルを削除しました: {}", path.display());
        }
    }

    Ok(())
}
