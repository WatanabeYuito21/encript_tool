use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

/// 設定ファイルの構造
#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
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
pub struct Argon2Config {
    /// メモリ使用量（KB）
    pub memory_cost: u32,
    /// 時間コスト（繰り返し回数）
    pub time_cost: u32,
    /// 並列度
    pub parallelism: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum OutputFormat {
    Base64,
    Hex,
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

/// 設定ファイルを読み込み
pub fn load_config(config_path: Option<&Path>) -> Result<Config> {
    let path = match config_path {
        Some(p) => p.to_path_buf(),
        None => get_default_config_path()?,
    };

    if !path.exists() {
        return Ok(Config::default());
    }

    let content = fs::read_to_string(&path)
        .with_context(|| format!("設定ファイルの読み取りに失敗: {}", path.display()))?;

    let config: Config = toml::from_str(&content)
        .with_context(|| format!("設定ファイルの解析に失敗: {}", path.display()))?;

    Ok(config)
}

/// デフォルトの設定ファイルパスを取得
pub fn get_default_config_path() -> Result<PathBuf> {
    let config_dir =
        dirs::config_dir().ok_or_else(|| anyhow!("設定ディレクトリが見つかりません"))?;

    let app_config_dir = config_dir.join("mycrypt");
    Ok(app_config_dir.join("config.toml"))
}

/// 設定ファイルを作成
pub fn create_config_file(path: &Path) -> Result<()> {
    // ディレクトリを作成
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("設定ディレクトリの作成に失敗: {}", parent.display()))?;
    }

    // デフォルト設定を作成
    let config = Config::default();
    let toml_content =
        toml::to_string_pretty(&config).context("設定ファイルの生成に失敗しました")?;

    fs::write(path, toml_content)
        .with_context(|| format!("設定ファイルの書き込みに失敗: {}", path.display()))?;

    Ok(())
}

/// 設定ファイルを削除
pub fn delete_config_file(path: &Path) -> Result<()> {
    if path.exists() {
        fs::remove_file(path)
            .with_context(|| format!("設定ファイルの削除に失敗: {}", path.display()))?;
    }
    Ok(())
}
