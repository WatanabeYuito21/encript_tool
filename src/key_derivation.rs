use crate::base64_encode;
use crate::config::{Argon2Config, Config};
use anyhow::{Result, anyhow};
use argon2::Argon2;
use std::hash::{Hash, Hasher};

/// Argon2を使用してパスワードから安全なキーを導出
pub fn derive_key_with_argon2(
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
        Some(32), // 出力長：32バイト
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

/// 旧式のキー導出（後方互換性のため）
pub fn generate_key_from_password_legacy(password: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    let password_bytes = password.as_bytes();

    for (i, &byte) in password_bytes.iter().cycle().take(32).enumerate() {
        key[i] = byte;
    }

    key
}

/// パスワードから32バイトキーを生成（Argon2使用）
pub fn generate_key_from_password(
    password: &str,
    config: &Config,
    verbose: bool,
) -> Result<[u8; 32]> {
    // ソルトを生成（実際のアプリケーションでは保存が必要）
    // ここでは簡易的にパスワードからソルトを導出
    let mut salt = [0u8; 16];
    let password_hash = std::collections::hash_map::DefaultHasher::new();
    let mut hasher = password_hash;
    password.hash(&mut hasher);
    let hash_value = hasher.finish();

    // ハッシュ値からソルトを生成
    let hash_bytes = hash_value.to_le_bytes();
    salt[..8].copy_from_slice(&hash_bytes);
    salt[8..16].copy_from_slice(&hash_bytes);

    derive_key_with_argon2(password, &salt, &config.argon2, verbose)
}
