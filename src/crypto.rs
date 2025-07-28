use crate::base64_encode;
use crate::config::Config;
use crate::key_derivation::generate_key_from_password;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose};
use rand::RngCore;

/// 文字列をAES-GCMで暗号化
pub fn encrypt_string(
    text: &str,
    password: &str,
    config: &Config,
    verbose: bool,
) -> Result<String> {
    if verbose {
        println!("=== AES-GCM 文字列暗号化開始 ===");
        println!("元のテキスト: {text}");
        println!("テキスト長: {} 文字", text.chars().count());
    }

    // キーを生成（Argon2使用）
    let key = generate_key_from_password(password, config, verbose)?;
    if verbose {
        println!("Argon2キー生成完了 (32バイト)");
    }

    // ランダムナンス生成
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    if verbose {
        println!("ナンス生成: {}", base64_encode(&nonce_bytes));
    }

    // AES-GCM暗号化エンジンを初期化
    let cipher = Aes256Gcm::new(&key.into());
    if verbose {
        println!("AES-GCM暗号エンジン初期化完了");
    }

    // 暗号化実行
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
        println!("ナンスと暗号文を結合。総データ長: {} バイト", result.len());
    }

    // Base64エンコードして返す
    let encoded = base64_encode(&result);
    if verbose {
        println!("Base64エンコード完了");
        println!("=== AES-GCM 文字列暗号化完了 ===");
    }

    Ok(encoded)
}

/// 文字列をAES-GCMで復号化
pub fn decrypt_string(
    encrypted_text: &str,
    password: &str,
    config: &Config,
    verbose: bool,
) -> Result<String> {
    if verbose {
        println!("=== AES-GCM 文字列復号化開始 ===");
        println!("暗号文長: {} 文字", encrypted_text.len());
    }

    // Base64デコード
    let data = general_purpose::STANDARD
        .decode(encrypted_text)
        .context("Base64デコードに失敗しました")?;
    if verbose {
        println!("Base64デコード完了。データ長: {} バイト", data.len());
    }

    if data.len() < 12 {
        return Err(anyhow!("データが短すぎます（最低12バイトのナンスが必要）"));
    }

    // ナンスと暗号文を分離
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    if verbose {
        println!("ナンス抽出: {}", base64_encode(nonce_bytes));
        println!("暗号文長: {} バイト", ciphertext.len());
    }

    // キーを再生成（Argon2使用）
    let key = generate_key_from_password(password, config, verbose)?;
    if verbose {
        println!("Argon2キー再生成完了");
    }

    // AES-GCM復号化エンジンを初期化
    let cipher = Aes256Gcm::new(&key.into());
    if verbose {
        println!("AES-GCM復号エンジン初期化完了");
    }

    // 復号化実行
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("復号化に失敗: {e}"))?;
    if verbose {
        println!("復号化完了。データ長: {} バイト", plaintext.len());
    }

    // UTF-8文字列に変換
    let result = String::from_utf8(plaintext).context("UTF-8変換に失敗しました")?;

    if verbose {
        println!("文字列変換完了: {} 文字", result.chars().count());
        println!("=== AES-GCM 文字列復号化完了 ===");
    }

    Ok(result)
}
