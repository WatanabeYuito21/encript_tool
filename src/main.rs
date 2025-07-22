use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::{Engine as _, engine::general_purpose};
use rand::RngCore;
use std::env;

fn main() {
    // コマンドライン引数を取得
    let args: Vec<String> = env::args().collect();

    // 引数があるかチェック
    if args.len() < 3 {
        println!(
            "使い方: {} <encrypt|decrypt> <テキスト> [パスワード]",
            args[0]
        );
        return;
    }

    // 引数を取得
    let command = &args[1];
    let text = &args[2];
    let password = if args.len() >= 4 {
        &args[3]
    } else {
        "defaultpass"
    };

    match command.as_str() {
        "encrypt" => {
            println!("=== AES暗号化 ===");
            match aes_encrypt(text, password) {
                Ok(encrypted) => {
                    println!("暗号化成功!");
                    println!("暗号文: {encrypted}");
                }
                Err(e) => {
                    println!("暗号化エラー: {e}");
                }
            }
        }
        "decrypt" => {
            println!("=== AES複合化 ===");
            match aes_decrypt(text, password) {
                Ok(decripted) => {
                    println!("複合化成功!");
                    println!("元のテキスト: {decripted}");
                }
                Err(e) => {
                    println!("複合化エラー: {e}");
                }
            }
        }
        _ => {
            println!("コマンドは 'encrypt' または 'decrypt' を指定してください。");
        }
    }
}

/// AES-GCMで暗号化
fn aes_encrypt(text: &str, password: &str) -> Result<String, Box<dyn std::error::Error>> {
    println!("元のテキスト: {text}");
    println!("パスワード: {password}");

    // パスワードから32バイトキーの生成
    let key = generate_key_from_password(password);
    println!("キー生成完了(32Byte)");

    // ランダムナンスの生成
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    println!("ナンス生成: {}", base64_encode(&nonce_bytes));

    // AES暗号化エンジンの初期化
    let cipher = Aes256Gcm::new(&key.into());
    println!("AES暗号エンジン初期化完了");

    // 暗号化実施
    let ciphertext = cipher
        .encrypt(nonce, text.as_bytes())
        .map_err(|e| format!("暗号化に失敗: {e}"))?;
    println!("暗号化完了。データ長: {} バイト", ciphertext.len());

    // ナンス + 暗号文を結合
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    println!("ナンス暗号文を結合。総データ長: {} バイト", result.len());

    // Base64エンコードして返却
    let encoded = base64_encode(&result);
    println!("Base64エンコード完了");

    Ok(encoded)
}

/// AES-GCMで複合化
fn aes_decrypt(encrypted_text: &str, password: &str) -> Result<String, Box<dyn std::error::Error>> {
    println!("暗号文: {encrypted_text}");
    println!("パスワード: {password}");

    // Base64デコード
    let data = general_purpose::STANDARD
        .decode(encrypted_text)
        .map_err(|e| format!("Base64デコードエラー: {e}"))?;
    println!("Base64デコード完了。データ長: {} バイト", data.len());

    if data.len() < 12 {
        return Err("データが短すぎます(最低12バイトのナンスが必要)".into());
    }

    // ナンスと暗号文を分離
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    println!("ナンス抽出: {}", base64_encode(nonce_bytes));
    println!("暗号文長: {} バイト", ciphertext.len());

    // パスワードからキーを再生成
    let key = generate_key_from_password(password);
    println!("キー再生成完了");

    // AES複合化エンジンを初期化
    let cipher = Aes256Gcm::new(&key.into());
    println!("AES復号エンジン初期化完了");

    // 複合化
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("複合化に失敗: {e}"))?;
    println!("複合化完了。データ長: {} バイト", plaintext.len());

    // UTF-8文字列に変換
    let result = String::from_utf8(plaintext).map_err(|e| format!("UTF-8変換エラー: {e}"))?;

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
