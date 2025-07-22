use base64::{Engine as _, engine::general_purpose};
use std::env;

fn main() {
    // コマンドライン引数を取得
    let args: Vec<String> = env::args().collect();

    // 引数があるかチェック
    if args.len() < 3 {
        println!("使い方: {} <encrypt|decrypt> <テキスト>", args[0]);
        return;
    }

    // 引数を取得
    let command = &args[1];
    let text = &args[2];

    match command.as_str() {
        "encrypt" => {
            println!("=== AES暗号化の準備 ===");
            demonstrate_crypto_basics(text);
        }
        "decrypt" => {
            println!("未実装")
        }
        _ => {
            println!("コマンドは 'encrypt' または 'decrypt' を指定してください。");
        }
    }
}

/// 暗号化の基本要素を理解するためのデモ
fn demonstrate_crypto_basics(text: &str) {
    println!("元のテキスト: {text}");

    // キーの生成
    let key = generate_simple_key("mypassword");
    println!("生成したキー: {}", base64_encode(&key));

    // ナンス(使い捨て番号)の生成
    let nonce = generate_nonce();
    println!("ナンス: {}", base64_encode(&nonce));

    // データの準備
    let data_bytes = text.as_bytes();
    println!("データ(バイト): {data_bytes:?}");

    // XOR暗号で暗号化
    let simple_encrypted = simple_xor_encrypt(data_bytes, &key[0..data_bytes.len().min(32)]);
    println!("安易暗号化結果: {}", base64_encode(&simple_encrypted));

    // 複合化して確認
    let decrypted = simple_xor_encrypt(&simple_encrypted, &key[0..simple_encrypted.len().min(32)]);
    let decrypted_text = String::from_utf8_lossy(&decrypted);
    println!("複合化結果: {decrypted_text}");

    if decrypted_text == text {
        println!("暗号化・複合化成功!");
    } else {
        println!("何かがおかしい");
    }
}

/// パスワードから簡単なキーを作成
fn generate_simple_key(password: &str) -> Vec<u8> {
    let mut key = vec![0u8; 32]; // 32byte = 256Bit Key
    let password_bytes = password.as_bytes();

    // パスワードをキーサイズに拡張
    for (i, &byte) in password_bytes.iter().cycle().take(32).enumerate() {
        key[i] = byte;
    }

    key
}

/// ランダムなナンスを生成(学習用で固定)
fn generate_nonce() -> Vec<u8> {
    vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
}

/// XOR暗号(学習用で簡単な暗号化)
fn simple_xor_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .zip(key.iter().cycle())
        .map(|(&data_byte, &key_byte)| data_byte ^ key_byte)
        .collect()
}

// Base64エンコードのヘルパー
fn base64_encode(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}
