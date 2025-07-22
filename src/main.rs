use base64::{Engine as _, engine::general_purpose};
use std::env;

fn main() {
    // コマンドライン引数を取得
    let args: Vec<String> = env::args().collect();

    // 引数があるかチェック
    if args.len() < 2 {
        println!("使い方: {} <テキスト>", args[0]);
        return;
    }

    // 最初の引数を取得
    let text = &args[1];
    println!("元のテキスト: {text}");

    // 文字列をバイト配列に変換
    let bytes = text.as_bytes();
    println!("バイト配列: {bytes:?}");

    // バイト文字をBase64エンコード
    let encoded = general_purpose::STANDARD.encode(bytes);
    println!("Base64 encode: {encoded}");

    // Base64でコードして元に戻す
    match general_purpose::STANDARD.decode(&encoded) {
        Ok(decoded_bytes) => match String::from_utf8(decoded_bytes) {
            Ok(decoded_text) => {
                println!("デコード結果: {decoded_text}");

                if decoded_text == *text {
                    println!("変換は成功しました!");
                } else {
                    println!("何かがおかしい...");
                }
            }
            Err(e) => println!("UTF-8変換エラー: {e}"),
        },
        Err(e) => println!("Base64デコードエラー: {e}"),
    }
}
