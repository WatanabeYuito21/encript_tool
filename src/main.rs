use std::env;

fn main() {
    // コマンドライン引数を取得
    let args: Vec<String> = env::args().collect();

    // 引数があるかチェック
    if args.len() < 3 {
        println!("使い方: {} <encript|decrypt> <テキスト>", args[0]);
        return;
    }

    // 引数を取得
    let command = &args[1];
    let text = &args[2];
    println!("元のテキスト: {text}");

    match command.as_str() {
        "encrypt" => {
            let encrypted = caeaser_encrypt(text, 3); // 3文字ずらす
            println!("暗号化: {encrypted}");
        }
        "decrypt" => {
            let decrypted = caeaser_decrypt(text, 3); // 3文字もどす
            println!("複合化: {decrypted}");
        }
        _ => {
            println!("コマンドは 'encrypt' または 'decrypt' を指定してください。");
        }
    }
}

/// シーザー暗号で暗号化(アルファベットのみ)
fn caeaser_encrypt(text: &str, shift: u8) -> String {
    text.chars().map(|ch| shift_char(ch, shift)).collect()
}

/// シーザー暗号で複合化
fn caeaser_decrypt(text: &str, shift: u8) -> String {
    caeaser_encrypt(text, 26 - shift)
}

/// 1文字シフトする関数
fn shift_char(ch: char, shift: u8) -> char {
    match ch {
        // 小文字のa-z
        'a'..='z' => {
            let pos = ch as u8 - b'a'; // aを0とする位置
            let new_pos = (pos + shift) % 26; // 26文字でループ
            (b'a' + new_pos) as char
        }

        // 大文字のA-Z
        'A'..='Z' => {
            let pos = ch as u8 - b'A'; // Aを0とする位置
            let new_pos = (pos + shift) % 26; // 26文字でループ
            (b'A' + new_pos) as char
        }

        // アルファベット以外はそのまま
        _ => ch,
    }
}
