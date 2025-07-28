use crate::base64_encode;
use crate::config::Config;
use crate::key_derivation::generate_key_from_password;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::{Context, Result, anyhow};
use indicatif::{ProgressBar, ProgressStyle};
use rand::RngCore;
use std::{
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
};

/// 出力ファイルのパスを決定
pub fn determine_output_path(
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
                // 復号化の場合:.enc拡張子の除去
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

/// 標準のファイル暗号化（AES-GCM）
pub fn encrypt_file_standard(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    config: &Config,
    verbose: bool,
) -> Result<()> {
    if verbose {
        println!("=== AES-GCM 標準ファイル暗号化開始 ===");
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
    let key = generate_key_from_password(password, config, verbose)?;
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    if verbose {
        println!("キー生成完了");
        println!("ナンス: {}", base64_encode(&nonce_bytes));
    }

    // AES-GCM暗号化エンジンを初期化
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
        println!("=== AES-GCM 標準ファイル暗号化完了 ===");
    }

    Ok(())
}

/// 標準のファイル復号化（AES-GCM）
pub fn decrypt_file_standard(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    config: &Config,
    verbose: bool,
) -> Result<()> {
    if verbose {
        println!("=== AES-GCM 標準ファイル復号化開始 ===");
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
    let key = generate_key_from_password(password, config, verbose)?;
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
        println!("=== AES-GCM 標準ファイル復号化完了 ===");
    }

    Ok(())
}

/// AES-GCMストリーミング暗号化（大容量ファイル対応）
pub fn encrypt_file_streaming(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    config: &Config,
    verbose: bool,
) -> Result<()> {
    const CHUNK_SIZE: usize = 64 * 1024; // 64KB のチャンク

    if verbose {
        println!("=== AES-GCM ストリーミング暗号化開始 ===");
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
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .progress_chars("#>-")
    );

    // キーを生成
    let key = generate_key_from_password(password, config, verbose)?;

    if verbose {
        println!("キー生成完了");
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

    // ファイルヘッダーを書き込み (マジックナンバー + チャンクサイズ)
    let header = b"GCMSTREAM";
    output_file
        .write_all(header)
        .context("ヘッダーの書き込みに失敗")?;
    output_file
        .write_all(&(CHUNK_SIZE as u32).to_le_bytes())
        .context("チャンクサイズの書き込みに失敗")?;

    if verbose {
        println!("AES-GCM暗号エンジン準備完了");
        println!("ストリーミング処理開始...");
    }

    // チャンクごとに処理
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut processed_bytes = 0u64;
    let mut chunk_counter = 0u64;

    loop {
        let bytes_read = input_file
            .read(&mut buffer)
            .context("ファイル読み込み中にエラーが発生")?;

        if bytes_read == 0 {
            break; // EOF
        }

        // チャンクごとにユニークなナンス生成
        let mut nonce_bytes = [0u8; 12];
        // チャンクカウンターを最初の8バイトに設定
        let counter_bytes = chunk_counter.to_le_bytes();
        nonce_bytes[0..8].copy_from_slice(&counter_bytes);
        // 残りの4バイトにランダム要素を追加
        let mut random_part = [0u8; 4];
        rand::rng().fill_bytes(&mut random_part);
        nonce_bytes[8..12].copy_from_slice(&random_part);

        let nonce = Nonce::from_slice(&nonce_bytes);

        // AES-GCM暗号化エンジンを初期化（チャンクごとに新しいインスタンス）
        let cipher = Aes256Gcm::new(&key.into());

        // データを暗号化
        let chunk_data = &buffer[..bytes_read];
        let encrypted_chunk = cipher
            .encrypt(nonce, chunk_data)
            .map_err(|e| anyhow!("チャンク暗号化に失敗: {e}"))?;

        // チャンクデータを書き込み: ナンス(12) + 暗号化データ長(4) + 暗号化データ
        output_file
            .write_all(&nonce_bytes)
            .context("ナンスの書き込みに失敗")?;
        output_file
            .write_all(&(encrypted_chunk.len() as u32).to_le_bytes())
            .context("チャンク長の書き込みに失敗")?;
        output_file
            .write_all(&encrypted_chunk)
            .context("暗号化チャンクの書き込みに失敗")?;

        processed_bytes += bytes_read as u64;
        chunk_counter += 1;
        progress.set_position(processed_bytes);
    }

    // バッファをフラッシュ
    output_file
        .flush()
        .context("出力ファイルのフラッシュに失敗")?;

    progress.finish_with_message("AES-GCM暗号化完了");

    if verbose {
        println!("処理済みバイト数: {processed_bytes} バイト");
        println!("処理済みチャンク数: {chunk_counter}");
        println!("=== AES-GCM ストリーミング暗号化完了 ===");
    }

    Ok(())
}

/// AES-GCMストリーミング復号化（大容量ファイル対応）
pub fn decrypt_file_streaming(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    config: &Config,
    verbose: bool,
) -> Result<()> {
    if verbose {
        println!("=== AES-GCM ストリーミング復号化開始 ===");
        println!("入力ファイル: {}", input_path.display());
        println!("出力ファイル: {}", output_path.display());
    }

    // ファイルサイズを取得
    let metadata = fs::metadata(input_path)
        .with_context(|| format!("ファイル情報の取得に失敗: {}", input_path.display()))?;
    let file_size = metadata.len();

    if file_size < 17 {
        // ヘッダー(9) + チャンクサイズ(4) + 最小チャンク(4) = 17
        return Err(anyhow!("暗号化ファイルが不正です（サイズが小さすぎます）"));
    }

    if verbose {
        println!(
            "ファイルサイズ: {} バイト ({:.2} MB)",
            file_size,
            file_size as f64 / 1_048_576.0
        );
    }

    // キーの生成
    let key = generate_key_from_password(password, config, verbose)?;

    // ファイルを開く
    let mut input_file = BufReader::new(
        File::open(input_path)
            .with_context(|| format!("入力ファイルのオープンに失敗: {}", input_path.display()))?,
    );

    let mut output_file = BufWriter::new(
        File::create(output_path)
            .with_context(|| format!("出力ファイルの作成に失敗: {}", output_path.display()))?,
    );

    // ヘッダーを読み込み
    let mut header = [0u8; 9];
    input_file
        .read_exact(&mut header)
        .context("ヘッダーの読み込みに失敗")?;

    if &header != b"GCMSTREAM" {
        return Err(anyhow!("無効なファイル形式です"));
    }

    // チャンクサイズを読み込み
    let mut chunk_size_bytes = [0u8; 4];
    input_file
        .read_exact(&mut chunk_size_bytes)
        .context("チャンクサイズの読み込みに失敗")?;
    let _chunk_size = u32::from_le_bytes(chunk_size_bytes) as usize;

    if verbose {
        println!("ファイル形式確認完了");
        println!("AES-GCM復号エンジン準備完了");
        println!("ストリーミング処理開始...");
    }

    // データサイズから進捗バーを設定（ヘッダー分を除く）
    let data_size = file_size - 13; // ヘッダー(9) + チャンクサイズ(4)
    let progress = ProgressBar::new(data_size);
    progress.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .progress_chars("#>-")
    );

    let mut processed_bytes = 0u64;
    let mut chunk_counter = 0u64;

    // チャンクごとに復号化
    loop {
        // ナンスを読み込み
        let mut nonce_bytes = [0u8; 12];
        match input_file.read_exact(&mut nonce_bytes) {
            Ok(()) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                break; // ファイル終端
            }
            Err(e) => return Err(anyhow!("ナンス読み込みエラー: {}", e)),
        }
        let nonce = Nonce::from_slice(&nonce_bytes);

        // 暗号化データ長を読み込み
        let mut encrypted_len_bytes = [0u8; 4];
        input_file
            .read_exact(&mut encrypted_len_bytes)
            .context("暗号化データ長の読み込みに失敗")?;
        let encrypted_len = u32::from_le_bytes(encrypted_len_bytes) as usize;

        // 暗号化データを読み込み
        let mut encrypted_chunk = vec![0u8; encrypted_len];
        input_file
            .read_exact(&mut encrypted_chunk)
            .context("暗号化チャンクの読み込みに失敗")?;

        // AES-GCM復号化エンジンを初期化（チャンクごとに新しいインスタンス）
        let cipher = Aes256Gcm::new(&key.into());

        // データを復号化
        let decrypted_chunk = cipher
            .decrypt(nonce, encrypted_chunk.as_slice())
            .map_err(|e| anyhow!("チャンク復号化に失敗: {e}"))?;

        // 復号化されたデータを書き込み
        output_file
            .write_all(&decrypted_chunk)
            .context("復号化データの書き込み中にエラーが発生")?;

        processed_bytes += (12 + 4 + encrypted_len) as u64; // ナンス + 長さ + データ
        chunk_counter += 1;
        progress.set_position(processed_bytes);
    }

    // バッファをフラッシュ
    output_file
        .flush()
        .context("出力ファイルのフラッシュに失敗")?;

    progress.finish_with_message("AES-GCM復号化完了");

    if verbose {
        println!("処理済みチャンク数: {chunk_counter}");
        println!("=== AES-GCM ストリーミング復号化完了 ===");
    }

    Ok(())
}
