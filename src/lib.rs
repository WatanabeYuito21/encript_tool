pub mod config;
pub mod crypto;
pub mod file_ops;
pub mod key_derivation;

// 公開API
pub use config::{Argon2Config, Config, OutputFormat};
pub use crypto::{decrypt_string, encrypt_string};
pub use file_ops::{
    decrypt_file_standard, decrypt_file_streaming, encrypt_file_standard, encrypt_file_streaming,
};
pub use key_derivation::{derive_key_with_argon2, generate_key_from_password};

// 共通ユーティリティ
use base64::{engine::general_purpose, Engine as _};

pub fn base64_encode(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

#[cfg(feature = "gui")]
pub mod gui;
