use eframe::egui;

/// GUI アプリケーション構造体
pub struct CryptApp {
    /// 入力テキスト
    input_text: String,
    /// パスワード
    password: String,
    /// 出力テキスト
    output_text: String,
    /// 設定（文字列として保持）
    config_info: String,
    /// 詳細出力フラグ
    verbose: bool,
    /// エラーメッセージ
    error_message: String,
    /// フォントが読み込まれたかどうか
    fonts_loaded: bool,
}

impl Default for CryptApp {
    fn default() -> Self {
        Self {
            input_text: String::new(),
            password: String::new(),
            output_text: String::new(),
            config_info: "デフォルト設定を使用".to_string(),
            verbose: false,
            error_message: String::new(),
            fonts_loaded: false,
        }
    }
}

impl CryptApp {
    /// 新しいアプリケーションインスタンスを作成
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self::default()
    }

    /// 暗号化処理を実行
    pub fn encrypt(&mut self) -> Result<(), String> {
        if self.input_text.is_empty() {
            return Err("入力テキストが空です".to_string());
        }

        if self.password.is_empty() {
            return Err("パスワードが空です".to_string());
        }

        // 仮の暗号化実装（Base64エンコード）
        use base64::{engine::general_purpose, Engine as _};
        let encoded = general_purpose::STANDARD.encode(&self.input_text);
        self.output_text = format!("暗号化済み: {encoded}");
        Ok(())
    }

    /// 復号化処理を実行
    pub fn decrypt(&mut self) -> Result<(), String> {
        if self.input_text.is_empty() {
            return Err("入力テキストが空です".to_string());
        }

        if self.password.is_empty() {
            return Err("パスワードが空です".to_string());
        }

        // 仮の復号化実装（Base64デコード）
        use base64::{engine::general_purpose, Engine as _};
        match general_purpose::STANDARD.decode(&self.input_text) {
            Ok(decoded) => match String::from_utf8(decoded) {
                Ok(text) => {
                    self.output_text = format!("復号化済み: {text}");
                    Ok(())
                }
                Err(_) => Err("復号化に失敗しました（無効なUTF-8）".to_string()),
            },
            Err(_) => Err("復号化に失敗しました（無効なBase64）".to_string()),
        }
    }

    /// 入力・出力テキストをクリア
    fn clear_text(&mut self) {
        self.input_text.clear();
        self.output_text.clear();
        self.error_message.clear();
    }

    /// 暗号化実行のヘルパー
    fn do_encrypt(&mut self) {
        match self.encrypt() {
            Ok(()) => {
                self.error_message.clear();
            }
            Err(e) => {
                self.error_message = format!("暗号化エラー: {e}");
                self.output_text.clear();
            }
        }
    }

    /// 復号化実行のヘルパー
    fn do_decrypt(&mut self) {
        match self.decrypt() {
            Ok(()) => {
                self.error_message.clear();
            }
            Err(e) => {
                self.error_message = format!("復号化エラー: {e}");
                self.output_text.clear();
            }
        }
    }
}

impl eframe::App for CryptApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 日本語フォントを一回だけ設定
        if !self.fonts_loaded {
            let mut fonts = egui::FontDefinitions::default();

            // VL Gothicフォントを読み込み
            if let Ok(font_data) =
                std::fs::read("/usr/share/fonts/vl-gothic-fonts/VL-Gothic-Regular.ttf")
            {
                fonts.font_data.insert(
                    "vl_gothic".to_owned(),
                    egui::FontData::from_owned(font_data).into(),
                );

                // フォントファミリーの先頭に追加
                fonts
                    .families
                    .get_mut(&egui::FontFamily::Proportional)
                    .unwrap()
                    .insert(0, "vl_gothic".to_owned());

                ctx.set_fonts(fonts);
            }

            self.fonts_loaded = true;
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("🔐 AES-GCM 暗号化ツール");

            ui.separator();

            // 入力テキスト領域
            ui.label("入力テキスト:");
            ui.text_edit_multiline(&mut self.input_text);

            ui.add_space(10.0);

            // パスワード入力
            ui.label("パスワード:");
            ui.text_edit_singleline(&mut self.password);

            ui.add_space(10.0);

            // 詳細出力チェックボックス
            ui.checkbox(&mut self.verbose, "詳細出力");

            ui.add_space(10.0);

            // ボタン類
            ui.horizontal(|ui| {
                if ui.button("🔒 暗号化").clicked() {
                    self.do_encrypt();
                }

                if ui.button("🔓 復号化").clicked() {
                    self.do_decrypt();
                }

                if ui.button("🗑️ クリア").clicked() {
                    self.clear_text();
                }
            });

            ui.add_space(10.0);

            // エラーメッセージ表示
            if !self.error_message.is_empty() {
                ui.colored_label(egui::Color32::RED, &self.error_message);
                ui.add_space(5.0);
            }

            // 出力テキスト領域
            ui.label("出力テキスト:");
            ui.text_edit_multiline(&mut self.output_text);

            ui.add_space(10.0);

            // 設定情報表示
            ui.collapsing("⚙️ 設定情報", |ui| {
                ui.label(&self.config_info);
                ui.label("Argon2 デフォルト設定:");
                ui.label("  メモリ使用量: 65536 KB");
                ui.label("  時間コスト: 3");
                ui.label("  並列度: 4");
            });
        });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([600.0, 500.0])
            .with_title("AES-GCM Encryption Tool"), // 英語に変更
        ..Default::default()
    };

    eframe::run_native(
        "AES-GCM Encryption Tool", // 英語に変更
        options,
        Box::new(|cc| Ok(Box::new(CryptApp::new(cc)))),
    )
}
