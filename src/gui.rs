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

        // この関数は main.rs で実装する必要があります
        // 今は仮の実装として、エラーを返します
        Err("暗号化機能は実装中です".to_string())
    }

    /// 復号化処理を実行
    pub fn decrypt(&mut self) -> Result<(), String> {
        if self.input_text.is_empty() {
            return Err("入力テキストが空です".to_string());
        }

        if self.password.is_empty() {
            return Err("パスワードが空です".to_string());
        }

        // この関数は main.rs で実装する必要があります
        // 今は仮の実装として、エラーを返します
        Err("復号化機能は実装中です".to_string())
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
                self.error_message = format!("暗号化エラー: {}", e);
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
                self.error_message = format!("復号化エラー: {}", e);
                self.output_text.clear();
            }
        }
    }
}

impl eframe::App for CryptApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("AES-GCM 暗号化ツール");

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
                if ui.button("暗号化").clicked() {
                    self.do_encrypt();
                }

                if ui.button("復号化").clicked() {
                    self.do_decrypt();
                }

                if ui.button("クリア").clicked() {
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
            ui.collapsing("設定情報", |ui| {
                ui.label(&self.config_info);
                ui.label("Argon2 デフォルト設定:");
                ui.label("  メモリ使用量: 65536 KB");
                ui.label("  時間コスト: 3");
                ui.label("  並列度: 4");
            });
        });
    }
}
