use eframe::egui;
use encript_tool::{
    config::{create_config_file, get_default_config_path, load_config, Config, OutputFormat},
    crypto::{decrypt_string, encrypt_string},
    file_ops::{
        decrypt_file_standard, decrypt_file_streaming, determine_output_path,
        encrypt_file_standard, encrypt_file_streaming,
    },
};
use std::path::PathBuf;

/// 実用的なGUI暗号化アプリケーション
pub struct CryptApp {
    // テキスト処理用
    input_text: String,
    text_password: String,
    output_text: String,
    text_password_visible: bool,
    text_use_env_password: bool,
    text_env_var_name: String,

    // ファイル処理用
    selected_file_path: String,
    output_file_path: String,
    file_processing_mode: FileProcessingMode,
    use_streaming: bool,
    delete_original: bool,
    file_password: String,
    file_password_visible: bool,
    file_use_env_password: bool,
    file_env_var_name: String,

    // 設定関連
    config: Config,
    verbose: bool,

    // UI状態
    error_message: String,
    success_message: String,
    fonts_loaded: bool,
    current_tab: Tab,

    // ファイル処理の進捗
    processing: bool,
}

#[derive(Clone, PartialEq)]
enum Tab {
    TextCrypto,
    FileCrypto,
    Settings,
    About,
}

#[derive(Clone, PartialEq)]
enum FileProcessingMode {
    Encrypt,
    Decrypt,
}

impl Default for CryptApp {
    fn default() -> Self {
        Self {
            // テキスト処理用
            input_text: String::new(),
            text_password: String::new(),
            output_text: String::new(),
            text_password_visible: false,
            text_use_env_password: false,
            text_env_var_name: "MYCRYPT_TEXT_PASSWORD".to_string(),

            // ファイル処理用
            selected_file_path: String::new(),
            output_file_path: String::new(),
            file_processing_mode: FileProcessingMode::Encrypt,
            use_streaming: false,
            delete_original: false,
            file_password: String::new(),
            file_password_visible: false,
            file_use_env_password: false,
            file_env_var_name: "MYCRYPT_FILE_PASSWORD".to_string(),

            config: Config::default(),
            verbose: false,

            error_message: String::new(),
            success_message: String::new(),
            fonts_loaded: false,
            current_tab: Tab::TextCrypto,

            processing: false,
        }
    }
}

impl CryptApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let mut app = Self::default();
        // 設定ファイルの読み込みを試行
        if let Ok(config) = load_config(None) {
            app.config = config;
        }
        app
    }

    /// テキスト処理用のパスワードを取得
    fn get_text_password(&self) -> Result<String, String> {
        if self.text_use_env_password {
            std::env::var(&self.text_env_var_name)
                .map_err(|_| format!("環境変数 {} が見つかりません", self.text_env_var_name))
        } else if !self.text_password.is_empty() {
            Ok(self.text_password.clone())
        } else {
            Err("パスワードが設定されていません".to_string())
        }
    }

    /// ファイル処理用のパスワードを取得
    fn get_file_password(&self) -> Result<String, String> {
        if self.file_use_env_password {
            std::env::var(&self.file_env_var_name)
                .map_err(|_| format!("環境変数 {} が見つかりません", self.file_env_var_name))
        } else if !self.file_password.is_empty() {
            Ok(self.file_password.clone())
        } else {
            Err("パスワードが設定されていません".to_string())
        }
    }

    /// テキスト暗号化処理
    fn encrypt_text(&mut self) -> Result<(), String> {
        if self.input_text.is_empty() {
            return Err("入力テキストが空です".to_string());
        }

        let password = self.get_text_password()?;

        match encrypt_string(&self.input_text, &password, &self.config, self.verbose) {
            Ok(encrypted) => {
                self.output_text = encrypted;
                Ok(())
            }
            Err(e) => Err(format!("暗号化エラー: {e}")),
        }
    }

    /// テキスト復号化処理
    fn decrypt_text(&mut self) -> Result<(), String> {
        if self.input_text.is_empty() {
            return Err("入力テキストが空です".to_string());
        }

        let password = self.get_text_password()?;

        match decrypt_string(&self.input_text, &password, &self.config, self.verbose) {
            Ok(decrypted) => {
                self.output_text = decrypted;
                Ok(())
            }
            Err(e) => Err(format!("復号化エラー: {e}")),
        }
    }

    /// ファイル処理実行
    fn process_file(&mut self) -> Result<(), String> {
        if self.selected_file_path.is_empty() {
            return Err("ファイルが選択されていません".to_string());
        }

        let input_path = PathBuf::from(&self.selected_file_path);
        let password = self.get_file_password()?;

        // 出力パスの決定
        let output_path = if self.output_file_path.is_empty() {
            determine_output_path(
                &input_path,
                &None,
                matches!(self.file_processing_mode, FileProcessingMode::Encrypt),
            )
            .map_err(|e| format!("出力パス決定エラー: {e}"))?
        } else {
            PathBuf::from(&self.output_file_path)
        };

        self.processing = true;

        let result = match self.file_processing_mode {
            FileProcessingMode::Encrypt => {
                if self.use_streaming {
                    encrypt_file_streaming(
                        &input_path,
                        &output_path,
                        &password,
                        &self.config,
                        self.verbose,
                    )
                } else {
                    encrypt_file_standard(
                        &input_path,
                        &output_path,
                        &password,
                        &self.config,
                        self.verbose,
                    )
                }
            }
            FileProcessingMode::Decrypt => {
                if self.use_streaming {
                    decrypt_file_streaming(
                        &input_path,
                        &output_path,
                        &password,
                        &self.config,
                        self.verbose,
                    )
                } else {
                    decrypt_file_standard(
                        &input_path,
                        &output_path,
                        &password,
                        &self.config,
                        self.verbose,
                    )
                }
            }
        };

        self.processing = false;

        match result {
            Ok(()) => {
                if self.delete_original {
                    if let Err(e) = std::fs::remove_file(&input_path) {
                        return Err(format!("元ファイル削除エラー: {e}"));
                    }
                }
                Ok(())
            }
            Err(e) => Err(format!("ファイル処理エラー: {e}")),
        }
    }

    /// 設定の保存
    fn save_config(&mut self) -> Result<(), String> {
        let config_path =
            get_default_config_path().map_err(|e| format!("設定パス取得エラー: {e}"))?;

        create_config_file(&config_path).map_err(|e| format!("設定保存エラー: {e}"))?;

        Ok(())
    }

    /// テキスト暗号化タブの描画
    fn draw_text_crypto_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("📝 テキスト暗号化");
        ui.separator();

        // 入力テキスト
        ui.label("入力テキスト:");
        ui.text_edit_multiline(&mut self.input_text);
        ui.add_space(10.0);

        // パスワード入力
        ui.horizontal(|ui| {
            ui.label("パスワード:");
            if self.text_password_visible {
                ui.text_edit_singleline(&mut self.text_password);
            } else {
                ui.add(egui::TextEdit::singleline(&mut self.text_password).password(true));
            }
            if ui
                .button(if self.text_password_visible {
                    "🙈"
                } else {
                    "👁"
                })
                .clicked()
            {
                self.text_password_visible = !self.text_password_visible;
            }
        });

        ui.checkbox(
            &mut self.text_use_env_password,
            "環境変数からパスワードを取得",
        );
        if self.text_use_env_password {
            ui.horizontal(|ui| {
                ui.label("環境変数名:");
                ui.text_edit_singleline(&mut self.text_env_var_name);
            });
        }

        ui.add_space(10.0);

        // 処理ボタン
        ui.horizontal(|ui| {
            if ui.button("🔒 暗号化").clicked() {
                match self.encrypt_text() {
                    Ok(()) => {
                        self.error_message.clear();
                        self.success_message = "暗号化が完了しました".to_string();
                    }
                    Err(e) => {
                        self.error_message = e;
                        self.success_message.clear();
                    }
                }
            }

            if ui.button("🔓 復号化").clicked() {
                match self.decrypt_text() {
                    Ok(()) => {
                        self.error_message.clear();
                        self.success_message = "復号化が完了しました".to_string();
                    }
                    Err(e) => {
                        self.error_message = e;
                        self.success_message.clear();
                    }
                }
            }

            if ui.button("🗑️ クリア").clicked() {
                self.input_text.clear();
                self.output_text.clear();
                self.error_message.clear();
                self.success_message.clear();
            }

            if ui.button("📋 コピー").clicked() {
                ui.ctx().copy_text(self.output_text.clone());
                self.success_message = "クリップボードにコピーしました".to_string();
            }
        });

        ui.add_space(10.0);

        // 詳細出力チェックボックス
        ui.checkbox(&mut self.verbose, "詳細出力");

        ui.add_space(10.0);

        // 出力テキスト
        ui.label("出力テキスト:");
        ui.text_edit_multiline(&mut self.output_text);
    }

    /// ファイル暗号化タブの描画
    fn draw_file_crypto_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("📁 ファイル暗号化");
        ui.separator();

        // ファイル選択
        ui.horizontal(|ui| {
            ui.label("ファイルパス:");
            ui.text_edit_singleline(&mut self.selected_file_path);
        });

        ui.add_space(10.0);

        // 処理モード選択
        ui.horizontal(|ui| {
            ui.label("処理モード:");
            ui.radio_value(
                &mut self.file_processing_mode,
                FileProcessingMode::Encrypt,
                "暗号化",
            );
            ui.radio_value(
                &mut self.file_processing_mode,
                FileProcessingMode::Decrypt,
                "復号化",
            );
        });

        // 出力ファイルパス
        ui.horizontal(|ui| {
            ui.label("出力ファイル:");
            ui.text_edit_singleline(&mut self.output_file_path);
            if ui.button("自動").clicked() {
                self.output_file_path.clear();
            }
        });

        ui.add_space(10.0);

        // ファイル用パスワード入力
        ui.horizontal(|ui| {
            ui.label("ファイルパスワード:");
            if self.file_password_visible {
                ui.text_edit_singleline(&mut self.file_password);
            } else {
                ui.add(egui::TextEdit::singleline(&mut self.file_password).password(true));
            }
            if ui
                .button(if self.file_password_visible {
                    "🙈"
                } else {
                    "👁"
                })
                .clicked()
            {
                self.file_password_visible = !self.file_password_visible;
            }
        });

        ui.checkbox(
            &mut self.file_use_env_password,
            "環境変数からパスワードを取得",
        );
        if self.file_use_env_password {
            ui.horizontal(|ui| {
                ui.label("環境変数名:");
                ui.text_edit_singleline(&mut self.file_env_var_name);
            });
        }

        ui.add_space(10.0);

        // オプション
        ui.checkbox(
            &mut self.use_streaming,
            "ストリーミング処理（大容量ファイル用）",
        );
        ui.checkbox(&mut self.delete_original, "処理後に元ファイルを削除");
        ui.checkbox(&mut self.verbose, "詳細出力");

        ui.add_space(10.0);

        // 処理実行
        if !self.processing {
            if ui.button("🚀 ファイル処理実行").clicked() {
                match self.process_file() {
                    Ok(()) => {
                        self.error_message.clear();
                        self.success_message = "ファイル処理が完了しました".to_string();
                    }
                    Err(e) => {
                        self.error_message = e;
                        self.success_message.clear();
                    }
                }
            }
        } else {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("処理中...");
            });
        }
    }

    /// 設定タブの描画
    fn draw_settings_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("⚙️ 設定");
        ui.separator();

        // Argon2設定
        ui.collapsing("🔧 Argon2 パラメータ", |ui| {
            ui.horizontal(|ui| {
                ui.label("メモリ使用量 (KB):");
                ui.add(
                    egui::DragValue::new(&mut self.config.argon2.memory_cost).range(1024..=1048576),
                );
            });

            ui.horizontal(|ui| {
                ui.label("時間コスト:");
                ui.add(egui::DragValue::new(&mut self.config.argon2.time_cost).range(1..=10));
            });

            ui.horizontal(|ui| {
                ui.label("並列度:");
                ui.add(egui::DragValue::new(&mut self.config.argon2.parallelism).range(1..=16));
            });
        });

        ui.add_space(10.0);

        // 出力形式
        ui.horizontal(|ui| {
            ui.label("出力形式:");
            ui.radio_value(
                &mut self.config.default_format,
                OutputFormat::Base64,
                "Base64",
            );
            ui.radio_value(&mut self.config.default_format, OutputFormat::Hex, "Hex");
        });

        ui.add_space(10.0);

        // その他の設定
        ui.checkbox(&mut self.config.default_verbose, "デフォルトで詳細出力");

        ui.add_space(20.0);

        // パスワード同期機能
        ui.collapsing("🔑 パスワード管理", |ui| {
            ui.label("便利機能:");
            ui.horizontal(|ui| {
                if ui.button("テキスト→ファイル").clicked() {
                    self.file_password = self.text_password.clone();
                    self.success_message =
                        "テキストパスワードをファイルにコピーしました".to_string();
                }
                if ui.button("ファイル→テキスト").clicked() {
                    self.text_password = self.file_password.clone();
                    self.success_message =
                        "ファイルパスワードをテキストにコピーしました".to_string();
                }
                if ui.button("両方クリア").clicked() {
                    self.text_password.clear();
                    self.file_password.clear();
                    self.success_message = "パスワードをクリアしました".to_string();
                }
            });
        });

        ui.add_space(10.0);

        // 設定ファイル操作
        ui.collapsing("💾 設定ファイル", |ui| {
            if let Ok(config_path) = get_default_config_path() {
                ui.label(format!("設定ファイル: {}", config_path.display()));
                ui.label(format!(
                    "存在: {}",
                    if config_path.exists() {
                        "はい"
                    } else {
                        "いいえ"
                    }
                ));

                ui.horizontal(|ui| {
                    if ui.button("💾 設定保存").clicked() {
                        match self.save_config() {
                            Ok(()) => {
                                self.error_message.clear();
                                self.success_message = "設定を保存しました".to_string();
                            }
                            Err(e) => {
                                self.error_message = e;
                                self.success_message.clear();
                            }
                        }
                    }

                    if ui.button("📂 設定読込").clicked() {
                        match load_config(None) {
                            Ok(config) => {
                                self.config = config;
                                self.error_message.clear();
                                self.success_message = "設定を読み込みました".to_string();
                            }
                            Err(e) => {
                                self.error_message = format!("設定読み込みエラー: {e}");
                                self.success_message.clear();
                            }
                        }
                    }

                    if ui.button("🔄 デフォルトにリセット").clicked() {
                        self.config = Config::default();
                        self.success_message = "設定をリセットしました".to_string();
                    }
                });
            } else {
                ui.label("設定ディレクトリが見つかりません");
            }
        });
    }

    /// Aboutタブの描画
    fn draw_about_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("ℹ️ このアプリについて");
        ui.separator();

        ui.label("AES-GCM 暗号化ツール GUI");
        ui.label("バージョン: 2.0");
        ui.add_space(10.0);

        ui.label("🔐 機能:");
        ui.label("• テキストの暗号化・復号化");
        ui.label("• ファイルの暗号化・復号化");
        ui.label("• 独立したパスワード管理");
        ui.label("• Argon2キー導出");
        ui.label("• ストリーミング処理");
        ui.label("• 設定の保存・読込");

        ui.add_space(10.0);

        ui.label("🛡️ セキュリティ:");
        ui.label("• AES-256-GCM暗号化");
        ui.label("• Argon2idキー導出");
        ui.label("• 安全なランダムナンス生成");

        ui.add_space(10.0);

        ui.label("🎛️ 使い方:");
        ui.label("1. テキストタブでテキストの暗号化・復号化");
        ui.label("2. ファイルタブでファイルの処理（独立パスワード）");
        ui.label("3. 設定タブでパラメータ調整とパスワード管理");
        ui.label("4. 環境変数でパスワード設定可能");
        ui.label("   - MYCRYPT_TEXT_PASSWORD（テキスト用）");
        ui.label("   - MYCRYPT_FILE_PASSWORD（ファイル用）");
    }
}

impl eframe::App for CryptApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 日本語フォント設定
        if !self.fonts_loaded {
            let mut fonts = egui::FontDefinitions::default();

            if let Ok(font_data) =
                std::fs::read("/usr/share/fonts/vl-gothic-fonts/VL-Gothic-Regular.ttf")
            {
                fonts.font_data.insert(
                    "vl_gothic".to_owned(),
                    egui::FontData::from_owned(font_data).into(),
                );

                fonts
                    .families
                    .get_mut(&egui::FontFamily::Proportional)
                    .unwrap()
                    .insert(0, "vl_gothic".to_owned());

                ctx.set_fonts(fonts);
            }

            self.fonts_loaded = true;
        }

        // トップメニューバー
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            egui::MenuBar::new().ui(ui, |ui| {
                ui.menu_button("ファイル", |ui| {
                    if ui.button("新規").clicked() {
                        self.input_text.clear();
                        self.output_text.clear();
                        self.text_password.clear();
                        self.file_password.clear();
                        self.selected_file_path.clear();
                        self.output_file_path.clear();
                        self.error_message.clear();
                        self.success_message.clear();
                    }
                    if ui.button("設定読込").clicked() {
                        match load_config(None) {
                            Ok(config) => {
                                self.config = config;
                                self.success_message = "設定を読み込みました".to_string();
                            }
                            Err(e) => {
                                self.error_message = format!("設定読み込みエラー: {e}");
                            }
                        }
                    }
                    if ui.button("設定保存").clicked() {
                        match self.save_config() {
                            Ok(()) => self.success_message = "設定を保存しました".to_string(),
                            Err(e) => self.error_message = e,
                        }
                    }
                    ui.separator();
                    if ui.button("終了").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });

                ui.menu_button("ヘルプ", |ui| {
                    if ui.button("このアプリについて").clicked() {
                        self.current_tab = Tab::About;
                    }
                });
            });
        });

        // タブバー
        egui::TopBottomPanel::top("tab_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.current_tab, Tab::TextCrypto, "📝 テキスト");
                ui.selectable_value(&mut self.current_tab, Tab::FileCrypto, "📁 ファイル");
                ui.selectable_value(&mut self.current_tab, Tab::Settings, "⚙️ 設定");
                ui.selectable_value(&mut self.current_tab, Tab::About, "ℹ️ 情報");
            });
        });

        // ステータスバー
        egui::TopBottomPanel::bottom("status_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if !self.error_message.is_empty() {
                    ui.colored_label(egui::Color32::RED, format!("❌ {}", self.error_message));
                } else if !self.success_message.is_empty() {
                    ui.colored_label(egui::Color32::GREEN, format!("✅ {}", self.success_message));
                } else {
                    ui.label("準備完了");
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.processing {
                        ui.spinner();
                    }
                });
            });
        });

        // メインコンテンツ
        egui::CentralPanel::default().show(ctx, |ui| match self.current_tab {
            Tab::TextCrypto => self.draw_text_crypto_tab(ui),
            Tab::FileCrypto => self.draw_file_crypto_tab(ui),
            Tab::Settings => self.draw_settings_tab(ui),
            Tab::About => self.draw_about_tab(ui),
        });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([800.0, 600.0])
            .with_min_inner_size([600.0, 400.0])
            .with_title("AES-GCM 暗号化ツール"),
        ..Default::default()
    };

    eframe::run_native(
        "AES-GCM Encryption Tool",
        options,
        Box::new(|cc| Ok(Box::new(CryptApp::new(cc)))),
    )
}
