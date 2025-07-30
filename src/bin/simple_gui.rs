// src/bin/simple_gui.rs
use eframe::egui;

struct SimpleApp {
    name: String,
    fonts_loaded: bool,
}

impl Default for SimpleApp {
    fn default() -> Self {
        Self {
            name: "World".to_owned(),
            fonts_loaded: false,
        }
    }
}

impl eframe::App for SimpleApp {
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
            ui.heading("WSL2 GUI Test");
            ui.horizontal(|ui| {
                ui.label("あなたの名前は？: ");
                ui.text_edit_singleline(&mut self.name);
            });
            ui.label(format!("Hello {}!", self.name));
        });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([320.0, 240.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Simple GUI Test",
        options,
        Box::new(|_cc| Ok(Box::new(SimpleApp::default()))),
    )
}
