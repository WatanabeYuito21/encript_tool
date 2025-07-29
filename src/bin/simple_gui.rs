// src/bin/simple_gui.rs
use eframe::egui;

struct SimpleApp {
    name: String,
}

impl Default for SimpleApp {
    fn default() -> Self {
        Self {
            name: "World".to_owned(),
        }
    }
}

impl eframe::App for SimpleApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("WSL2 GUI Test");
            ui.horizontal(|ui| {
                ui.label("Your name: ");
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
