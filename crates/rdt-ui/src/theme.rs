//! Colour palette and theme application.

use eframe::egui;

/// The colour scheme in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Palette {
    /// Follow the operating system.
    System,
    /// Light.
    Light,
    /// Dark.
    Dark,
}

impl Palette {
    /// Maps a stored setting onto a palette.
    pub fn for_theme(theme: rdt_config::Theme) -> Self {
        match theme {
            rdt_config::Theme::System => Self::System,
            rdt_config::Theme::Light => Self::Light,
            rdt_config::Theme::Dark => Self::Dark,
        }
    }

    /// True when a dark background should be used.
    pub fn is_dark(self) -> bool {
        match self {
            Self::System => std::env::var("COLORFGBG").map(|value| value.ends_with(";15")).unwrap_or(true),
            Self::Light => false,
            Self::Dark => true,
        }
    }

    /// The terminal background colour, matching the default terminal theme.
    pub fn terminal_background(self) -> egui::Color32 {
        if self.is_dark() {
            egui::Color32::from_rgb(24, 24, 27)
        } else {
            egui::Color32::from_rgb(250, 250, 249)
        }
    }

    /// Maps one of the 16 ANSI colours onto an RGB triple.
    pub fn ansi(self, index: u8) -> egui::Color32 {
        let dark = self.is_dark();
        let base: [egui::Color32; 8] = if dark {
            [
                egui::Color32::from_rgb(63, 63, 70),
                egui::Color32::from_rgb(248, 113, 113),
                egui::Color32::from_rgb(74, 222, 128),
                egui::Color32::from_rgb(250, 204, 21),
                egui::Color32::from_rgb(96, 165, 250),
                egui::Color32::from_rgb(232, 121, 249),
                egui::Color32::from_rgb(34, 211, 238),
                egui::Color32::from_rgb(212, 212, 216),
            ]
        } else {
            [
                egui::Color32::from_rgb(28, 25, 23),
                egui::Color32::from_rgb(185, 28, 28),
                egui::Color32::from_rgb(21, 128, 61),
                egui::Color32::from_rgb(161, 98, 7),
                egui::Color32::from_rgb(29, 78, 216),
                egui::Color32::from_rgb(126, 34, 206),
                egui::Color32::from_rgb(14, 116, 144),
                egui::Color32::from_rgb(87, 83, 78),
            ]
        };
        match index {
            0..=7 => base[index as usize],
            8..=15 => {
                let colour = base[(index - 8) as usize];
                colour.gamma_multiply(1.25)
            }
            _ => base[7],
        }
    }
}

/// Applies the palette to the egui context.
pub fn apply_theme(context: &egui::Context, palette: &Palette) {
    let mut visuals = if palette.is_dark() {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };
    visuals.widgets.noninteractive.bg_fill = palette.terminal_background();
    context.set_visuals(visuals);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn palettes_map_from_settings() {
        assert_eq!(Palette::for_theme(rdt_config::Theme::Dark), Palette::Dark);
        assert_eq!(Palette::for_theme(rdt_config::Theme::Light), Palette::Light);
        assert_eq!(Palette::for_theme(rdt_config::Theme::System), Palette::System);
    }

    #[test]
    fn dark_and_light_differ() {
        assert!(Palette::Dark.is_dark());
        assert!(!Palette::Light.is_dark());
        assert_ne!(
            Palette::Dark.terminal_background(),
            Palette::Light.terminal_background()
        );
    }

    #[test]
    fn ansi_indices_stay_in_range() {
        for index in 0..=255u8 {
            let _ = Palette::Dark.ansi(index);
            let _ = Palette::Light.ansi(index);
        }
        assert_ne!(Palette::Dark.ansi(1), Palette::Dark.ansi(2));
    }
}
