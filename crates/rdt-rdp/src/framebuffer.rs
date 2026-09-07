//! The BGRA framebuffer that holds the decoded remote desktop.

use std::fmt;

/// A rectangle of the framebuffer that changed since the last frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DamageRect {
    /// Left edge in pixels.
    pub left: u32,
    /// Top edge in pixels.
    pub top: u32,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
}

impl DamageRect {
    /// True when the rectangle covers no pixels.
    pub fn is_empty(&self) -> bool {
        self.width == 0 || self.height == 0
    }

    /// Clamps the rectangle to the framebuffer bounds.
    pub fn clamped(self, width: u32, height: u32) -> Self {
        let left = self.left.min(width.saturating_sub(1));
        let top = self.top.min(height.saturating_sub(1));
        Self {
            left,
            top,
            width: self.width.min(width - left),
            height: self.height.min(height - top),
        }
    }

    /// Merges two rectangles into their bounding box.
    pub fn union(self, other: Self) -> Self {
        if self.is_empty() {
            return other;
        }
        if other.is_empty() {
            return self;
        }
        let left = self.left.min(other.left);
        let top = self.top.min(other.top);
        let right = (self.left + self.width).max(other.left + other.width);
        let bottom = (self.top + self.height).max(other.top + other.height);
        Self {
            left,
            top,
            width: right - left,
            height: bottom - top,
        }
    }
}

/// A BGRA8 framebuffer with damage tracking.
///
/// The UI thread reads [`Framebuffer::pixels`] to upload a texture while the
/// session task writes into it; both sides hold the lock only for the duration
/// of a copy, so a slow renderer can never stall decoding.
#[derive(Debug, Clone)]
pub struct Framebuffer {
    width: u32,
    height: u32,
    pixels: Vec<u8>,
    damage: Vec<DamageRect>,
}

impl Framebuffer {
    /// Creates a black framebuffer of the given size.
    pub fn new(width: u32, height: u32) -> Self {
        let width = width.max(1);
        let height = height.max(1);
        Self {
            width,
            height,
            pixels: vec![0u8; (width * height * 4) as usize],
            damage: Vec::new(),
        }
    }

    /// Width in pixels.
    pub fn width(&self) -> u32 {
        self.width
    }

    /// Height in pixels.
    pub fn height(&self) -> u32 {
        self.height
    }

    /// The raw BGRA pixel data.
    pub fn pixels(&self) -> &[u8] {
        &self.pixels
    }

    /// Bytes per row.
    pub fn stride(&self) -> usize {
        self.width as usize * 4
    }

    /// Resizes, preserving the overlapping region.
    pub fn resize(&mut self, width: u32, height: u32) {
        let width = width.max(1);
        let height = height.max(1);
        if width == self.width && height == self.height {
            return;
        }
        let mut next = vec![0u8; (width * height * 4) as usize];
        let rows = height.min(self.height);
        let row_bytes = (width.min(self.width) * 4) as usize;
        for row in 0..rows as usize {
            let target = row * (width as usize * 4);
            let source = row * self.stride();
            next[target..target + row_bytes].copy_from_slice(&self.pixels[source..source + row_bytes]);
        }
        self.width = width;
        self.height = height;
        self.pixels = next;
        self.damage.clear();
        self.mark_dirty(DamageRect {
            left: 0,
            top: 0,
            width,
            height,
        });
    }

    /// Blits a decoded bitmap into the framebuffer and records the damage.
    pub fn blit(&mut self, rect: DamageRect, data: &[u8]) {
        let rect = rect.clamped(self.width, self.height);
        if rect.is_empty() {
            return;
        }
        let expected = (rect.width * rect.height * 4) as usize;
        if data.len() < expected {
            // A truncated update would smear stale pixels across the screen, so
            // it is dropped instead.
            tracing::warn!(expected, got = data.len(), "dropping a truncated bitmap update");
            return;
        }
        for row in 0..rect.height {
            let target = ((rect.top + row) * self.width + rect.left) as usize * 4;
            let source = (row * rect.width) as usize * 4;
            self.pixels[target..target + (rect.width as usize * 4)]
                .copy_from_slice(&data[source..source + (rect.width as usize * 4)]);
        }
        self.mark_dirty(rect);
    }

    /// Fills a rectangle with a solid colour (used by surface commands).
    pub fn fill(&mut self, rect: DamageRect, bgra: [u8; 4]) {
        let rect = rect.clamped(self.width, self.height);
        for row in 0..rect.height {
            let start = ((rect.top + row) * self.width + rect.left) as usize * 4;
            for column in 0..rect.width as usize {
                let at = start + column * 4;
                self.pixels[at..at + 4].copy_from_slice(&bgra);
            }
        }
        self.mark_dirty(rect);
    }

    /// Records additional damage.
    pub fn mark_dirty(&mut self, rect: DamageRect) {
        match self.damage.last_mut() {
            // Keeping a single bounding box is enough for a texture upload and
            // avoids unbounded growth during scrolling.
            Some(last) => *last = last.union(rect),
            None => self.damage.push(rect),
        }
    }

    /// Takes the accumulated damage, clearing it.
    pub fn take_damage(&mut self) -> Vec<DamageRect> {
        std::mem::take(&mut self.damage)
    }

    /// True when something changed since the last frame.
    pub fn is_dirty(&self) -> bool {
        !self.damage.is_empty()
    }
}

impl fmt::Display for Framebuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}x{} BGRA", self.width, self.height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_framebuffer_is_black() {
        let buffer = Framebuffer::new(4, 2);
        assert_eq!(buffer.pixels().len(), 4 * 2 * 4);
        assert!(buffer.pixels().iter().all(|byte| *byte == 0));
        assert!(!buffer.is_dirty());
        assert_eq!(buffer.stride(), 16);
    }

    #[test]
    fn blitting_records_damage() {
        let mut buffer = Framebuffer::new(4, 4);
        let rect = DamageRect { left: 1, top: 1, width: 2, height: 2 };
        buffer.blit(rect, &vec![0xAA; 2 * 2 * 4]);
        assert!(buffer.is_dirty());
        let damage = buffer.take_damage();
        assert_eq!(damage, vec![rect]);
        assert!(!buffer.is_dirty());
        assert_eq!(buffer.pixels()[(1 * 4 + 1) * 4], 0xAA);
    }

    #[test]
    fn blits_are_clamped_to_the_buffer() {
        let mut buffer = Framebuffer::new(2, 2);
        buffer.blit(
            DamageRect { left: 1, top: 1, width: 10, height: 10 },
            &vec![0x11; 10 * 10 * 4],
        );
        assert_eq!(buffer.take_damage(), vec![DamageRect { left: 1, top: 1, width: 1, height: 1 }]);
    }

    #[test]
    fn truncated_updates_are_dropped() {
        let mut buffer = Framebuffer::new(4, 4);
        buffer.blit(DamageRect { left: 0, top: 0, width: 4, height: 4 }, &[0xFF; 8]);
        assert!(!buffer.is_dirty());
        assert!(buffer.pixels().iter().all(|byte| *byte == 0));
    }

    #[test]
    fn damage_merges_into_a_bounding_box() {
        let mut buffer = Framebuffer::new(8, 8);
        buffer.mark_dirty(DamageRect { left: 0, top: 0, width: 2, height: 2 });
        buffer.mark_dirty(DamageRect { left: 4, top: 4, width: 2, height: 2 });
        assert_eq!(
            buffer.take_damage(),
            vec![DamageRect { left: 0, top: 0, width: 6, height: 6 }]
        );
    }

    #[test]
    fn resizing_preserves_the_overlap() {
        let mut buffer = Framebuffer::new(2, 2);
        buffer.fill(DamageRect { left: 0, top: 0, width: 2, height: 2 }, [1, 2, 3, 4]);
        buffer.resize(4, 4);
        assert_eq!(buffer.width(), 4);
        assert_eq!(buffer.pixels()[0..4], [1, 2, 3, 4]);
        assert_eq!(buffer.pixels()[(3 * 4 + 3) * 4..], [0, 0, 0, 0]);
        assert!(buffer.is_dirty());
    }

    #[test]
    fn rectangles_union_and_clamp() {
        let a = DamageRect { left: 0, top: 0, width: 2, height: 2 };
        let b = DamageRect { left: 3, top: 3, width: 2, height: 2 };
        assert_eq!(a.union(b), DamageRect { left: 0, top: 0, width: 5, height: 5 });
        assert!(DamageRect::default().is_empty());
        assert_eq!(DamageRect::default().union(a), a);
        assert_eq!(
            b.clamped(4, 4),
            DamageRect { left: 3, top: 3, width: 1, height: 1 }
        );
    }

    #[test]
    fn the_buffer_describes_itself() {
        assert_eq!(Framebuffer::new(800, 600).to_string(), "800x600 BGRA");
    }
}
