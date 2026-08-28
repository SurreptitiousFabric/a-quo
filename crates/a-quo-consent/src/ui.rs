use std::collections::HashMap;
use std::fs;
use std::num::NonZeroU32;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use a_quo_approval::{ApprovalDecision, ApprovalPrompt};
use softbuffer::{Context, Surface};
use swash::{
    CacheKey, FontRef, GlyphId,
    scale::{Render, ScaleContext, Source, image::Content, image::Image},
    shape::ShapeContext,
    zeno::Format,
};
use thiserror::Error;
use tiny_skia::{Color, Paint, Pixmap, Rect, Transform};
use winit::application::ApplicationHandler;
use winit::dpi::{LogicalSize, PhysicalPosition};
use winit::event::{ElementState, MouseButton, WindowEvent};
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop};
use winit::keyboard::{Key, ModifiersState, NamedKey};
use winit::platform::wayland::WindowAttributesExtWayland;
use winit::window::{CursorIcon, Theme, Window, WindowId};

const WINDOW_WIDTH: f64 = 780.0;
const WINDOW_HEIGHT: f64 = 760.0;
const CONSENT_DEADLINE: Duration = Duration::from_secs(90);
const FONT_LIMIT_BYTES: u64 = 4 * 1024 * 1024;
const FONT_PATHS: &[&str] = &[
    "/usr/share/fonts/noto/NotoSans-Regular.ttf",
    "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
];

const BACKGROUND: Rgb = Rgb(13, 17, 23);
const PANEL: Rgb = Rgb(23, 29, 38);
const PANEL_RAISED: Rgb = Rgb(29, 37, 48);
const BORDER: Rgb = Rgb(57, 68, 84);
const ACCENT: Rgb = Rgb(93, 211, 194);
const ACCENT_DARK: Rgb = Rgb(22, 91, 84);
const WARNING: Rgb = Rgb(245, 190, 78);
const TEXT: Rgb = Rgb(242, 245, 249);
const MUTED: Rgb = Rgb(165, 176, 191);
const DISABLED: Rgb = Rgb(84, 94, 108);

#[derive(Debug, Error)]
pub enum UiError {
    #[error("no trusted packaged font is available")]
    FontUnavailable,

    #[error("packaged font is unsafe: {0}")]
    UnsafeFont(PathBuf),

    #[error("cannot read packaged font: {0}")]
    FontRead(PathBuf),

    #[error("packaged font contains no usable face")]
    InvalidFont,

    #[error("cannot start the Wayland event loop")]
    EventLoop,

    #[error("cannot create the Wayland consent window")]
    Window,

    #[error("cannot render the Wayland consent window")]
    Render,

    #[error("the consent window ended without a decision")]
    NoDecision,
}

pub fn show(prompt: ApprovalPrompt) -> Result<ApprovalDecision, UiError> {
    let text_engine = trusted_text_engine()?;
    let event_loop = EventLoop::new().map_err(|_| UiError::EventLoop)?;
    event_loop.set_control_flow(ControlFlow::Wait);
    let mut application = ConsentApplication::new(prompt, text_engine);
    event_loop
        .run_app(&mut application)
        .map_err(|_| UiError::EventLoop)?;
    if let Some(failure) = application.failure {
        return Err(failure.into_error());
    }
    application.decision.ok_or(UiError::NoDecision)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Failure {
    Window,
    Render,
}

impl Failure {
    fn into_error(self) -> UiError {
        match self {
            Self::Window => UiError::Window,
            Self::Render => UiError::Render,
        }
    }
}

struct ConsentApplication {
    prompt: ApprovalPrompt,
    window: Option<ConsentWindow>,
    interaction: Interaction,
    modifiers: ModifiersState,
    cursor: Option<PhysicalPosition<f64>>,
    started: Instant,
    next_tick: Instant,
    decision: Option<ApprovalDecision>,
    failure: Option<Failure>,
    text_engine: TextEngine,
}

impl ConsentApplication {
    fn new(prompt: ApprovalPrompt, text_engine: TextEngine) -> Self {
        let started = Instant::now();
        Self {
            prompt,
            window: None,
            interaction: Interaction::default(),
            modifiers: ModifiersState::empty(),
            cursor: None,
            started,
            next_tick: started + Duration::from_secs(1),
            decision: None,
            failure: None,
            text_engine,
        }
    }

    fn finish(&mut self, event_loop: &ActiveEventLoop, decision: ApprovalDecision) {
        if self.decision.is_none() && self.failure.is_none() {
            self.decision = Some(decision);
        }
        event_loop.exit();
    }

    fn fail(&mut self, event_loop: &ActiveEventLoop, failure: Failure) {
        self.failure = Some(failure);
        event_loop.exit();
    }

    fn redraw(&self) {
        if let Some(window) = &self.window {
            window.window.request_redraw();
        }
    }

    fn activate_control(&mut self, event_loop: &ActiveEventLoop, control: Control) {
        if self.started.elapsed() >= CONSENT_DEADLINE {
            self.finish(event_loop, ApprovalDecision::Cancel);
            return;
        }
        match self.interaction.activate(control) {
            Some(decision) => self.finish(event_loop, decision),
            None => self.redraw(),
        }
    }

    fn current_control(&self) -> Option<Control> {
        let window = self.window.as_ref()?;
        let cursor = self.cursor?;
        let scale = window.window.scale_factor();
        let logical_width = f64::from(window.window.inner_size().width) / scale;
        let logical_height = f64::from(window.window.inner_size().height) / scale;
        controls(logical_width, logical_height).at(cursor.x / scale, cursor.y / scale)
    }
}

impl ApplicationHandler for ConsentApplication {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.window.is_some() {
            return;
        }
        let size = LogicalSize::new(WINDOW_WIDTH, WINDOW_HEIGHT);
        let attributes = Window::default_attributes()
            .with_title("A Quo — signing approval")
            .with_inner_size(size)
            .with_min_inner_size(size)
            .with_max_inner_size(size)
            .with_resizable(false)
            .with_decorations(false)
            .with_theme(Some(Theme::Dark))
            .with_name("a-quo-consent", "a-quo-consent");
        let window = match event_loop.create_window(attributes) {
            Ok(window) => window,
            Err(_) => {
                self.fail(event_loop, Failure::Window);
                return;
            }
        };
        match ConsentWindow::new(window) {
            Ok(window) => {
                self.window = Some(window);
                self.redraw();
            }
            Err(()) => self.fail(event_loop, Failure::Render),
        }
    }

    fn window_event(
        &mut self,
        event_loop: &ActiveEventLoop,
        window_id: WindowId,
        event: WindowEvent,
    ) {
        if self
            .window
            .as_ref()
            .is_none_or(|window| window.window.id() != window_id)
        {
            return;
        }
        match event {
            WindowEvent::CloseRequested => self.finish(event_loop, ApprovalDecision::Cancel),
            WindowEvent::Focused(false) => {
                self.interaction.reset_for_focus_loss();
                self.modifiers = ModifiersState::empty();
                self.redraw();
            }
            WindowEvent::ModifiersChanged(modifiers) => self.modifiers = modifiers.state(),
            WindowEvent::CursorMoved { position, .. } => {
                self.cursor = Some(position);
                let icon = if self.current_control().is_some() {
                    CursorIcon::Pointer
                } else {
                    CursorIcon::Default
                };
                if let Some(window) = &self.window {
                    window.window.set_cursor(icon);
                    window.window.set_cursor_visible(true);
                }
            }
            WindowEvent::CursorEntered { .. } => {
                if let Some(window) = &self.window {
                    window.window.set_cursor(CursorIcon::Default);
                    window.window.set_cursor_visible(false);
                }
            }
            WindowEvent::CursorLeft { .. } => {
                self.cursor = None;
                if let Some(window) = &self.window {
                    window.window.set_cursor(CursorIcon::Default);
                    window.window.set_cursor_visible(false);
                }
            }
            WindowEvent::MouseInput {
                state,
                button: MouseButton::Left,
                ..
            } => {
                let control = self.current_control();
                match state {
                    ElementState::Pressed => self.interaction.pressed = control,
                    ElementState::Released => {
                        if let Some(pressed) = self.interaction.pressed.take()
                            && Some(pressed) == control
                        {
                            self.activate_control(event_loop, pressed);
                        }
                    }
                }
            }
            WindowEvent::KeyboardInput {
                event,
                is_synthetic: false,
                ..
            } if event.state == ElementState::Pressed && !event.repeat => match event.logical_key {
                Key::Named(NamedKey::Escape) => {
                    self.finish(event_loop, ApprovalDecision::Cancel);
                }
                Key::Named(NamedKey::Tab) => {
                    self.interaction.focus_next(self.modifiers.shift_key());
                    self.redraw();
                }
                Key::Named(NamedKey::Enter | NamedKey::Space) => {
                    self.activate_control(event_loop, self.interaction.focus);
                }
                _ => {}
            },
            WindowEvent::RedrawRequested => {
                let elapsed = self.started.elapsed();
                let remaining = CONSENT_DEADLINE.saturating_sub(elapsed).as_secs();
                let Some(window) = self.window.as_mut() else {
                    return;
                };
                if window
                    .render(
                        &self.prompt,
                        &self.interaction,
                        remaining,
                        &mut self.text_engine,
                    )
                    .is_err()
                {
                    self.fail(event_loop, Failure::Render);
                }
            }
            _ => {}
        }
    }

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        let now = Instant::now();
        let deadline = self.started + CONSENT_DEADLINE;
        if now >= deadline {
            self.finish(event_loop, ApprovalDecision::Cancel);
            return;
        }
        if now >= self.next_tick {
            self.next_tick = now + Duration::from_secs(1);
            self.redraw();
        }
        event_loop.set_control_flow(ControlFlow::WaitUntil(self.next_tick.min(deadline)));
    }

    fn exiting(&mut self, _event_loop: &ActiveEventLoop) {
        self.window = None;
    }
}

struct ConsentWindow {
    surface: Surface<Arc<Window>, Arc<Window>>,
    _context: Context<Arc<Window>>,
    window: Arc<Window>,
}

impl ConsentWindow {
    fn new(window: Window) -> Result<Self, ()> {
        let window = Arc::new(window);
        let context = Context::new(Arc::clone(&window)).map_err(|_| ())?;
        let surface = Surface::new(&context, Arc::clone(&window)).map_err(|_| ())?;
        window.set_cursor(CursorIcon::Default);
        window.set_cursor_visible(false);
        Ok(Self {
            surface,
            _context: context,
            window,
        })
    }

    fn render(
        &mut self,
        prompt: &ApprovalPrompt,
        interaction: &Interaction,
        remaining_seconds: u64,
        text_engine: &mut TextEngine,
    ) -> Result<(), ()> {
        let size = self.window.inner_size();
        let (Some(width), Some(height)) =
            (NonZeroU32::new(size.width), NonZeroU32::new(size.height))
        else {
            return Ok(());
        };
        self.surface.resize(width, height).map_err(|_| ())?;
        let mut pixmap = Pixmap::new(size.width, size.height).ok_or(())?;
        pixmap.fill(BACKGROUND.color());
        let scale = self.window.scale_factor() as f32;
        let logical_width = size.width as f32 / scale;
        let logical_height = size.height as f32 / scale;
        draw_content(
            &mut pixmap,
            scale,
            logical_width,
            logical_height,
            prompt,
            interaction,
            remaining_seconds,
            text_engine,
        );

        let mut buffer = self.surface.buffer_mut().map_err(|_| ())?;
        if buffer.len() != pixmap.data().len() / 4 {
            return Err(());
        }
        let (pixels, remainder) = pixmap.data().as_chunks::<4>();
        debug_assert!(remainder.is_empty());
        for (destination, pixel) in buffer.iter_mut().zip(pixels) {
            *destination =
                (u32::from(pixel[0]) << 16) | (u32::from(pixel[1]) << 8) | u32::from(pixel[2]);
        }
        buffer.present().map_err(|_| ())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Control {
    Cancel,
    Confirm,
    Approve,
}

#[derive(Clone, Copy, Debug)]
struct Interaction {
    confirmed: bool,
    focus: Control,
    pressed: Option<Control>,
}

impl Default for Interaction {
    fn default() -> Self {
        Self {
            confirmed: false,
            focus: Control::Cancel,
            pressed: None,
        }
    }
}

impl Interaction {
    fn reset_for_focus_loss(&mut self) {
        self.confirmed = false;
        self.focus = Control::Cancel;
        self.pressed = None;
    }

    fn focus_next(&mut self, reverse: bool) {
        self.focus = match (self.focus, reverse, self.confirmed) {
            (Control::Cancel, false, _) => Control::Confirm,
            (Control::Confirm, false, true) => Control::Approve,
            (Control::Confirm, false, false) | (Control::Approve, false, _) => Control::Cancel,
            (Control::Cancel, true, true) => Control::Approve,
            (Control::Cancel, true, false) | (Control::Approve, true, _) => Control::Confirm,
            (Control::Confirm, true, _) => Control::Cancel,
        };
    }

    fn activate(&mut self, control: Control) -> Option<ApprovalDecision> {
        match control {
            Control::Cancel => Some(ApprovalDecision::Decline),
            Control::Confirm => {
                self.confirmed = !self.confirmed;
                if !self.confirmed && self.focus == Control::Approve {
                    self.focus = Control::Confirm;
                }
                None
            }
            Control::Approve if self.confirmed => Some(ApprovalDecision::Approve),
            Control::Approve => None,
        }
    }
}

#[derive(Clone, Copy)]
struct Rgb(u8, u8, u8);

impl Rgb {
    fn color(self) -> Color {
        Color::from_rgba8(self.0, self.1, self.2, 255)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Align {
    Center,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Weight {
    Normal,
    Bold,
}

impl Weight {
    const NORMAL: Self = Self::Normal;
    const BOLD: Self = Self::Bold;
}

#[derive(Clone, Copy, Debug)]
struct UiRect {
    x: f32,
    y: f32,
    width: f32,
    height: f32,
}

impl UiRect {
    fn contains(self, x: f64, y: f64) -> bool {
        x >= f64::from(self.x)
            && x <= f64::from(self.x + self.width)
            && y >= f64::from(self.y)
            && y <= f64::from(self.y + self.height)
    }
}

struct Controls {
    confirm: UiRect,
    cancel: UiRect,
    approve: UiRect,
}

impl Controls {
    fn at(&self, x: f64, y: f64) -> Option<Control> {
        if self.confirm.contains(x, y) {
            Some(Control::Confirm)
        } else if self.cancel.contains(x, y) {
            Some(Control::Cancel)
        } else if self.approve.contains(x, y) {
            Some(Control::Approve)
        } else {
            None
        }
    }
}

fn controls(width: f64, height: f64) -> Controls {
    Controls {
        confirm: UiRect {
            x: 40.0,
            y: height as f32 - 154.0,
            width: width as f32 - 80.0,
            height: 54.0,
        },
        cancel: UiRect {
            x: width as f32 - 326.0,
            y: height as f32 - 82.0,
            width: 132.0,
            height: 46.0,
        },
        approve: UiRect {
            x: width as f32 - 182.0,
            y: height as f32 - 82.0,
            width: 142.0,
            height: 46.0,
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn draw_content(
    pixmap: &mut Pixmap,
    scale: f32,
    width: f32,
    height: f32,
    prompt: &ApprovalPrompt,
    interaction: &Interaction,
    remaining_seconds: u64,
    text_engine: &mut TextEngine,
) {
    let mut text = TextPainter {
        pixmap,
        scale,
        engine: text_engine,
    };

    fill_rect(
        text.pixmap,
        scale,
        UiRect {
            x: 0.0,
            y: 0.0,
            width,
            height: 6.0,
        },
        ACCENT,
    );
    text.draw(
        "A QUO  ·  DIRECT WAYLAND  ·  NO D-BUS",
        UiRect {
            x: 40.0,
            y: 25.0,
            width: width - 80.0,
            height: 22.0,
        },
        12.0,
        Weight::BOLD,
        ACCENT,
        None,
    );
    text.draw(
        "Sign these exact bytes?",
        UiRect {
            x: 40.0,
            y: 52.0,
            width: width - 80.0,
            height: 46.0,
        },
        29.0,
        Weight::BOLD,
        TEXT,
        None,
    );
    text.draw(
        "Check the persona, immutable SHA-256 digest, and key. The name below came from the requesting app.",
        UiRect {
            x: 40.0,
            y: 101.0,
            width: width - 80.0,
            height: 43.0,
        },
        14.0,
        Weight::NORMAL,
        MUTED,
        None,
    );

    let panel = UiRect {
        x: 40.0,
        y: 150.0,
        width: width - 80.0,
        height: 390.0,
    };
    outlined_panel(text.pixmap, scale, panel, PANEL, BORDER);

    draw_field(
        &mut text,
        "PERSONA",
        &truncate_middle(&prompt.persona_label, 72),
        62.0,
        172.0,
        width - 124.0,
    );
    draw_field(
        &mut text,
        "CALLER-SUPPLIED ARTIFACT LABEL",
        &truncate_middle(&prompt.artifact_label, 96),
        62.0,
        226.0,
        width - 124.0,
    );

    let facts = format!(
        "Purpose: {}    •    Type: {}    •    Size: {}",
        prompt.persona_purpose.label(),
        prompt.artifact_kind.label(),
        format_size(prompt.artifact_size)
    );
    text.draw(
        &facts,
        UiRect {
            x: 62.0,
            y: 284.0,
            width: width - 124.0,
            height: 28.0,
        },
        13.0,
        Weight::NORMAL,
        MUTED,
        None,
    );

    let digest = prompt.sha256_hex();
    let digest = format!("{}\n{}", &digest[..32], &digest[32..]);
    draw_field(
        &mut text,
        "IMMUTABLE SHA-256",
        &digest,
        62.0,
        324.0,
        width - 124.0,
    );
    draw_field(
        &mut text,
        "SIGNING KEY FINGERPRINT",
        &prompt.key_fingerprint,
        62.0,
        400.0,
        width - 124.0,
    );

    let caller = format!(
        "Request {}    •    caller PID {} / UID {}",
        prompt.request_id, prompt.peer.pid, prompt.peer.uid
    );
    text.draw(
        &caller,
        UiRect {
            x: 62.0,
            y: 470.0,
            width: width - 124.0,
            height: 26.0,
        },
        11.0,
        Weight::NORMAL,
        MUTED,
        None,
    );

    fill_rect(
        text.pixmap,
        scale,
        UiRect {
            x: 62.0,
            y: 504.0,
            width: 4.0,
            height: 20.0,
        },
        WARNING,
    );
    text.draw(
        "A valid signature proves these bytes and this key—not safety, truth, or legal identity.",
        UiRect {
            x: 76.0,
            y: 503.0,
            width: width - 142.0,
            height: 24.0,
        },
        12.5,
        Weight::BOLD,
        WARNING,
        None,
    );

    let controls = controls(f64::from(width), f64::from(height));
    draw_checkbox(&mut text, controls.confirm, interaction);
    draw_button(
        &mut text,
        controls.cancel,
        "Decline",
        interaction.focus == Control::Cancel,
        true,
        false,
    );
    draw_button(
        &mut text,
        controls.approve,
        "Sign bytes",
        interaction.focus == Control::Approve,
        interaction.confirmed,
        true,
    );

    let footer = format!(
        "Esc cancels  •  focus loss resets confirmation  •  expires in {remaining_seconds}s"
    );
    text.draw(
        &footer,
        UiRect {
            x: 40.0,
            y: height - 27.0,
            width: width - 80.0,
            height: 18.0,
        },
        10.5,
        Weight::NORMAL,
        MUTED,
        Some(Align::Center),
    );
}

fn draw_field(text: &mut TextPainter<'_>, label: &str, value: &str, x: f32, y: f32, width: f32) {
    text.draw(
        label,
        UiRect {
            x,
            y,
            width,
            height: 18.0,
        },
        10.5,
        Weight::BOLD,
        ACCENT,
        None,
    );
    text.draw(
        value,
        UiRect {
            x,
            y: y + 18.0,
            width,
            height: 46.0,
        },
        15.0,
        Weight::NORMAL,
        TEXT,
        None,
    );
}

fn draw_checkbox(text: &mut TextPainter<'_>, rect: UiRect, interaction: &Interaction) {
    let border = if interaction.focus == Control::Confirm {
        ACCENT
    } else {
        BORDER
    };
    outlined_panel(text.pixmap, text.scale, rect, PANEL_RAISED, border);
    let box_rect = UiRect {
        x: rect.x + 14.0,
        y: rect.y + 15.0,
        width: 24.0,
        height: 24.0,
    };
    outlined_panel(
        text.pixmap,
        text.scale,
        box_rect,
        if interaction.confirmed {
            ACCENT_DARK
        } else {
            PANEL
        },
        if interaction.confirmed { ACCENT } else { MUTED },
    );
    if interaction.confirmed {
        text.draw("✓", box_rect, 17.0, Weight::BOLD, TEXT, Some(Align::Center));
    }
    text.draw(
        "I intend to sign exactly this SHA-256 digest with this persona.",
        UiRect {
            x: rect.x + 50.0,
            y: rect.y + 15.0,
            width: rect.width - 62.0,
            height: 28.0,
        },
        13.0,
        Weight::BOLD,
        TEXT,
        None,
    );
}

#[allow(clippy::too_many_arguments)]
fn draw_button(
    text: &mut TextPainter<'_>,
    rect: UiRect,
    label: &str,
    focused: bool,
    enabled: bool,
    primary: bool,
) {
    let fill = if !enabled {
        PANEL_RAISED
    } else if primary {
        ACCENT_DARK
    } else {
        PANEL_RAISED
    };
    let border = if focused { ACCENT } else { BORDER };
    outlined_panel(text.pixmap, text.scale, rect, fill, border);
    text.draw(
        label,
        UiRect {
            x: rect.x,
            y: rect.y + 11.0,
            width: rect.width,
            height: 25.0,
        },
        13.0,
        Weight::BOLD,
        if enabled { TEXT } else { DISABLED },
        Some(Align::Center),
    );
}

struct TrustedFont {
    data: Vec<u8>,
    offset: u32,
    key: CacheKey,
}

impl TrustedFont {
    fn new(data: Vec<u8>) -> Option<Self> {
        let (offset, key) = {
            let font = FontRef::from_index(&data, 0)?;
            (font.offset, font.key)
        };
        Some(Self { data, offset, key })
    }

    fn as_ref(&self) -> FontRef<'_> {
        FontRef {
            data: &self.data,
            offset: self.offset,
            key: self.key,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct ShapedGlyph {
    id: GlyphId,
    x: f32,
    y: f32,
}

#[derive(Debug)]
struct ShapedLine {
    glyphs: Vec<ShapedGlyph>,
    width: f32,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct GlyphCacheKey {
    id: GlyphId,
    size_bits: u32,
    bold: bool,
}

struct TextEngine {
    font: TrustedFont,
    shape_context: ShapeContext,
    scale_context: ScaleContext,
    glyph_cache: HashMap<GlyphCacheKey, Option<Image>>,
}

impl TextEngine {
    fn new(data: Vec<u8>) -> Option<Self> {
        Some(Self {
            font: TrustedFont::new(data)?,
            shape_context: ShapeContext::new(),
            scale_context: ScaleContext::new(),
            glyph_cache: HashMap::new(),
        })
    }

    fn ascent(&self, font_size: f32) -> f32 {
        self.font.as_ref().metrics(&[]).scale(font_size).ascent
    }

    fn shape_line(&mut self, value: &str, font_size: f32) -> ShapedLine {
        let font = self.font.as_ref();
        let mut shaper = self.shape_context.builder(font).size(font_size).build();
        shaper.add_str(value);

        let mut glyphs = Vec::new();
        let mut cursor = 0.0_f32;
        shaper.shape_with(|cluster| {
            for glyph in cluster.glyphs {
                glyphs.push(ShapedGlyph {
                    id: glyph.id,
                    x: cursor + glyph.x,
                    y: glyph.y,
                });
                cursor += glyph.advance;
            }
        });
        ShapedLine {
            glyphs,
            width: cursor.max(0.0),
        }
    }

    fn layout_lines(&mut self, value: &str, font_size: f32, max_width: f32) -> Vec<ShapedLine> {
        let mut lines = Vec::new();
        for paragraph in value.split('\n') {
            if paragraph.is_empty() {
                lines.push(self.shape_line("", font_size));
                continue;
            }

            let mut start = 0;
            while start < paragraph.len() {
                let mut best_end = start;
                let mut first_end = None;
                let mut last_break = None;
                for (relative, character) in paragraph[start..].char_indices() {
                    let end = start + relative + character.len_utf8();
                    first_end.get_or_insert(end);
                    if self.shape_line(&paragraph[start..end], font_size).width <= max_width {
                        best_end = end;
                        if character.is_whitespace() {
                            last_break = Some(end);
                        }
                    } else {
                        break;
                    }
                }

                let line_end = if best_end == paragraph.len() {
                    best_end
                } else {
                    last_break
                        .filter(|end| *end > start)
                        .or((best_end > start).then_some(best_end))
                        .or(first_end)
                        .unwrap_or(paragraph.len())
                };
                let line = paragraph[start..line_end].trim_end_matches(char::is_whitespace);
                lines.push(self.shape_line(line, font_size));
                start = line_end;
                while let Some(character) = paragraph[start..].chars().next() {
                    if !character.is_whitespace() {
                        break;
                    }
                    start += character.len_utf8();
                }
            }
        }
        lines
    }

    fn glyph_image(&mut self, glyph_id: GlyphId, font_size: f32, weight: Weight) -> Option<&Image> {
        let key = GlyphCacheKey {
            id: glyph_id,
            size_bits: font_size.to_bits(),
            bold: weight == Weight::Bold,
        };
        if !self.glyph_cache.contains_key(&key) {
            let font = self.font.as_ref();
            let mut scaler = self
                .scale_context
                .builder(font)
                .size(font_size)
                .hint(true)
                .build();
            let sources = [Source::Outline];
            let mut renderer = Render::new(&sources);
            renderer.format(Format::Alpha);
            if weight == Weight::Bold {
                renderer.embolden((font_size * 0.025).max(0.25));
            }
            let image = renderer.render(&mut scaler, glyph_id);
            self.glyph_cache.insert(key, image);
        }
        self.glyph_cache.get(&key).and_then(Option::as_ref)
    }
}

struct TextPainter<'a> {
    pixmap: &'a mut Pixmap,
    scale: f32,
    engine: &'a mut TextEngine,
}

impl TextPainter<'_> {
    #[allow(clippy::too_many_arguments)]
    fn draw(
        &mut self,
        value: &str,
        rect: UiRect,
        font_size: f32,
        weight: Weight,
        color: Rgb,
        alignment: Option<Align>,
    ) {
        if rect.width <= 0.0 || rect.height <= 0.0 || font_size <= 0.0 {
            return;
        }
        let physical_size = font_size * self.scale;
        let physical_width = rect.width * self.scale;
        let line_height = physical_size * 1.35;
        let lines = self
            .engine
            .layout_lines(value, physical_size, physical_width);
        let maximum_lines = ((rect.height * self.scale) / line_height).floor().max(1.0) as usize;
        let origin_x = rect.x * self.scale;
        let origin_y = rect.y * self.scale;
        let clip = PixelClip {
            left: origin_x.floor() as i32,
            top: origin_y.floor() as i32,
            right: (origin_x + physical_width).ceil() as i32,
            bottom: (origin_y + rect.height * self.scale).ceil() as i32,
        };
        let ascent = self.engine.ascent(physical_size);

        for (line_index, line) in lines.into_iter().take(maximum_lines).enumerate() {
            let line_x = match alignment {
                Some(Align::Center) => ((physical_width - line.width) / 2.0).max(0.0),
                None => 0.0,
            };
            let baseline = origin_y + ascent + line_index as f32 * line_height;
            for glyph in line.glyphs {
                let x = (origin_x + line_x + glyph.x).round() as i32;
                let y = (baseline - glyph.y).round() as i32;
                if let Some(image) = self.engine.glyph_image(glyph.id, physical_size, weight) {
                    blend_glyph(self.pixmap, x, y, image, color, clip);
                }
            }
        }
    }
}

fn fill_rect(pixmap: &mut Pixmap, scale: f32, rect: UiRect, color: Rgb) {
    let Some(rect) = Rect::from_xywh(
        rect.x * scale,
        rect.y * scale,
        rect.width * scale,
        rect.height * scale,
    ) else {
        return;
    };
    let mut paint = Paint::default();
    paint.set_color(color.color());
    pixmap.fill_rect(rect, &paint, Transform::identity(), None);
}

fn outlined_panel(pixmap: &mut Pixmap, scale: f32, rect: UiRect, fill: Rgb, border: Rgb) {
    fill_rect(pixmap, scale, rect, border);
    let inset = (1.0 / scale).max(0.5);
    fill_rect(
        pixmap,
        scale,
        UiRect {
            x: rect.x + inset,
            y: rect.y + inset,
            width: (rect.width - inset * 2.0).max(0.0),
            height: (rect.height - inset * 2.0).max(0.0),
        },
        fill,
    );
}

#[derive(Clone, Copy)]
struct PixelClip {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}

fn blend_glyph(
    pixmap: &mut Pixmap,
    baseline_x: i32,
    baseline_y: i32,
    image: &Image,
    color: Rgb,
    clip: PixelClip,
) {
    if image.content != Content::Mask {
        return;
    }
    let pixmap_width = pixmap.width() as i32;
    let pixmap_height = pixmap.height() as i32;
    let x = baseline_x + image.placement.left;
    let y = baseline_y - image.placement.top;
    for offset_y in 0..image.placement.height as i32 {
        let pixel_y = y + offset_y;
        if pixel_y < 0 || pixel_y >= pixmap_height || pixel_y < clip.top || pixel_y >= clip.bottom {
            continue;
        }
        for offset_x in 0..image.placement.width as i32 {
            let pixel_x = x + offset_x;
            if pixel_x < 0
                || pixel_x >= pixmap_width
                || pixel_x < clip.left
                || pixel_x >= clip.right
            {
                continue;
            }
            let source_index =
                offset_y as usize * image.placement.width as usize + offset_x as usize;
            let Some(&mask) = image.data.get(source_index) else {
                return;
            };
            let alpha = u16::from(mask);
            let index = ((pixel_y * pixmap_width + pixel_x) * 4) as usize;
            let data = pixmap.data_mut();
            data[index] = blend_channel(color.0, data[index], alpha);
            data[index + 1] = blend_channel(color.1, data[index + 1], alpha);
            data[index + 2] = blend_channel(color.2, data[index + 2], alpha);
            data[index + 3] = 255;
        }
    }
}

fn blend_channel(source: u8, destination: u8, alpha: u16) -> u8 {
    let inverse = 255 - alpha;
    ((u16::from(source) * alpha + u16::from(destination) * inverse + 127) / 255) as u8
}

fn trusted_text_engine() -> Result<TextEngine, UiError> {
    let path = FONT_PATHS
        .iter()
        .map(Path::new)
        .find(|path| path.exists())
        .ok_or(UiError::FontUnavailable)?;
    validate_trusted_font_path(path)?;
    let data = fs::read(path).map_err(|_| UiError::FontRead(path.to_path_buf()))?;
    TextEngine::new(data).ok_or(UiError::InvalidFont)
}

fn validate_trusted_font_path(path: &Path) -> Result<(), UiError> {
    let mut components = path.ancestors().collect::<Vec<_>>();
    components.reverse();

    for component in components {
        let metadata =
            fs::symlink_metadata(component).map_err(|_| UiError::FontRead(path.to_path_buf()))?;
        let is_font = component == path;
        let wrong_type = if is_font {
            !metadata.file_type().is_file()
                || metadata.len() == 0
                || metadata.len() > FONT_LIMIT_BYTES
        } else {
            !metadata.file_type().is_dir()
        };
        if metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || wrong_type
        {
            return Err(UiError::UnsafeFont(path.to_path_buf()));
        }
    }

    Ok(())
}

fn truncate_middle(value: &str, maximum_characters: usize) -> String {
    let characters = value.chars().collect::<Vec<_>>();
    if characters.len() <= maximum_characters {
        return value.to_owned();
    }
    let tail = maximum_characters / 3;
    let head = maximum_characters - tail - 1;
    let mut output = characters[..head].iter().collect::<String>();
    output.push('…');
    output.extend(characters[characters.len() - tail..].iter());
    output
}

fn format_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    if bytes < KIB {
        format!("{bytes} bytes")
    } else if bytes < MIB {
        format!("{:.1} KiB ({bytes} bytes)", bytes as f64 / KIB as f64)
    } else {
        format!("{:.1} MiB ({bytes} bytes)", bytes as f64 / MIB as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_requires_the_exact_digest_confirmation() {
        let mut interaction = Interaction::default();
        assert_eq!(interaction.focus, Control::Cancel);
        assert_eq!(interaction.activate(Control::Approve), None);
        assert!(!interaction.confirmed);

        assert_eq!(interaction.activate(Control::Confirm), None);
        assert!(interaction.confirmed);
        assert_eq!(
            interaction.activate(Control::Approve),
            Some(ApprovalDecision::Approve)
        );
    }

    #[test]
    fn keyboard_focus_skips_disabled_approval() {
        let mut interaction = Interaction::default();
        interaction.focus_next(false);
        assert_eq!(interaction.focus, Control::Confirm);
        interaction.focus_next(false);
        assert_eq!(interaction.focus, Control::Cancel);

        interaction.activate(Control::Confirm);
        interaction.focus = Control::Confirm;
        interaction.focus_next(false);
        assert_eq!(interaction.focus, Control::Approve);
    }

    #[test]
    fn focus_loss_disarms_approval_and_clears_a_click() {
        let mut interaction = Interaction {
            confirmed: true,
            focus: Control::Approve,
            pressed: Some(Control::Approve),
        };
        interaction.reset_for_focus_loss();
        assert!(!interaction.confirmed);
        assert_eq!(interaction.focus, Control::Cancel);
        assert_eq!(interaction.pressed, None);
    }

    #[test]
    fn display_helpers_are_bounded_and_unambiguous() {
        let long = "beginning-abcdefghijklmnopqrstuvwxyz-ending.tar.zst";
        let shortened = truncate_middle(long, 24);
        assert_eq!(shortened.chars().count(), 24);
        assert!(shortened.starts_with("beginning-"));
        assert!(shortened.ends_with("tar.zst"));
        assert_eq!(format_size(42), "42 bytes");
        assert_eq!(format_size(1024), "1.0 KiB (1024 bytes)");
    }
}
