use std::collections::HashMap;
use std::fs;
use std::num::NonZeroU32;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use a_quo_approval::{
    ApprovalDecision, ApprovalPrompt, ApprovalSubject, ArtifactApproval, DomainApproval,
    PersonaRootApproval, PersonaTransitionApproval, RecoveryParticipationApproval,
};
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
const TRANSITION_WINDOW_HEIGHT: f64 = 900.0;
const RECOVERY_WINDOW_HEIGHT: f64 = 900.0;
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
        let review_surface_ready = self.review_surface_ready();
        match self.interaction.activate_for_subject(
            control,
            review_surface_ready,
            &self.prompt.subject,
        ) {
            Some(decision) => self.finish(event_loop, decision),
            None => self.redraw(),
        }
    }

    fn review_surface_ready(&self) -> bool {
        self.window
            .as_ref()
            .is_some_and(|window| window.review_surface_ready(&self.prompt.subject))
    }

    fn current_control(&self) -> Option<Control> {
        let window = self.window.as_ref()?;
        let cursor = self.cursor?;
        let scale = window.window.scale_factor();
        let logical_width = f64::from(window.window.inner_size().width) / scale;
        let logical_height = f64::from(window.window.inner_size().height) / scale;
        control_at_for_subject(
            logical_width,
            logical_height,
            self.review_surface_ready(),
            cursor.x / scale,
            cursor.y / scale,
            &self.prompt.subject,
            &self.interaction,
        )
    }
}

impl ApplicationHandler for ConsentApplication {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.window.is_some() {
            return;
        }
        let size = LogicalSize::new(WINDOW_WIDTH, window_height(&self.prompt.subject));
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
                    let review_surface_ready = self.review_surface_ready();
                    self.interaction.focus_next_for_subject(
                        self.modifiers.shift_key(),
                        review_surface_ready,
                        &self.prompt.subject,
                    );
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
                let review_surface_ready = self.review_surface_ready();
                if !review_surface_ready {
                    self.interaction.reset_for_incomplete_surface();
                }
                let Some(window) = self.window.as_mut() else {
                    return;
                };
                if window
                    .render(
                        &self.prompt,
                        &self.interaction,
                        remaining,
                        review_surface_ready,
                        &mut self.text_engine,
                    )
                    .is_err()
                {
                    self.fail(event_loop, Failure::Render);
                }
            }
            WindowEvent::Resized(_)
            | WindowEvent::Moved(_)
            | WindowEvent::ScaleFactorChanged { .. } => {
                if !self.review_surface_ready() {
                    self.interaction.reset_for_incomplete_surface();
                }
                self.redraw();
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
        review_surface_ready: bool,
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
            review_surface_ready,
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

    fn review_surface_ready(&self, subject: &ApprovalSubject) -> bool {
        let required_height = match subject {
            ApprovalSubject::PersonaTransition(_) => TRANSITION_WINDOW_HEIGHT,
            ApprovalSubject::RecoveryParticipation(_) => RECOVERY_WINDOW_HEIGHT,
            ApprovalSubject::Artifact(_)
            | ApprovalSubject::Domain(_)
            | ApprovalSubject::PersonaRoot(_) => return true,
        };
        if !matches!(
            subject,
            ApprovalSubject::PersonaTransition(_) | ApprovalSubject::RecoveryParticipation(_)
        ) {
            return true;
        }

        let size = self.window.inner_size();
        let window_dimensions =
            logical_dimensions(size.width, size.height, self.window.scale_factor());
        let output_dimensions = self.window.current_monitor().and_then(|monitor| {
            let size = monitor.size();
            logical_dimensions(size.width, size.height, monitor.scale_factor())
        });
        detailed_review_fits(window_dimensions, output_dimensions, required_height)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Control {
    Back,
    Cancel,
    Confirm,
    Next,
    Approve,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveryPage {
    Evidence,
    Transition,
}

#[derive(Clone, Copy, Debug)]
struct Interaction {
    confirmed: bool,
    focus: Control,
    pressed: Option<Control>,
    recovery_page: RecoveryPage,
}

impl Default for Interaction {
    fn default() -> Self {
        Self {
            confirmed: false,
            focus: Control::Cancel,
            pressed: None,
            recovery_page: RecoveryPage::Evidence,
        }
    }
}

impl Interaction {
    fn reset_for_focus_loss(&mut self) {
        self.reset_for_incomplete_surface();
    }

    fn reset_for_incomplete_surface(&mut self) {
        self.confirmed = false;
        self.focus = Control::Cancel;
        self.pressed = None;
        self.recovery_page = RecoveryPage::Evidence;
    }

    fn focus_next(&mut self, reverse: bool, review_surface_ready: bool) {
        if !review_surface_ready {
            self.reset_for_incomplete_surface();
            return;
        }
        self.focus = match (self.focus, reverse, self.confirmed) {
            (Control::Cancel, false, _) => Control::Confirm,
            (Control::Confirm, false, true) => Control::Approve,
            (Control::Confirm, false, false) | (Control::Approve, false, _) => Control::Cancel,
            (Control::Cancel, true, true) => Control::Approve,
            (Control::Cancel, true, false) | (Control::Approve, true, _) => Control::Confirm,
            (Control::Confirm, true, _) => Control::Cancel,
            (Control::Back | Control::Next, _, _) => Control::Cancel,
        };
    }

    fn activate(
        &mut self,
        control: Control,
        review_surface_ready: bool,
    ) -> Option<ApprovalDecision> {
        if !review_surface_ready {
            self.reset_for_incomplete_surface();
            return (control == Control::Cancel).then_some(ApprovalDecision::Decline);
        }
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
            Control::Back | Control::Next => None,
        }
    }

    fn focus_next_for_subject(
        &mut self,
        reverse: bool,
        review_surface_ready: bool,
        subject: &ApprovalSubject,
    ) {
        if !matches!(subject, ApprovalSubject::RecoveryParticipation(_)) {
            self.focus_next(reverse, review_surface_ready);
            return;
        }
        if !review_surface_ready {
            self.reset_for_incomplete_surface();
            return;
        }
        self.focus = match (self.recovery_page, self.focus, reverse, self.confirmed) {
            (RecoveryPage::Evidence, Control::Cancel, false, _) => Control::Next,
            (RecoveryPage::Evidence, Control::Next, false, _) => Control::Cancel,
            (RecoveryPage::Evidence, Control::Cancel, true, _) => Control::Next,
            (RecoveryPage::Evidence, Control::Next, true, _) => Control::Cancel,
            (RecoveryPage::Evidence, _, _, _) => Control::Cancel,
            (RecoveryPage::Transition, Control::Back, false, _) => Control::Cancel,
            (RecoveryPage::Transition, Control::Cancel, false, _) => Control::Confirm,
            (RecoveryPage::Transition, Control::Confirm, false, true) => Control::Approve,
            (RecoveryPage::Transition, Control::Confirm, false, false) => Control::Back,
            (RecoveryPage::Transition, Control::Approve, false, _) => Control::Back,
            (RecoveryPage::Transition, Control::Back, true, true) => Control::Approve,
            (RecoveryPage::Transition, Control::Back, true, false) => Control::Confirm,
            (RecoveryPage::Transition, Control::Cancel, true, _) => Control::Back,
            (RecoveryPage::Transition, Control::Confirm, true, _) => Control::Cancel,
            (RecoveryPage::Transition, Control::Approve, true, _) => Control::Confirm,
            (RecoveryPage::Transition, Control::Next, _, _) => Control::Back,
        };
    }

    fn activate_for_subject(
        &mut self,
        control: Control,
        review_surface_ready: bool,
        subject: &ApprovalSubject,
    ) -> Option<ApprovalDecision> {
        if !matches!(subject, ApprovalSubject::RecoveryParticipation(_)) {
            return self.activate(control, review_surface_ready);
        }
        if !review_surface_ready {
            self.reset_for_incomplete_surface();
            return (control == Control::Cancel).then_some(ApprovalDecision::Decline);
        }
        match (self.recovery_page, control) {
            (_, Control::Cancel) => Some(ApprovalDecision::Decline),
            (RecoveryPage::Evidence, Control::Next) => {
                self.recovery_page = RecoveryPage::Transition;
                self.confirmed = false;
                self.focus = Control::Back;
                self.pressed = None;
                None
            }
            (RecoveryPage::Transition, Control::Back) => {
                self.recovery_page = RecoveryPage::Evidence;
                self.confirmed = false;
                self.focus = Control::Cancel;
                self.pressed = None;
                None
            }
            (RecoveryPage::Transition, Control::Confirm) => {
                self.confirmed = !self.confirmed;
                if !self.confirmed && self.focus == Control::Approve {
                    self.focus = Control::Confirm;
                }
                None
            }
            (RecoveryPage::Transition, Control::Approve) if self.confirmed => {
                Some(ApprovalDecision::Approve)
            }
            _ => None,
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

#[derive(Clone, Copy, Debug, PartialEq)]
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

#[derive(Clone, Copy, Debug)]
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

fn control_at(
    width: f64,
    height: f64,
    review_surface_ready: bool,
    x: f64,
    y: f64,
) -> Option<Control> {
    if review_surface_ready {
        controls(width, height).at(x, y)
    } else if blocked_cancel_rect(width as f32, height as f32).contains(x, y) {
        Some(Control::Cancel)
    } else {
        None
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct LogicalDimensions {
    width: f64,
    height: f64,
}

impl LogicalDimensions {
    fn fits_detailed_review(self, required_height: f64) -> bool {
        self.width >= WINDOW_WIDTH && self.height >= required_height
    }
}

fn logical_dimensions(width: u32, height: u32, scale_factor: f64) -> Option<LogicalDimensions> {
    if width == 0 || height == 0 || !scale_factor.is_finite() || scale_factor <= 0.0 {
        return None;
    }
    Some(LogicalDimensions {
        width: f64::from(width) / scale_factor,
        height: f64::from(height) / scale_factor,
    })
}

fn detailed_review_fits(
    window: Option<LogicalDimensions>,
    output: Option<LogicalDimensions>,
    required_height: f64,
) -> bool {
    window.is_some_and(|dimensions| dimensions.fits_detailed_review(required_height))
        && output.is_some_and(|dimensions| dimensions.fits_detailed_review(required_height))
}

#[cfg(test)]
fn transition_review_fits(
    window: Option<LogicalDimensions>,
    output: Option<LogicalDimensions>,
) -> bool {
    detailed_review_fits(window, output, TRANSITION_WINDOW_HEIGHT)
}

fn blocked_cancel_rect(width: f32, height: f32) -> UiRect {
    let button_width = 142.0_f32.min((width - 32.0).max(0.0));
    UiRect {
        x: ((width - button_width) / 2.0).max(0.0),
        y: 400.0_f32.min((height - 64.0).max(0.0)),
        width: button_width,
        height: 46.0_f32.min(height.max(0.0)),
    }
}

#[derive(Clone, Copy, Debug)]
struct LabeledFieldLayout {
    label: UiRect,
    value: UiRect,
}

fn labeled_field_layout(x: f32, y: f32, width: f32, value_height: f32) -> LabeledFieldLayout {
    LabeledFieldLayout {
        label: UiRect {
            x,
            y,
            width,
            height: 18.0,
        },
        value: UiRect {
            x,
            y: y + 18.0,
            width,
            height: value_height,
        },
    }
}

#[derive(Clone, Copy, Debug)]
struct PersonaTransitionLayout {
    panel: UiRect,
    persona: LabeledFieldLayout,
    anchor: LabeledFieldLayout,
    facts: UiRect,
    root_digest: LabeledFieldLayout,
    previous_digest: LabeledFieldLayout,
    previous_key: LabeledFieldLayout,
    next_key: LabeledFieldLayout,
    transition_digest: LabeledFieldLayout,
    caller: UiRect,
    warning_bar: UiRect,
    warning: UiRect,
    controls: Controls,
    footer: UiRect,
}

fn persona_transition_layout(width: f32, height: f32) -> PersonaTransitionLayout {
    let field_x = 62.0;
    let field_width = width - 124.0;
    PersonaTransitionLayout {
        panel: UiRect {
            x: 40.0,
            y: 150.0,
            width: width - 80.0,
            height: 460.0,
        },
        persona: labeled_field_layout(field_x, 164.0, field_width, 24.0),
        anchor: labeled_field_layout(field_x, 210.0, field_width, 24.0),
        facts: UiRect {
            x: field_x,
            y: 256.0,
            width: field_width,
            height: 24.0,
        },
        root_digest: labeled_field_layout(field_x, 284.0, field_width, 46.0),
        previous_digest: labeled_field_layout(field_x, 352.0, field_width, 46.0),
        previous_key: labeled_field_layout(field_x, 420.0, field_width, 24.0),
        next_key: labeled_field_layout(field_x, 466.0, field_width, 24.0),
        transition_digest: labeled_field_layout(field_x, 512.0, field_width, 46.0),
        caller: UiRect {
            x: field_x,
            y: 626.0,
            width: field_width,
            height: 26.0,
        },
        warning_bar: UiRect {
            x: field_x,
            y: 659.0,
            width: 4.0,
            height: 20.0,
        },
        warning: UiRect {
            x: 76.0,
            y: 658.0,
            width: width - 142.0,
            height: 44.0,
        },
        controls: controls(f64::from(width), f64::from(height)),
        footer: UiRect {
            x: 40.0,
            y: height - 27.0,
            width: width - 80.0,
            height: 18.0,
        },
    }
}

#[derive(Clone, Copy, Debug)]
struct RecoveryLayout {
    panel: UiRect,
    caller: UiRect,
    warning_bar: UiRect,
    warning: UiRect,
    confirm: UiRect,
    back: UiRect,
    cancel: UiRect,
    advance: UiRect,
    footer: UiRect,
}

fn recovery_layout(width: f32, height: f32) -> RecoveryLayout {
    RecoveryLayout {
        panel: UiRect {
            x: 40.0,
            y: 150.0,
            width: width - 80.0,
            height: 460.0,
        },
        caller: UiRect {
            x: 62.0,
            y: 626.0,
            width: width - 124.0,
            height: 26.0,
        },
        warning_bar: UiRect {
            x: 62.0,
            y: 659.0,
            width: 4.0,
            height: 36.0,
        },
        warning: UiRect {
            x: 76.0,
            y: 658.0,
            width: width - 142.0,
            height: 54.0,
        },
        confirm: UiRect {
            x: 40.0,
            y: height - 154.0,
            width: width - 80.0,
            height: 54.0,
        },
        back: UiRect {
            x: 40.0,
            y: height - 82.0,
            width: 132.0,
            height: 46.0,
        },
        cancel: UiRect {
            x: width - 326.0,
            y: height - 82.0,
            width: 132.0,
            height: 46.0,
        },
        advance: UiRect {
            x: width - 182.0,
            y: height - 82.0,
            width: 142.0,
            height: 46.0,
        },
        footer: UiRect {
            x: 40.0,
            y: height - 27.0,
            width: width - 80.0,
            height: 18.0,
        },
    }
}

fn control_at_for_subject(
    width: f64,
    height: f64,
    review_surface_ready: bool,
    x: f64,
    y: f64,
    subject: &ApprovalSubject,
    interaction: &Interaction,
) -> Option<Control> {
    if !matches!(subject, ApprovalSubject::RecoveryParticipation(_)) {
        return control_at(width, height, review_surface_ready, x, y);
    }
    if !review_surface_ready {
        return blocked_cancel_rect(width as f32, height as f32)
            .contains(x, y)
            .then_some(Control::Cancel);
    }
    let layout = recovery_layout(width as f32, height as f32);
    if layout.cancel.contains(x, y) {
        return Some(Control::Cancel);
    }
    match interaction.recovery_page {
        RecoveryPage::Evidence => layout.advance.contains(x, y).then_some(Control::Next),
        RecoveryPage::Transition => {
            if layout.back.contains(x, y) {
                Some(Control::Back)
            } else if layout.confirm.contains(x, y) {
                Some(Control::Confirm)
            } else if layout.advance.contains(x, y) {
                Some(Control::Approve)
            } else {
                None
            }
        }
    }
}

fn window_height(subject: &ApprovalSubject) -> f64 {
    match subject {
        ApprovalSubject::PersonaTransition(_) => TRANSITION_WINDOW_HEIGHT,
        ApprovalSubject::RecoveryParticipation(_) => RECOVERY_WINDOW_HEIGHT,
        ApprovalSubject::Artifact(_)
        | ApprovalSubject::Domain(_)
        | ApprovalSubject::PersonaRoot(_) => WINDOW_HEIGHT,
    }
}

#[derive(Clone, Copy)]
struct SubjectCopy {
    heading: &'static str,
    explanation: &'static str,
    warning: &'static str,
    confirmation: &'static str,
    approval_label: &'static str,
}

fn subject_copy(subject: &ApprovalSubject) -> SubjectCopy {
    match subject {
        ApprovalSubject::Artifact(_) => SubjectCopy {
            heading: "Sign these exact bytes?",
            explanation: "Check the persona, immutable SHA-256 digest, and key. The name below came from the requesting app.",
            warning: "A valid signature proves these bytes and this key—not safety, truth, or legal identity.",
            confirmation: "I intend to sign exactly this SHA-256 digest with this persona.",
            approval_label: "Sign bytes",
        },
        ApprovalSubject::Domain(_) => SubjectCopy {
            heading: "Sign this domain-control statement?",
            explanation: "Check the exact DNS name, validity, TXT commitment, persona, and signing key.",
            warning: "This may prove current DNS publishing control—not legal ownership, identity, or safety.",
            confirmation: "I intend to sign this exact domain claim and TXT commitment.",
            approval_label: "Sign claim",
        },
        ApprovalSubject::PersonaRoot(_) => SubjectCopy {
            heading: "Create this persona root?",
            explanation: "Check the persona, unique anchor, root digest, creation time, and initial signing key.",
            warning: "This durable root can link future activity—it does not prove legal identity, safety, or recovery rights.",
            confirmation: "I intend to create this exact long-lived persona root.",
            approval_label: "Create root",
        },
        ApprovalSubject::PersonaTransition(_) => SubjectCopy {
            heading: "Rotate this persona key?",
            explanation: "Check the pinned root, exact chain head, sequence, previous key, next key, and transition digest.",
            warning: "Rotation proves key continuity—not current trust, legal identity, or that either key is safe.",
            confirmation: "I intend to rotate from the previous key to the next key using this exact transition digest.",
            approval_label: "Rotate key",
        },
        ApprovalSubject::RecoveryParticipation(_) => SubjectCopy {
            heading: "Join this recovery ceremony?",
            explanation: "Review both pages. Approval signs the transition statement and binds it to this exact portable request.",
            warning: "Neither signature proves legal identity, safety, or truth. Participant/device independence is not established.",
            confirmation: "I approve both signatures: this exact request evidence and its recovery transition statement.",
            approval_label: "Sign response",
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
    review_surface_ready: bool,
    text_engine: &mut TextEngine,
) {
    let mut text = TextPainter {
        pixmap,
        scale,
        engine: text_engine,
    };

    if matches!(
        prompt.subject,
        ApprovalSubject::PersonaTransition(_) | ApprovalSubject::RecoveryParticipation(_)
    ) && !review_surface_ready
    {
        draw_incomplete_detailed_surface(
            &mut text,
            width,
            height,
            interaction,
            remaining_seconds,
            &prompt.subject,
        );
        return;
    }

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
    let copy = subject_copy(&prompt.subject);
    text.draw(
        copy.heading,
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
        copy.explanation,
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

    let transition_layout = matches!(&prompt.subject, ApprovalSubject::PersonaTransition(_))
        .then(|| persona_transition_layout(width, height));
    let recovery_layout = matches!(&prompt.subject, ApprovalSubject::RecoveryParticipation(_))
        .then(|| recovery_layout(width, height));
    let panel = recovery_layout.map_or_else(
        || UiRect {
            ..transition_layout.map_or_else(
                || UiRect {
                    x: 40.0,
                    y: 150.0,
                    width: width - 80.0,
                    height: match &prompt.subject {
                        ApprovalSubject::Artifact(_) => 390.0,
                        ApprovalSubject::Domain(_)
                        | ApprovalSubject::PersonaRoot(_)
                        | ApprovalSubject::PersonaTransition(_)
                        | ApprovalSubject::RecoveryParticipation(_) => 400.0,
                    },
                },
                |layout| layout.panel,
            )
        },
        |layout| layout.panel,
    );
    outlined_panel(text.pixmap, scale, panel, PANEL, BORDER);

    match &prompt.subject {
        ApprovalSubject::Artifact(artifact) => {
            draw_artifact_subject(&mut text, width, prompt, artifact)
        }
        ApprovalSubject::Domain(domain) => draw_domain_subject(&mut text, width, prompt, domain),
        ApprovalSubject::PersonaRoot(root) => {
            draw_persona_root_subject(&mut text, width, prompt, root)
        }
        ApprovalSubject::PersonaTransition(transition) => draw_persona_transition_subject(
            &mut text,
            prompt,
            transition,
            &transition_layout.expect("transition layout is present"),
        ),
        ApprovalSubject::RecoveryParticipation(recovery) => draw_recovery_subject(
            &mut text,
            prompt,
            recovery,
            interaction.recovery_page,
            &recovery_layout.expect("recovery layout is present"),
        ),
    }
    let (key_y, caller_y, warning_y) = match &prompt.subject {
        ApprovalSubject::Artifact(_) => (Some(400.0), 470.0, 503.0),
        ApprovalSubject::Domain(_) => (Some(424.0), 492.0, 520.0),
        ApprovalSubject::PersonaRoot(_) => (Some(424.0), 492.0, 520.0),
        ApprovalSubject::PersonaTransition(_) => (None, 626.0, 658.0),
        ApprovalSubject::RecoveryParticipation(_) => (None, 626.0, 658.0),
    };
    if let Some(key_y) = key_y {
        draw_field(
            &mut text,
            "SIGNING KEY FINGERPRINT",
            &prompt.key_fingerprint,
            62.0,
            key_y,
            width - 124.0,
        );
    }

    let caller_rect = recovery_layout.map_or_else(
        || {
            transition_layout.map_or(
                UiRect {
                    x: 62.0,
                    y: caller_y,
                    width: width - 124.0,
                    height: 26.0,
                },
                |layout| layout.caller,
            )
        },
        |layout| layout.caller,
    );
    let caller = format!(
        "Request {}    •    caller PID {} / UID {}",
        prompt.request_id, prompt.peer.pid, prompt.peer.uid
    );
    text.draw(&caller, caller_rect, 11.0, Weight::NORMAL, MUTED, None);

    let warning_bar = recovery_layout.map_or_else(
        || {
            transition_layout.map_or(
                UiRect {
                    x: 62.0,
                    y: warning_y + 1.0,
                    width: 4.0,
                    height: 20.0,
                },
                |layout| layout.warning_bar,
            )
        },
        |layout| layout.warning_bar,
    );
    let warning_rect = recovery_layout.map_or_else(
        || {
            transition_layout.map_or(
                UiRect {
                    x: 76.0,
                    y: warning_y,
                    width: width - 142.0,
                    height: 24.0,
                },
                |layout| layout.warning,
            )
        },
        |layout| layout.warning,
    );
    fill_rect(text.pixmap, scale, warning_bar, WARNING);
    text.draw(
        copy.warning,
        warning_rect,
        12.5,
        Weight::BOLD,
        WARNING,
        None,
    );

    if let Some(layout) = recovery_layout {
        draw_recovery_controls(&mut text, layout, interaction, copy);
    } else {
        let controls = transition_layout.map_or_else(
            || controls(f64::from(width), f64::from(height)),
            |layout| layout.controls,
        );
        draw_checkbox(
            &mut text,
            controls.confirm,
            interaction,
            copy.confirmation,
            transition_layout.is_some(),
        );
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
            copy.approval_label,
            interaction.focus == Control::Approve,
            interaction.confirmed,
            true,
        );
    }

    let footer = match &prompt.subject {
        ApprovalSubject::RecoveryParticipation(_) => format!(
            "Page {} of 2  •  Esc cancels  •  focus loss restarts review  •  consent expires in {remaining_seconds}s",
            match interaction.recovery_page {
                RecoveryPage::Evidence => 1,
                RecoveryPage::Transition => 2,
            }
        ),
        _ => format!(
            "Esc cancels  •  focus loss resets confirmation  •  expires in {remaining_seconds}s"
        ),
    };
    let footer_rect = recovery_layout.map_or_else(
        || {
            transition_layout.map_or(
                UiRect {
                    x: 40.0,
                    y: height - 27.0,
                    width: width - 80.0,
                    height: 18.0,
                },
                |layout| layout.footer,
            )
        },
        |layout| layout.footer,
    );
    text.draw(
        &footer,
        footer_rect,
        10.5,
        Weight::NORMAL,
        MUTED,
        Some(Align::Center),
    );
}

fn draw_incomplete_detailed_surface(
    text: &mut TextPainter<'_>,
    width: f32,
    height: f32,
    interaction: &Interaction,
    remaining_seconds: u64,
    subject: &ApprovalSubject,
) {
    fill_rect(
        text.pixmap,
        text.scale,
        UiRect {
            x: 0.0,
            y: 0.0,
            width,
            height: 6.0,
        },
        WARNING,
    );
    text.draw(
        "A QUO  ·  APPROVAL DISABLED",
        UiRect {
            x: 40.0,
            y: 25.0,
            width: width - 80.0,
            height: 22.0,
        },
        12.0,
        Weight::BOLD,
        WARNING,
        None,
    );
    text.draw(
        match subject {
            ApprovalSubject::RecoveryParticipation(_) => {
                "The complete recovery review does not fit"
            }
            _ => "The complete key-rotation review does not fit",
        },
        UiRect {
            x: 40.0,
            y: 58.0,
            width: width - 80.0,
            height: 78.0,
        },
        25.0,
        Weight::BOLD,
        TEXT,
        None,
    );
    let panel = UiRect {
        x: 40.0,
        y: 150.0,
        width: width - 80.0,
        height: 174.0,
    };
    outlined_panel(text.pixmap, text.scale, panel, PANEL, BORDER);
    text.draw(
        "A Quo cannot safely show every required persona, key, chain, policy, and digest field on this output at its current scale.",
        UiRect {
            x: 62.0,
            y: 174.0,
            width: width - 124.0,
            height: 58.0,
        },
        14.0,
        Weight::NORMAL,
        TEXT,
        None,
    );
    text.draw(
        "No confirmation or approval control is available. Move the request to an output with at least 780 × 900 logical pixels, or press Esc to cancel.",
        UiRect {
            x: 62.0,
            y: 244.0,
            width: width - 124.0,
            height: 58.0,
        },
        12.5,
        Weight::BOLD,
        WARNING,
        None,
    );

    draw_button(
        text,
        blocked_cancel_rect(width, height),
        "Decline",
        interaction.focus == Control::Cancel,
        true,
        false,
    );
    let footer = format!("Esc cancels  •  approval disabled  •  expires in {remaining_seconds}s");
    text.draw(
        &footer,
        UiRect {
            x: 40.0,
            y: (height - 27.0).clamp(0.0, 468.0),
            width: width - 80.0,
            height: 18.0,
        },
        10.5,
        Weight::NORMAL,
        MUTED,
        Some(Align::Center),
    );
}

fn draw_artifact_subject(
    text: &mut TextPainter<'_>,
    width: f32,
    prompt: &ApprovalPrompt,
    artifact: &ArtifactApproval,
) {
    draw_field(
        text,
        "PERSONA",
        &truncate_middle(&prompt.persona_label, 72),
        62.0,
        172.0,
        width - 124.0,
    );
    draw_field(
        text,
        "CALLER-SUPPLIED ARTIFACT LABEL",
        &truncate_middle(&artifact.artifact_label, 96),
        62.0,
        226.0,
        width - 124.0,
    );
    let facts = format!(
        "Purpose: {}    •    Type: {}    •    Size: {}",
        prompt
            .persona_purpose
            .map(|purpose| purpose.label())
            .unwrap_or("unavailable"),
        artifact.artifact_kind.label(),
        format_size(artifact.artifact_size)
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
    let digest = artifact.sha256_hex();
    let digest = format!("{}\n{}", &digest[..32], &digest[32..]);
    draw_field(
        text,
        "IMMUTABLE SHA-256",
        &digest,
        62.0,
        324.0,
        width - 124.0,
    );
}

fn draw_domain_subject(
    text: &mut TextPainter<'_>,
    width: f32,
    prompt: &ApprovalPrompt,
    domain: &DomainApproval,
) {
    draw_field(
        text,
        "PERSONA",
        &truncate_middle(&prompt.persona_label, 72),
        62.0,
        172.0,
        width - 124.0,
    );
    text.draw(
        "EXACT DNS NAME",
        UiRect {
            x: 62.0,
            y: 226.0,
            width: width - 124.0,
            height: 18.0,
        },
        10.5,
        Weight::BOLD,
        ACCENT,
        None,
    );
    text.draw(
        &wrap_ascii(&domain.domain, 50),
        UiRect {
            x: 62.0,
            y: 244.0,
            width: width - 124.0,
            height: 82.0,
        },
        10.5,
        Weight::NORMAL,
        TEXT,
        None,
    );
    let duration = domain.expires_at.saturating_sub(domain.issued_at);
    let facts = format!(
        "Purpose: {}    •    Valid {}    •    Unix time {} → {}",
        prompt
            .persona_purpose
            .map(|purpose| purpose.label())
            .unwrap_or("unavailable"),
        format_duration(duration),
        domain.issued_at,
        domain.expires_at
    );
    text.draw(
        &facts,
        UiRect {
            x: 62.0,
            y: 330.0,
            width: width - 124.0,
            height: 28.0,
        },
        12.0,
        Weight::NORMAL,
        MUTED,
        None,
    );
    draw_field(
        text,
        "DNS TXT VALUE TO PUBLISH",
        &wrap_ascii(&domain.dns_txt_value, 40),
        62.0,
        358.0,
        width - 124.0,
    );
}

fn draw_persona_root_subject(
    text: &mut TextPainter<'_>,
    width: f32,
    prompt: &ApprovalPrompt,
    root: &PersonaRootApproval,
) {
    draw_field(
        text,
        "PERSONA",
        &truncate_middle(&prompt.persona_label, 72),
        62.0,
        172.0,
        width - 124.0,
    );
    draw_field(
        text,
        "UNIQUE PERSONA ANCHOR",
        &root.persona_anchor,
        62.0,
        226.0,
        width - 124.0,
    );
    let facts = format!(
        "Purpose: {}    •    Created at Unix time {}",
        prompt
            .persona_purpose
            .map(|purpose| purpose.label())
            .unwrap_or("unavailable"),
        root.issued_at
    );
    text.draw(
        &facts,
        UiRect {
            x: 62.0,
            y: 294.0,
            width: width - 124.0,
            height: 28.0,
        },
        12.0,
        Weight::NORMAL,
        MUTED,
        None,
    );
    let digest = root.root_sha256_hex();
    let digest = format!("{}\n{}", &digest[..32], &digest[32..]);
    draw_field(
        text,
        "ROOT STATEMENT SHA-256 — PIN THIS SEPARATELY",
        &digest,
        62.0,
        326.0,
        width - 124.0,
    );
}

fn draw_persona_transition_subject(
    text: &mut TextPainter<'_>,
    prompt: &ApprovalPrompt,
    transition: &PersonaTransitionApproval,
    layout: &PersonaTransitionLayout,
) {
    draw_labeled_field(
        text,
        "PERSONA",
        &truncate_middle(&prompt.persona_label, 72),
        layout.persona,
    );
    draw_labeled_field(
        text,
        "UNIQUE PERSONA ANCHOR",
        &transition.persona_anchor,
        layout.anchor,
    );
    let facts = format!(
        "Purpose: {}    •    Sequence {}    •    Issued at Unix time {}",
        prompt
            .persona_purpose
            .map(|purpose| purpose.label())
            .unwrap_or("unavailable"),
        transition.sequence,
        transition.issued_at
    );
    text.draw(&facts, layout.facts, 12.0, Weight::NORMAL, MUTED, None);

    let root_digest = split_sha256_hex(&transition.root_sha256_hex());
    draw_labeled_field(
        text,
        "PINNED ROOT STATEMENT SHA-256",
        &root_digest,
        layout.root_digest,
    );
    let previous_digest = previous_transition_display(transition);
    draw_labeled_field(
        text,
        "CHAIN HEAD BEFORE ROTATION",
        &previous_digest,
        layout.previous_digest,
    );
    draw_labeled_field(
        text,
        "PREVIOUS KEY FINGERPRINT",
        &transition.previous_key_fingerprint,
        layout.previous_key,
    );
    draw_labeled_field(
        text,
        "NEXT KEY FINGERPRINT",
        &transition.next_key_fingerprint,
        layout.next_key,
    );
    let transition_digest = split_sha256_hex(&transition.transition_sha256_hex());
    draw_labeled_field(
        text,
        "EXACT TRANSITION STATEMENT SHA-256",
        &transition_digest,
        layout.transition_digest,
    );
}

fn draw_recovery_subject(
    text: &mut TextPainter<'_>,
    prompt: &ApprovalPrompt,
    recovery: &RecoveryParticipationApproval,
    page: RecoveryPage,
    layout: &RecoveryLayout,
) {
    match page {
        RecoveryPage::Evidence => draw_recovery_evidence_page(text, prompt, recovery, layout),
        RecoveryPage::Transition => draw_recovery_transition_page(text, recovery, layout),
    }
}

fn draw_recovery_evidence_page(
    text: &mut TextPainter<'_>,
    prompt: &ApprovalPrompt,
    recovery: &RecoveryParticipationApproval,
    layout: &RecoveryLayout,
) {
    let x = layout.panel.x + 22.0;
    let width = layout.panel.width - 44.0;
    draw_labeled_text(
        text,
        "PERSONA FROM VERIFIED ROOT — EXACT",
        &wrap_exact_characters(&prompt.persona_label, 40),
        labeled_field_layout(x, 160.0, width, 105.0),
        10.5,
    );
    draw_labeled_field(
        text,
        "UNIQUE PERSONA ANCHOR",
        &recovery.persona_anchor,
        labeled_field_layout(x, 288.0, width, 20.0),
    );
    draw_labeled_field(
        text,
        "SIGNED CEREMONY ID",
        &recovery.ceremony_id,
        labeled_field_layout(x, 330.0, width, 20.0),
    );
    let facts = format!(
        "Expires at Unix time {}    •    Role: {}",
        recovery.ceremony_expires_at,
        recovery.participant_role.label()
    );
    text.draw(
        &facts,
        UiRect {
            x,
            y: 374.0,
            width,
            height: 24.0,
        },
        11.5,
        Weight::NORMAL,
        MUTED,
        None,
    );
    draw_labeled_field(
        text,
        "PARTICIPANT KEY FINGERPRINT",
        &recovery.participant_key_fingerprint,
        labeled_field_layout(x, 396.0, width, 20.0),
    );
    draw_labeled_field(
        text,
        "PINNED ROOT STATEMENT SHA-256",
        &recovery.root_sha256_hex(),
        labeled_field_layout(x, 438.0, width, 22.0),
    );
    let policy_facts = recovery_policy_facts(recovery);
    text.draw(
        &policy_facts,
        UiRect {
            x,
            y: 480.0,
            width,
            height: 20.0,
        },
        10.5,
        Weight::BOLD,
        ACCENT,
        None,
    );
    text.draw(
        &recovery.policy_sha256_hex(),
        UiRect {
            x,
            y: 497.0,
            width,
            height: 22.0,
        },
        15.0,
        Weight::NORMAL,
        TEXT,
        None,
    );
    draw_labeled_field(
        text,
        "PINNED CONTINUITY HEAD BEFORE RECOVERY",
        &recovery_head_display(recovery),
        labeled_field_layout(x, 523.0, width, 46.0),
    );
}

fn recovery_policy_facts(recovery: &RecoveryParticipationApproval) -> String {
    format!(
        "RECOVERY POLICY v{}    •    threshold {} distinct authorized recovery-key signatures",
        recovery.recovery_policy_version, recovery.recovery_policy_threshold
    )
}

fn draw_recovery_transition_page(
    text: &mut TextPainter<'_>,
    recovery: &RecoveryParticipationApproval,
    layout: &RecoveryLayout,
) {
    let x = layout.panel.x + 22.0;
    let width = layout.panel.width - 44.0;
    let facts = format!(
        "Reason: {}    •    New sequence {}    •    Role: {}",
        recovery.reason.label(),
        recovery.previous_head_sequence.saturating_add(1),
        recovery.participant_role.label()
    );
    text.draw(
        &facts,
        UiRect {
            x,
            y: 168.0,
            width,
            height: 26.0,
        },
        12.0,
        Weight::BOLD,
        MUTED,
        None,
    );
    draw_field(
        text,
        "PREVIOUS PERSONA KEY FINGERPRINT",
        &recovery.previous_key_fingerprint,
        x,
        207.0,
        width,
    );
    draw_field(
        text,
        "NEXT PERSONA KEY FINGERPRINT",
        &recovery.next_key_fingerprint,
        x,
        261.0,
        width,
    );
    draw_field(
        text,
        "YOUR PARTICIPANT KEY / DERIVED ROLE",
        &format!(
            "{}    •    {}",
            recovery.participant_key_fingerprint,
            recovery.participant_role.label()
        ),
        x,
        315.0,
        width,
    );
    draw_labeled_field(
        text,
        "EXACT PORTABLE REQUEST SHA-256",
        &split_sha256_hex(&recovery.request_sha256_hex()),
        labeled_field_layout(x, 376.0, width, 46.0),
    );
    draw_field(
        text,
        "SIGNED CEREMONY ID",
        &recovery.ceremony_id,
        x,
        449.0,
        width,
    );
    let timing = recovery_signing_notice(recovery);
    text.draw(
        &timing,
        UiRect {
            x,
            y: 511.0,
            width,
            height: 52.0,
        },
        12.0,
        Weight::NORMAL,
        TEXT,
        None,
    );
}

fn recovery_signing_notice(recovery: &RecoveryParticipationApproval) -> String {
    format!(
        "Two same-key signatures are produced; a hardware key may ask twice. Both must finish before Unix time {}.",
        recovery.ceremony_expires_at
    )
}

fn recovery_head_display(recovery: &RecoveryParticipationApproval) -> String {
    match recovery.previous_head_sha256_hex() {
        Some(digest) => format!(
            "Sequence {}\n{}",
            recovery.previous_head_sequence,
            split_sha256_hex(&digest).replace('\n', "  ")
        ),
        None => "Sequence 0 — PERSONA ROOT (no previous transition)".to_owned(),
    }
}

fn draw_recovery_controls(
    text: &mut TextPainter<'_>,
    layout: RecoveryLayout,
    interaction: &Interaction,
    copy: SubjectCopy,
) {
    match interaction.recovery_page {
        RecoveryPage::Evidence => {
            draw_button(
                text,
                layout.cancel,
                "Decline",
                interaction.focus == Control::Cancel,
                true,
                false,
            );
            draw_button(
                text,
                layout.advance,
                "Next page",
                interaction.focus == Control::Next,
                true,
                true,
            );
        }
        RecoveryPage::Transition => {
            draw_checkbox(text, layout.confirm, interaction, copy.confirmation, true);
            draw_button(
                text,
                layout.back,
                "Back",
                interaction.focus == Control::Back,
                true,
                false,
            );
            draw_button(
                text,
                layout.cancel,
                "Decline",
                interaction.focus == Control::Cancel,
                true,
                false,
            );
            draw_button(
                text,
                layout.advance,
                copy.approval_label,
                interaction.focus == Control::Approve,
                interaction.confirmed,
                true,
            );
        }
    }
}

fn split_sha256_hex(digest: &str) -> String {
    debug_assert_eq!(digest.len(), 64);
    format!("{}\n{}", &digest[..32], &digest[32..])
}

fn previous_transition_display(transition: &PersonaTransitionApproval) -> String {
    transition
        .previous_sha256_hex()
        .map(|digest| split_sha256_hex(&digest))
        .unwrap_or_else(|| "PERSONA ROOT — NO PREVIOUS TRANSITION".to_owned())
}

fn draw_field(text: &mut TextPainter<'_>, label: &str, value: &str, x: f32, y: f32, width: f32) {
    draw_labeled_field(text, label, value, labeled_field_layout(x, y, width, 46.0));
}

fn draw_labeled_field(
    text: &mut TextPainter<'_>,
    label: &str,
    value: &str,
    layout: LabeledFieldLayout,
) {
    text.draw(label, layout.label, 10.5, Weight::BOLD, ACCENT, None);
    text.draw(value, layout.value, 15.0, Weight::NORMAL, TEXT, None);
}

fn draw_labeled_text(
    text: &mut TextPainter<'_>,
    label: &str,
    value: &str,
    layout: LabeledFieldLayout,
    font_size: f32,
) {
    text.draw(label, layout.label, 10.5, Weight::BOLD, ACCENT, None);
    text.draw(value, layout.value, font_size, Weight::NORMAL, TEXT, None);
}

fn draw_checkbox(
    text: &mut TextPainter<'_>,
    rect: UiRect,
    interaction: &Interaction,
    label: &str,
    allow_two_lines: bool,
) {
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
        label,
        checkbox_label_rect(rect, allow_two_lines),
        13.0,
        Weight::BOLD,
        TEXT,
        None,
    );
}

fn checkbox_label_rect(rect: UiRect, allow_two_lines: bool) -> UiRect {
    if allow_two_lines {
        UiRect {
            x: rect.x + 50.0,
            y: rect.y + 9.0,
            width: rect.width - 62.0,
            height: 36.0,
        }
    } else {
        UiRect {
            x: rect.x + 50.0,
            y: rect.y + 15.0,
            width: rect.width - 62.0,
            height: 28.0,
        }
    }
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

fn format_duration(seconds: i64) -> String {
    const DAY: i64 = 24 * 60 * 60;
    const HOUR: i64 = 60 * 60;
    if seconds > 0 && seconds % DAY == 0 {
        let days = seconds / DAY;
        format!("{days} day{}", if days == 1 { "" } else { "s" })
    } else if seconds > 0 && seconds % HOUR == 0 {
        let hours = seconds / HOUR;
        format!("{hours} hour{}", if hours == 1 { "" } else { "s" })
    } else {
        format!("{seconds} seconds")
    }
}

fn wrap_ascii(value: &str, columns: usize) -> String {
    debug_assert!(columns > 0);
    let mut output = String::with_capacity(value.len() + value.len() / columns);
    for (index, character) in value.chars().enumerate() {
        if index > 0 && index % columns == 0 {
            output.push('\n');
        }
        output.push(character);
    }
    output
}

fn wrap_exact_characters(value: &str, columns: usize) -> String {
    debug_assert!(columns > 0);
    let mut output = String::with_capacity(value.len() + value.len() / columns);
    for (index, character) in value.chars().enumerate() {
        if index > 0 && index % columns == 0 {
            output.push('\n');
        }
        output.push(character);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_requires_the_exact_digest_confirmation() {
        let mut interaction = Interaction::default();
        assert_eq!(interaction.focus, Control::Cancel);
        assert_eq!(interaction.activate(Control::Approve, true), None);
        assert!(!interaction.confirmed);

        assert_eq!(interaction.activate(Control::Confirm, true), None);
        assert!(interaction.confirmed);
        assert_eq!(
            interaction.activate(Control::Approve, true),
            Some(ApprovalDecision::Approve)
        );
    }

    #[test]
    fn keyboard_focus_skips_disabled_approval() {
        let mut interaction = Interaction::default();
        interaction.focus_next(false, true);
        assert_eq!(interaction.focus, Control::Confirm);
        interaction.focus_next(false, true);
        assert_eq!(interaction.focus, Control::Cancel);

        interaction.activate(Control::Confirm, true);
        interaction.focus = Control::Confirm;
        interaction.focus_next(false, true);
        assert_eq!(interaction.focus, Control::Approve);
    }

    #[test]
    fn focus_loss_disarms_approval_and_clears_a_click() {
        let mut interaction = Interaction {
            confirmed: true,
            focus: Control::Approve,
            pressed: Some(Control::Approve),
            recovery_page: RecoveryPage::Evidence,
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
        assert_eq!(format_duration(7 * 24 * 60 * 60), "7 days");
        assert_eq!(wrap_ascii("abcdefgh", 4), "abcd\nefgh");
        let longest_domain = "a".repeat(253);
        let wrapped = wrap_ascii(&longest_domain, 50);
        assert_eq!(wrapped.replace('\n', ""), longest_domain);
        assert!(wrapped.lines().all(|line| line.len() <= 50));
        assert_eq!(wrapped.lines().count(), 6);
    }

    #[test]
    fn persona_transition_copy_and_digest_display_are_explicit() {
        let transition = PersonaTransitionApproval {
            persona_anchor: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            root_statement_sha256: [0x11; 32],
            sequence: 2,
            previous_transition_sha256: Some([0x22; 32]),
            issued_at: 1_700_000_000,
            previous_key_fingerprint: "previous-key".to_owned(),
            next_key_fingerprint: "next-key".to_owned(),
            transition_statement_sha256: [0x33; 32],
        };
        let subject = ApprovalSubject::PersonaTransition(transition.clone());
        let copy = subject_copy(&subject);

        assert_eq!(window_height(&subject), TRANSITION_WINDOW_HEIGHT);
        assert_eq!(copy.heading, "Rotate this persona key?");
        assert_eq!(copy.approval_label, "Rotate key");
        assert!(copy.explanation.contains("exact chain head"));
        assert!(copy.confirmation.contains("exact transition digest"));
        assert_eq!(
            split_sha256_hex(&transition.root_sha256_hex()),
            format!("{}\n{}", "11".repeat(16), "11".repeat(16))
        );
        assert_eq!(
            previous_transition_display(&transition),
            format!("{}\n{}", "22".repeat(16), "22".repeat(16))
        );

        let first = PersonaTransitionApproval {
            sequence: 1,
            previous_transition_sha256: None,
            ..transition
        };
        assert_eq!(
            previous_transition_display(&first),
            "PERSONA ROOT — NO PREVIOUS TRANSITION"
        );
    }

    #[test]
    fn transition_approval_fails_closed_without_the_complete_surface() {
        let full = Some(LogicalDimensions {
            width: WINDOW_WIDTH,
            height: TRANSITION_WINDOW_HEIGHT,
        });
        assert!(transition_review_fits(full, full));
        assert!(!transition_review_fits(
            Some(LogicalDimensions {
                width: WINDOW_WIDTH,
                height: TRANSITION_WINDOW_HEIGHT - 1.0,
            }),
            full,
        ));
        assert!(!transition_review_fits(full, None));

        let hidpi_output = logical_dimensions(1920, 1080, 2.0);
        assert_eq!(
            hidpi_output,
            Some(LogicalDimensions {
                width: 960.0,
                height: 540.0,
            })
        );
        assert!(!transition_review_fits(full, hidpi_output));

        let mut interaction = Interaction {
            confirmed: true,
            focus: Control::Approve,
            pressed: Some(Control::Approve),
            recovery_page: RecoveryPage::Evidence,
        };
        assert_eq!(interaction.activate(Control::Approve, false), None);
        assert!(!interaction.confirmed);
        assert_eq!(interaction.focus, Control::Cancel);
        assert_eq!(interaction.pressed, None);
        assert_eq!(interaction.activate(Control::Confirm, false), None);
        assert!(!interaction.confirmed);
        interaction.focus_next(false, false);
        assert_eq!(interaction.focus, Control::Cancel);

        let regular = controls(WINDOW_WIDTH, TRANSITION_WINDOW_HEIGHT);
        let approve_x = f64::from(regular.approve.x + regular.approve.width / 2.0);
        let approve_y = f64::from(regular.approve.y + regular.approve.height / 2.0);
        assert_eq!(
            control_at(
                WINDOW_WIDTH,
                TRANSITION_WINDOW_HEIGHT,
                false,
                approve_x,
                approve_y,
            ),
            None
        );
        let blocked_cancel = blocked_cancel_rect(WINDOW_WIDTH as f32, 768.0);
        assert_eq!(
            control_at(
                WINDOW_WIDTH,
                768.0,
                false,
                f64::from(blocked_cancel.x + blocked_cancel.width / 2.0),
                f64::from(blocked_cancel.y + blocked_cancel.height / 2.0),
            ),
            Some(Control::Cancel)
        );
    }

    #[test]
    fn complete_transition_layout_is_contained_and_non_overlapping() {
        fn right(rect: UiRect) -> f32 {
            rect.x + rect.width
        }
        fn bottom(rect: UiRect) -> f32 {
            rect.y + rect.height
        }
        fn overlaps(left: UiRect, right_rect: UiRect) -> bool {
            left.x < right(right_rect)
                && right_rect.x < right(left)
                && left.y < bottom(right_rect)
                && right_rect.y < bottom(left)
        }
        fn field_rect(field: LabeledFieldLayout) -> UiRect {
            UiRect {
                x: field.label.x,
                y: field.label.y,
                width: field.label.width,
                height: bottom(field.value) - field.label.y,
            }
        }

        let width = WINDOW_WIDTH as f32;
        let height = TRANSITION_WINDOW_HEIGHT as f32;
        let layout = persona_transition_layout(width, height);
        let evidence = [
            field_rect(layout.persona),
            field_rect(layout.anchor),
            layout.facts,
            field_rect(layout.root_digest),
            field_rect(layout.previous_digest),
            field_rect(layout.previous_key),
            field_rect(layout.next_key),
            field_rect(layout.transition_digest),
        ];

        for (index, rect) in evidence.iter().copied().enumerate() {
            assert!(rect.x >= layout.panel.x);
            assert!(rect.y >= layout.panel.y);
            assert!(right(rect) <= right(layout.panel));
            assert!(bottom(rect) <= bottom(layout.panel));
            for other in evidence.iter().copied().skip(index + 1) {
                assert!(!overlaps(rect, other), "evidence rows overlap");
            }
        }

        for field in [
            layout.persona,
            layout.anchor,
            layout.root_digest,
            layout.previous_digest,
            layout.previous_key,
            layout.next_key,
            layout.transition_digest,
        ] {
            assert_eq!(bottom(field.label), field.value.y);
            assert!(!overlaps(field.label, field.value));
        }

        assert!(bottom(layout.panel) <= layout.caller.y);
        assert!(bottom(layout.caller) <= layout.warning.y);
        assert!(bottom(layout.warning) <= layout.controls.confirm.y);
        assert!(layout.warning.height >= 2.0 * 12.5 * 1.35);
        let confirmation_label = checkbox_label_rect(layout.controls.confirm, true);
        assert!(confirmation_label.height >= 2.0 * 13.0 * 1.35);
        assert!(!overlaps(layout.warning, confirmation_label));
        assert!(bottom(layout.controls.confirm) <= layout.controls.cancel.y);
        assert_eq!(layout.controls.cancel.y, layout.controls.approve.y);
        assert!(!overlaps(layout.controls.cancel, layout.controls.approve));
        assert!(bottom(layout.controls.cancel) <= layout.footer.y);
        assert!(bottom(layout.controls.approve) <= layout.footer.y);
        assert!(right(layout.panel) <= width);
        assert!(right(layout.controls.approve) <= width);
        assert!(bottom(layout.footer) <= height);
    }

    #[test]
    fn recovery_review_requires_both_pages_confirmation_and_a_complete_viewport() {
        let subject = recovery_subject();
        let copy = subject_copy(&subject);
        assert_eq!(window_height(&subject), RECOVERY_WINDOW_HEIGHT);
        assert_eq!(copy.heading, "Join this recovery ceremony?");
        assert!(copy.explanation.contains("both pages"));
        assert!(copy.explanation.contains("transition statement"));
        assert!(copy.explanation.contains("exact portable request"));
        assert!(copy.confirmation.contains("both signatures"));
        assert!(copy.warning.contains("proves legal identity"));
        assert!(copy.warning.contains("safety"));
        assert!(copy.warning.contains("independence is not established"));
        let ApprovalSubject::RecoveryParticipation(recovery) = &subject else {
            unreachable!();
        };
        let policy = recovery_policy_facts(recovery);
        assert!(policy.contains("distinct authorized recovery-key signatures"));
        assert!(!policy.contains("independent"));
        let exact_label = "Persona ".repeat(32);
        assert_eq!(exact_label.len(), a_quo_approval::MAX_PERSONA_LABEL_BYTES);
        let wrapped = wrap_exact_characters(&exact_label, 40);
        assert_eq!(wrapped.replace('\n', ""), exact_label);
        assert!(!wrapped.contains('…'));
        assert!(wrapped.lines().all(|line| line.chars().count() <= 40));
        assert!(wrapped.lines().count() <= 7);
        let signing_notice = recovery_signing_notice(recovery);
        assert!(signing_notice.contains("Two same-key signatures"));
        assert!(signing_notice.contains("hardware key may ask twice"));

        let full = Some(LogicalDimensions {
            width: WINDOW_WIDTH,
            height: RECOVERY_WINDOW_HEIGHT,
        });
        assert!(detailed_review_fits(full, full, RECOVERY_WINDOW_HEIGHT));
        assert!(!detailed_review_fits(
            full,
            Some(LogicalDimensions {
                width: WINDOW_WIDTH,
                height: RECOVERY_WINDOW_HEIGHT - 1.0,
            }),
            RECOVERY_WINDOW_HEIGHT,
        ));

        let mut interaction = Interaction::default();
        assert_eq!(interaction.recovery_page, RecoveryPage::Evidence);
        assert_eq!(
            interaction.activate_for_subject(Control::Approve, true, &subject),
            None
        );
        interaction.focus_next_for_subject(false, true, &subject);
        assert_eq!(interaction.focus, Control::Next);
        assert_eq!(
            interaction.activate_for_subject(Control::Next, true, &subject),
            None
        );
        assert_eq!(interaction.recovery_page, RecoveryPage::Transition);
        assert_eq!(interaction.focus, Control::Back);
        assert_eq!(
            interaction.activate_for_subject(Control::Approve, true, &subject),
            None
        );
        assert!(!interaction.confirmed);
        assert_eq!(
            interaction.activate_for_subject(Control::Confirm, true, &subject),
            None
        );
        assert!(interaction.confirmed);
        assert_eq!(
            interaction.activate_for_subject(Control::Approve, true, &subject),
            Some(ApprovalDecision::Approve)
        );

        interaction.activate_for_subject(Control::Back, true, &subject);
        assert_eq!(interaction.recovery_page, RecoveryPage::Evidence);
        assert!(!interaction.confirmed);
        interaction.activate_for_subject(Control::Next, true, &subject);
        interaction.activate_for_subject(Control::Confirm, true, &subject);
        interaction.reset_for_focus_loss();
        assert_eq!(interaction.recovery_page, RecoveryPage::Evidence);
        assert_eq!(interaction.focus, Control::Cancel);
        assert!(!interaction.confirmed);

        assert_eq!(
            interaction.activate_for_subject(Control::Next, false, &subject),
            None
        );
        assert_eq!(interaction.recovery_page, RecoveryPage::Evidence);
        assert_eq!(
            interaction.activate_for_subject(Control::Cancel, false, &subject),
            Some(ApprovalDecision::Decline)
        );
    }

    #[test]
    fn recovery_controls_and_layout_never_hide_decline_or_enable_early_approval() {
        fn right(rect: UiRect) -> f32 {
            rect.x + rect.width
        }
        fn bottom(rect: UiRect) -> f32 {
            rect.y + rect.height
        }
        fn center(rect: UiRect) -> (f64, f64) {
            (
                f64::from(rect.x + rect.width / 2.0),
                f64::from(rect.y + rect.height / 2.0),
            )
        }

        let subject = recovery_subject();
        let width = WINDOW_WIDTH as f32;
        let height = RECOVERY_WINDOW_HEIGHT as f32;
        let layout = recovery_layout(width, height);
        assert!(layout.panel.x >= 0.0 && layout.panel.y >= 0.0);
        assert!(right(layout.panel) <= width);
        assert!(bottom(layout.panel) <= layout.caller.y);
        assert!(bottom(layout.caller) <= layout.warning.y);
        assert!(bottom(layout.warning) <= layout.confirm.y);
        assert!(bottom(layout.confirm) <= layout.cancel.y);
        assert_eq!(layout.back.y, layout.cancel.y);
        assert_eq!(layout.cancel.y, layout.advance.y);
        assert!(bottom(layout.advance) <= layout.footer.y);
        assert!(right(layout.advance) <= width);
        assert!(bottom(layout.footer) <= height);

        let evidence = Interaction::default();
        let (cancel_x, cancel_y) = center(layout.cancel);
        let (next_x, next_y) = center(layout.advance);
        let (confirm_x, confirm_y) = center(layout.confirm);
        assert_eq!(
            control_at_for_subject(
                WINDOW_WIDTH,
                RECOVERY_WINDOW_HEIGHT,
                true,
                cancel_x,
                cancel_y,
                &subject,
                &evidence,
            ),
            Some(Control::Cancel)
        );
        assert_eq!(
            control_at_for_subject(
                WINDOW_WIDTH,
                RECOVERY_WINDOW_HEIGHT,
                true,
                next_x,
                next_y,
                &subject,
                &evidence,
            ),
            Some(Control::Next)
        );
        assert_eq!(
            control_at_for_subject(
                WINDOW_WIDTH,
                RECOVERY_WINDOW_HEIGHT,
                true,
                confirm_x,
                confirm_y,
                &subject,
                &evidence,
            ),
            None
        );

        let transition = Interaction {
            recovery_page: RecoveryPage::Transition,
            focus: Control::Back,
            ..Interaction::default()
        };
        let (back_x, back_y) = center(layout.back);
        assert_eq!(
            control_at_for_subject(
                WINDOW_WIDTH,
                RECOVERY_WINDOW_HEIGHT,
                true,
                back_x,
                back_y,
                &subject,
                &transition,
            ),
            Some(Control::Back)
        );
        assert_eq!(
            control_at_for_subject(
                WINDOW_WIDTH,
                RECOVERY_WINDOW_HEIGHT,
                true,
                confirm_x,
                confirm_y,
                &subject,
                &transition,
            ),
            Some(Control::Confirm)
        );
        assert_eq!(
            control_at_for_subject(
                WINDOW_WIDTH,
                RECOVERY_WINDOW_HEIGHT,
                true,
                next_x,
                next_y,
                &subject,
                &transition,
            ),
            Some(Control::Approve)
        );

        let blocked = blocked_cancel_rect(width, 700.0);
        let (blocked_x, blocked_y) = center(blocked);
        assert_eq!(
            control_at_for_subject(
                WINDOW_WIDTH,
                700.0,
                false,
                blocked_x,
                blocked_y,
                &subject,
                &transition,
            ),
            Some(Control::Cancel)
        );
    }

    fn recovery_subject() -> ApprovalSubject {
        ApprovalSubject::RecoveryParticipation(RecoveryParticipationApproval {
            request_sha256: [0x11; 32],
            ceremony_id: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            ceremony_expires_at: 1_700_000_300,
            persona_anchor: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_owned(),
            root_statement_sha256: [0x22; 32],
            recovery_policy_version: 2,
            recovery_policy_sha256: [0x33; 32],
            recovery_policy_threshold: 2,
            previous_head_sequence: 0,
            previous_head_sha256: None,
            reason: a_quo_approval::RecoveryReason::Recovery,
            previous_key_fingerprint: "SHA256:previous".to_owned(),
            next_key_fingerprint: "SHA256:next".to_owned(),
            participant_role: a_quo_approval::RecoveryParticipantRole::RecoveryAuthority,
            participant_key_fingerprint: "SHA256:participant".to_owned(),
        })
    }
}
