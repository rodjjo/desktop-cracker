//! The renderer: the guest's frame as a streaming OpenGL texture on a quad, and the guest's
//! pointer on top of it.
//!
//! It is **not** a window: the window is `crate::gtk_window` (a GTK window whose content is a
//! `gtk::GLArea`), and the GL calls arrive through a `glow::Context` loaded from the context
//! GTK made.  What this module owns is the drawing — one program, two textures, one quad.
//!
//! It has **no key table**, and it had one removed on 2026-10-11.  The window forwards a key as
//! the kernel's key code, which is a number read from the X server that reported the key
//! (`crate::keymap`); a table of key *names* in the renderer could only be a second, hand-kept
//! copy of that, and the copy it kept was wrong for the keys past 180 (`Up` was 200 there, the
//! kernel calls it 103).

use glow::HasContext as _;

/// The renderer: a streaming RGBA texture on a quad, and the guest's pointer on top of it.
///
/// Written with **modern GL** (a shader, a vertex array, `TEXTURE0`), which is what OpenGL 3.3
/// core actually offers: the immediate-mode calls an older path used (`glBegin`/`glVertex2f`,
/// `glEnable(GL_TEXTURE_2D)`) are gone from a core profile, and a driver that offers one is a
/// driver where they do nothing.
pub struct Renderer {
    program: glow::Program,
    /// The **pointer's** program: the same vertex shader, and a fragment shader that keeps the
    /// texture's alpha (`draw_cursor`).  The frame's program makes everything opaque, which is
    /// right for the guest's screen and wrong for an arrow.
    cursor_program: glow::Program,
    vao: glow::VertexArray,
    /// The buffer the unit quad (and, for one draw, the pointer's quad) lives in.
    quad: glow::Buffer,
    texture: glow::Texture,
    /// The guest's pointer, as its own texture (the shape is redefined rarely, its position
    /// moves constantly).
    cursor: glow::Texture,
    cursor_size: (i32, i32),
    /// The texture's current size, so a geometry change re-allocates it.
    size: (u32, u32),
}

impl Renderer {
    /// Build the program, the quad and the two textures.
    pub fn new(gl: &glow::Context) -> Result<Renderer, String> {
        let program = build_program(gl)?;
        let cursor_program = build_program_with(gl, CURSOR_FRAGMENT)?;
        let (vao, quad, texture, cursor) = unsafe {
            let vao = gl.create_vertex_array().map_err(|e| e.to_string())?;
            gl.bind_vertex_array(Some(vao));
            let buffer = gl.create_buffer().map_err(|e| e.to_string())?;
            gl.bind_buffer(glow::ARRAY_BUFFER, Some(buffer));
            // A unit quad: position and texture coordinate are the same pair, so the
            // framebuffer's first row (the guest's top) lands at the top of the window.
            #[rustfmt::skip]
            let quad: [f32; 16] = [
                0.0, 0.0, 0.0, 0.0,
                1.0, 0.0, 1.0, 0.0,
                0.0, 1.0, 0.0, 1.0,
                1.0, 1.0, 1.0, 1.0,
            ];
            gl.buffer_data_u8_slice(glow::ARRAY_BUFFER, bytemuck_cast(&quad), glow::STATIC_DRAW);
            gl.enable_vertex_attrib_array(0);
            gl.vertex_attrib_pointer_f32(0, 2, glow::FLOAT, false, 16, 0);
            gl.enable_vertex_attrib_array(1);
            gl.vertex_attrib_pointer_f32(1, 2, glow::FLOAT, false, 16, 8);

            let texture = gl.create_texture().map_err(|e| e.to_string())?;
            gl.bind_texture(glow::TEXTURE_2D, Some(texture));
            gl.tex_parameter_i32(
                glow::TEXTURE_2D,
                glow::TEXTURE_MIN_FILTER,
                glow::NEAREST as i32,
            );
            gl.tex_parameter_i32(
                glow::TEXTURE_2D,
                glow::TEXTURE_MAG_FILTER,
                glow::NEAREST as i32,
            );
            gl.tex_parameter_i32(
                glow::TEXTURE_2D,
                glow::TEXTURE_WRAP_S,
                glow::CLAMP_TO_EDGE as i32,
            );
            gl.tex_parameter_i32(
                glow::TEXTURE_2D,
                glow::TEXTURE_WRAP_T,
                glow::CLAMP_TO_EDGE as i32,
            );

            let cursor = gl.create_texture().map_err(|e| e.to_string())?;
            gl.bind_texture(glow::TEXTURE_2D, Some(cursor));
            gl.tex_parameter_i32(
                glow::TEXTURE_2D,
                glow::TEXTURE_MIN_FILTER,
                glow::NEAREST as i32,
            );
            gl.tex_parameter_i32(
                glow::TEXTURE_2D,
                glow::TEXTURE_MAG_FILTER,
                glow::NEAREST as i32,
            );
            gl.tex_parameter_i32(
                glow::TEXTURE_2D,
                glow::TEXTURE_WRAP_S,
                glow::CLAMP_TO_EDGE as i32,
            );
            gl.tex_parameter_i32(
                glow::TEXTURE_2D,
                glow::TEXTURE_WRAP_T,
                glow::CLAMP_TO_EDGE as i32,
            );
            (vao, buffer, texture, cursor)
        };
        Ok(Renderer {
            program,
            cursor_program,
            vao,
            quad,
            texture,
            cursor,
            cursor_size: (0, 0),
            size: (0, 0),
        })
    }

    /// How big the frame texture is (the guest's geometry).
    pub fn texture_size(&self) -> (u32, u32) {
        self.size
    }

    /// Make the frame texture large enough for `width`x`height`.
    pub fn ensure_texture(&mut self, gl: &glow::Context, width: u32, height: u32) {
        if self.size == (width, height) {
            return;
        }
        unsafe {
            gl.bind_texture(glow::TEXTURE_2D, Some(self.texture));
            gl.tex_image_2d(
                glow::TEXTURE_2D,
                0,
                glow::RGBA8 as i32,
                width as i32,
                height as i32,
                0,
                glow::RGBA,
                glow::UNSIGNED_BYTE,
                glow::PixelUnpackData::Slice(None),
            );
        }
        self.size = (width, height);
    }

    /// Upload one damaged rectangle of the guest's frame.
    ///
    /// `stride` is the framebuffer's own stride in bytes, and the guest's layout is told by
    /// its pixman format: BGRA in memory on a little-endian host is `BGRA`/`UNSIGNED_INT_8_8_8_8_REV`
    /// (alpha in the high byte), and the shader takes the RGB it needs.
    ///
    /// # Safety
    ///
    /// `base` must point into a mapping that stays valid for the whole call, at least
    /// `offset + w*h*bpp` bytes in, and the mapping must be the layout `format`/`type_`
    /// describe.  The frame path holds the surface alive (`Arc`) while it calls this, which
    /// is what makes that true; an `unsafe` block hidden inside would have hidden the
    /// requirement instead.
    #[allow(clippy::too_many_arguments)] // a rectangle, its layout, and where to read it
    pub unsafe fn upload_rect(
        &self,
        gl: &glow::Context,
        base: *const u8,
        offset: usize,
        stride: u32,
        x: i32,
        y: i32,
        w: i32,
        h: i32,
        bpp: u32,
        format: u32,
        type_: u32,
    ) {
        if base.is_null() || w <= 0 || h <= 0 {
            return;
        }
        {
            gl.bind_texture(glow::TEXTURE_2D, Some(self.texture));
            gl.pixel_store_i32(glow::UNPACK_ROW_LENGTH, (stride / bpp.max(1)) as i32);
            gl.tex_sub_image_2d(
                glow::TEXTURE_2D,
                0,
                x,
                y,
                w,
                h,
                format,
                type_,
                glow::PixelUnpackData::Slice(Some(std::slice::from_raw_parts(
                    base.add(offset),
                    (w as usize) * (h as usize) * (bpp as usize),
                ))),
            );
        }
    }

    /// Put the guest's pointer shape into its own texture (`CursorDefine`).
    pub fn upload_cursor(&mut self, gl: &glow::Context, width: i32, height: i32, data: &[u8]) {
        if width <= 0 || height <= 0 || data.is_empty() {
            return;
        }
        unsafe {
            gl.bind_texture(glow::TEXTURE_2D, Some(self.cursor));
            gl.pixel_store_i32(glow::UNPACK_ROW_LENGTH, 0);
            // **The row length is 0 (unset) on purpose.**  `UNPACK_ROW_LENGTH` is a *client*
            // pixel-store state: setting it here once leaves it set for the **frame** upload
            // that follows (`upload_rect`, which sets it for its own stride anyway), and, more
            // to the point, it used to be given in *pixels* while the pointer arrives as a
            // tightly packed `width` x `height` block — the pointer's upload never needed it.
            gl.tex_image_2d(
                glow::TEXTURE_2D,
                0,
                glow::RGBA8 as i32,
                width,
                height,
                0,
                glow::BGRA,
                glow::UNSIGNED_INT_8_8_8_8_REV,
                glow::PixelUnpackData::Slice(Some(data)),
            );
        }
        self.cursor_size = (width, height);
    }

    /// The cursor texture's size (0,0 when the guest never defined one).
    pub fn cursor_size(&self) -> (i32, i32) {
        self.cursor_size
    }

    /// Draw the frame (letterboxed inside the window) and the pointer on top of it.
    ///
    /// `geometry` is `None` while the guest has never sent pixels: the window then shows the
    /// clear colour, which is what a window that exists before its guest looks like.
    ///
    /// `cursor` is the guest's **pointer**: position, hot spot, and whether the guest wants it
    /// shown.  The renderer holds its shape in a texture of its own (`Renderer::upload_cursor`).
    pub fn draw(
        &self,
        gl: &glow::Context,
        viewport: (u32, u32),
        geometry: Option<(u32, u32)>,
        cursor: Option<CursorDraw>,
    ) {
        unsafe {
            gl.viewport(0, 0, viewport.0 as i32, viewport.1 as i32);
            gl.clear_color(0.05, 0.05, 0.06, 1.0);
            gl.clear(glow::COLOR_BUFFER_BIT);
            let Some((fw, fh)) = geometry else {
                return;
            };
            if fw == 0 || fh == 0 || self.size != (fw, fh) {
                return;
            }
            // The frame is scaled to fill the window, whatever the window's size: the
            // guest's screen is always its own size, and the window is the rule's.
            let (x, y, w, h) = self.image_rect(viewport, (fw, fh));
            gl.use_program(Some(self.program));
            gl.bind_vertex_array(Some(self.vao));
            // **The unit quad, every frame**: the pointer's pass rewrites this same buffer with
            // its own small quad (see `draw_cursor`), so the frame must put the unit quad back
            // before it draws — otherwise the next frame is drawn with the pointer's rect
            // stretched across the whole window.  That is the "big cursor over a black screen"
            // the operator saw.
            gl.bind_buffer(glow::ARRAY_BUFFER, Some(self.quad));
            gl.buffer_data_u8_slice(glow::ARRAY_BUFFER, unit_quad(), glow::DYNAMIC_DRAW);
            gl.active_texture(glow::TEXTURE0);
            gl.bind_texture(glow::TEXTURE_2D, Some(self.texture));
            gl.uniform_1_i32(
                gl.get_uniform_location(self.program, "u_texture").as_ref(),
                0,
            );
            gl.uniform_4_f32(
                gl.get_uniform_location(self.program, "u_rect").as_ref(),
                x,
                y,
                w,
                h,
            );
            gl.uniform_4_f32(
                gl.get_uniform_location(self.program, "u_uv").as_ref(),
                0.0,
                0.0,
                1.0,
                1.0,
            );
            gl.uniform_2_f32(
                gl.get_uniform_location(self.program, "u_viewport").as_ref(),
                viewport.0 as f32,
                viewport.1 as f32,
            );
            gl.draw_arrays(glow::TRIANGLE_STRIP, 0, 4);

            if let Some(cursor) = cursor {
                // The guest's own arrow, when it has defined one and wants it shown.
                self.draw_cursor(gl, viewport, (fw, fh), cursor);
            }
        }
    }

    /// The pointer, drawn where the guest put it (its **hot spot** is where a click lands).
    ///
    /// **The quad is in the frame's own 0..1 space, not in guest pixels.**  The vertex shader
    /// places a vertex at `u_rect.xy + a_pos * u_rect.zw`, i.e. it treats `a_pos` as a fraction
    /// of the rectangle the pass covers — that is what makes one program serve both the frame
    /// (a unit quad over the letterboxed rectangle) and the pointer (a small quad inside it).
    /// Feeding it guest *pixels* (hundreds) multiplied by a rectangle a thousand pixels wide put
    /// the quad at `x * 1280`, far outside the window, so the pointer was clipped away entirely.
    ///
    /// The pointer also has **its own program** (`CURSOR_FRAGMENT`): the frame's fragment shader
    /// forces alpha to `1.0` (the guest's screen is opaque), and a pointer drawn with it is a
    /// solid black square — every transparent pixel of the arrow's box written as opaque black.
    /// The pointer's shader keeps the texture's own alpha and blends with it.
    fn draw_cursor(
        &self,
        gl: &glow::Context,
        viewport: (u32, u32),
        geometry: (u32, u32),
        cursor: CursorDraw,
    ) {
        if self.cursor_size.0 <= 0 || !cursor.visible {
            return;
        }
        let (gw, gh) = (geometry.0 as f32, geometry.1 as f32);
        if gw <= 0.0 || gh <= 0.0 {
            return;
        }
        let (cw, ch) = (self.cursor_size.0 as f32, self.cursor_size.1 as f32);
        // Where the guest says the pointer is, in **guest pixels**, said as a fraction of the
        // guest's screen: the quad's top-left is the position minus the hot spot, which is the
        // pixel of the arrow a click lands on.
        let quad = UnitQuad {
            x0: (cursor.x as f32 - cursor.hot_x as f32) / gw,
            y0: (cursor.y as f32 - cursor.hot_y as f32) / gh,
            w: cw / gw,
            h: ch / gh,
        };
        unsafe {
            gl.enable(glow::BLEND);
            // **The pointer's own blend**, and it leaves the window's alpha channel alone: the GL
            // config was asked for one (`with_alpha_size(8)`), and on a compositing session that
            // channel is what the compositor composites the window with — an arrow blended into it
            // can make the window itself partially transparent.
            //
            // The pointer's ARGB is used as it came from the guest (its colour bytes are not
            // premultiplied by its alpha), so `SRC_ALPHA / ONE_MINUS_SRC_ALPHA` is the pair that
            // mixes it with the guest's screen, with the destination alpha kept at 1.
            gl.blend_func_separate(
                glow::SRC_ALPHA,
                glow::ONE_MINUS_SRC_ALPHA,
                glow::ONE,
                glow::ONE_MINUS_SRC_ALPHA,
            );
            gl.use_program(Some(self.cursor_program));
            gl.bind_vertex_array(Some(self.vao));
            gl.bind_texture(glow::TEXTURE_2D, Some(self.cursor));
            gl.uniform_1_i32(
                gl.get_uniform_location(self.cursor_program, "u_texture")
                    .as_ref(),
                0,
            );
            gl.bind_buffer(glow::ARRAY_BUFFER, Some(self.quad));
            gl.buffer_data_u8_slice(glow::ARRAY_BUFFER, &quad.bytes(), glow::DYNAMIC_DRAW);
            self.place(gl, self.cursor_program, viewport, geometry, quad);
            gl.draw_arrays(glow::TRIANGLE_STRIP, 0, 4);
            gl.disable(glow::BLEND);
            // The frame's program is the one the next frame draws with, and the frame's pass
            // rewrites the unit quad anyway (`unit_quad` in `draw`).
            gl.use_program(Some(self.program));
        }
    }

    /// Set `u_rect`, `u_uv` and `u_viewport` for a pass drawn inside the frame's rectangle.
    ///
    /// `quad` is the part of the guest's screen the pass covers, in the shader's 0..1 space: it is
    /// both where the quad goes (times the frame's rectangle) and which texels it shows.
    fn place(
        &self,
        gl: &glow::Context,
        program: glow::Program,
        viewport: (u32, u32),
        geometry: (u32, u32),
        quad: UnitQuad,
    ) {
        let (x, y, w, h) = self.image_rect(viewport, geometry);
        unsafe {
            gl.uniform_4_f32(
                gl.get_uniform_location(program, "u_rect").as_ref(),
                x,
                y,
                w,
                h,
            );
            gl.uniform_4_f32(
                gl.get_uniform_location(program, "u_uv").as_ref(),
                quad.x0,
                quad.y0,
                quad.w,
                quad.h,
            );
            gl.uniform_2_f32(
                gl.get_uniform_location(program, "u_viewport").as_ref(),
                viewport.0 as f32,
                viewport.1 as f32,
            );
        }
    }

    /// The frame's rectangle inside the window: the guest's aspect ratio is kept, centred.
    fn image_rect(&self, viewport: (u32, u32), geometry: (u32, u32)) -> (f32, f32, f32, f32) {
        let (win_w, win_h) = (viewport.0 as f32, viewport.1 as f32);
        let (fw, fh) = (geometry.0 as f32, geometry.1 as f32);
        if fw == 0.0 || fh == 0.0 {
            return (0.0, 0.0, win_w, win_h);
        }
        let scale = (win_w / fw).min(win_h / fh);
        let (w, h) = (fw * scale, fh * scale);
        ((win_w - w) / 2.0, (win_h - h) / 2.0, w, h)
    }
}

impl Drop for Renderer {
    fn drop(&mut self) {
        // The GL context is already gone when the process is ending; a leak here is the
        // driver's to free, and a failing delete is not worth a panic on shutdown.
    }
}

/// What to draw for the guest's pointer this frame.
#[derive(Debug, Clone, Copy)]
pub struct CursorDraw {
    pub x: i32,
    pub y: i32,
    pub hot_x: i32,
    pub hot_y: i32,
    pub visible: bool,
}

/// Compile the two shaders and link them: the frame is one textured quad, placed by
/// `u_rect` (a letterboxed rectangle in window pixels) and sampled with the quad's own
/// coordinate.
fn build_program(gl: &glow::Context) -> Result<glow::Program, String> {
    build_program_with(gl, FRAME_FRAGMENT)
}

/// The vertex shader both passes use: `a_pos` is a fraction of the rectangle `u_rect`
/// describes, and the same fraction samples the texture, so a pass is one textured quad placed
/// anywhere in the window.
const VERTEX: &str = r#"#version 330 core
layout(location = 0) in vec2 a_pos;
// `u_rect` places the quad in the window (x, y, w, h in window pixels); `u_uv` says which part of
// the **texture** the quad shows, as the rectangle `a_pos` runs over.
uniform vec4 u_rect;
uniform vec4 u_uv;
uniform vec2 u_viewport;
out vec2 v_uv;
void main() {
    vec2 pixel = u_rect.xy + a_pos * u_rect.zw;
    vec2 ndc = vec2(pixel.x / u_viewport.x * 2.0 - 1.0, 1.0 - pixel.y / u_viewport.y * 2.0);
    // **The texture coordinate is not `a_pos`.**  It is for the frame, whose quad *is* the whole
    // picture (`u_uv = (0,0,1,1)`), but the pointer's quad covers a small rectangle of the guest's
    // screen, so `a_pos` there runs over `0.49 … 0.55` — and mapping that straight at the texture
    // samples the middle of the 64x64 arrow shape, which is transparent.  The pointer was drawn,
    // in the right place, with the wrong texels: an invisible arrow.  `u_uv` is what makes one
    // shader serve both.
    v_uv = (a_pos - u_uv.xy) / u_uv.zw;
    gl_Position = vec4(ndc, 0.0, 1.0);
}
"#;

/// The frame's fragment shader: **opaque**.  The guest's screen has no alpha of its own, and a
/// framebuffer that kept one would show the window's background through it.
const FRAME_FRAGMENT: &str = r#"#version 330 core
in vec2 v_uv;
uniform sampler2D u_texture;
out vec4 out_color;
void main() { out_color = vec4(texture(u_texture, v_uv).rgb, 1.0); }
"#;

/// The pointer's fragment shader: the texture's **own alpha**, so the arrow's shape is the
/// shape of what it covers.
const CURSOR_FRAGMENT: &str = r#"#version 330 core
in vec2 v_uv;
uniform sampler2D u_texture;
out vec4 out_color;
void main() { out_color = texture(u_texture, v_uv); }
"#;

/// Compile `VERTEX` and one fragment shader and link them.
fn build_program_with(gl: &glow::Context, fragment_source: &str) -> Result<glow::Program, String> {
    fn compile(gl: &glow::Context, kind: u32, source: &str) -> Result<glow::Shader, String> {
        unsafe {
            let shader = gl.create_shader(kind).map_err(|e| e.to_string())?;
            gl.shader_source(shader, source);
            gl.compile_shader(shader);
            if !gl.get_shader_compile_status(shader) {
                let log = gl.get_shader_info_log(shader);
                gl.delete_shader(shader);
                return Err(format!("a shader did not compile: {log}"));
            }
            Ok(shader)
        }
    }
    unsafe {
        let vertex = compile(gl, glow::VERTEX_SHADER, VERTEX)?;
        let fragment = compile(gl, glow::FRAGMENT_SHADER, fragment_source)?;
        let program = gl.create_program().map_err(|e| e.to_string())?;
        gl.attach_shader(program, vertex);
        gl.attach_shader(program, fragment);
        gl.link_program(program);
        let linked = gl.get_program_link_status(program);
        let log = gl.get_program_info_log(program);
        gl.detach_shader(program, vertex);
        gl.detach_shader(program, fragment);
        gl.delete_shader(vertex);
        gl.delete_shader(fragment);
        if !linked {
            gl.delete_program(program);
            return Err(format!("the shader program did not link: {log}"));
        }
        Ok(program)
    }
}

/// **The unit quad**: position and texture coordinate are the same pair, so the framebuffer's
/// first row (the guest's top) lands at the top of the window.
fn unit_quad() -> &'static [u8] {
    #[rustfmt::skip]
    static QUAD: [f32; 16] = [
        0.0, 0.0, 0.0, 0.0,
        1.0, 0.0, 1.0, 0.0,
        0.0, 1.0, 0.0, 1.0,
        1.0, 1.0, 1.0, 1.0,
    ];
    bytemuck_cast(&QUAD)
}

/// A quad **inside** the frame's own 0..1 space: the position fractions `a_pos` runs over, so a
/// pass covers `[x0, x0+w] x [y0, y0+h]` of the picture rather than all of it.
///
/// It exists because the pass that draws the guest's pointer needs exactly this arithmetic, and
/// because writing it out by hand is how the pointer's coordinates came to be guest *pixels* in a
/// space that is a fraction — the bug the operator saw as "the cursor is not drawn at all".
#[derive(Clone, Copy)]
struct UnitQuad {
    x0: f32,
    y0: f32,
    w: f32,
    h: f32,
}

impl UnitQuad {
    /// The 4 vertices of a `TRIANGLE_STRIP`: (x, y, u, v).
    fn bytes(&self) -> [u8; 64] {
        let (x0, y0, x1, y1) = (self.x0, self.y0, self.x0 + self.w, self.y0 + self.h);
        #[rustfmt::skip]
        let quad: [f32; 16] = [
            x0, y0, 0.0, 0.0,
            x1, y0, 1.0, 0.0,
            x0, y1, 0.0, 1.0,
            x1, y1, 1.0, 1.0,
        ];
        let mut out = [0u8; 64];
        out.copy_from_slice(bytemuck_cast(&quad));
        out
    }
}

/// Reinterpret an `f32` slice as bytes, for a vertex buffer.
fn bytemuck_cast(values: &[f32]) -> &[u8] {
    // SAFETY: `f32` has no padding and no invalid bit patterns, so the slice is plain bytes.
    unsafe {
        std::slice::from_raw_parts(values.as_ptr().cast::<u8>(), std::mem::size_of_val(values))
    }
}
