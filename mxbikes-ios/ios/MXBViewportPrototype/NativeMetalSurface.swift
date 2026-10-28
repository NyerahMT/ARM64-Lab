import SwiftUI
import MetalKit

/// Standalone render bridge, not an original-game emulation result.
struct NativeMetalSurface: UIViewRepresentable {
    func makeCoordinator() -> GPUBridge { GPUBridge() }

    func makeUIView(context: Context) -> MTKView {
        let view = MTKView(frame: .zero, device: MTLCreateSystemDefaultDevice())
        view.colorPixelFormat = .bgra8Unorm
        view.clearColor = MTLClearColor(red: 0.025, green: 0.03, blue: 0.045, alpha: 1)
        view.framebufferOnly = true
        view.preferredFramesPerSecond = 60
        view.isPaused = false
        view.enableSetNeedsDisplay = false
        context.coordinator.configure(view)
        view.delegate = context.coordinator
        return view
    }
    func updateUIView(_ uiView: MTKView, context: Context) {}
}

final class GPUBridge: NSObject, MTKViewDelegate {
    private var queue: MTLCommandQueue?
    private var pipeline: MTLRenderPipelineState?
    private let guestGL = mxb_gl_create()
    private let textureBank = mxb_tex_create()
    private let isRendererProbe = ProcessInfo.processInfo.arguments.contains("--renderer-probe-only")

    deinit {
        mxb_gl_destroy(guestGL)
        mxb_tex_destroy(textureBank)
    }

    func configure(_ view: MTKView) {
        guard let device = view.device,
              let library = device.makeDefaultLibrary(),
              let vertex = library.makeFunction(name: "mxb_vertex"),
              let fragment = library.makeFunction(name: "mxb_fragment") else { return }
        let descriptor = MTLRenderPipelineDescriptor()
        descriptor.vertexFunction = vertex
        descriptor.fragmentFunction = fragment
        descriptor.colorAttachments[0].pixelFormat = view.colorPixelFormat
        descriptor.colorAttachments[0].isBlendingEnabled = true
        descriptor.colorAttachments[0].rgbBlendOperation = .add
        descriptor.colorAttachments[0].alphaBlendOperation = .add
        descriptor.colorAttachments[0].sourceRGBBlendFactor = .sourceAlpha
        descriptor.colorAttachments[0].destinationRGBBlendFactor = .oneMinusSourceAlpha
        descriptor.colorAttachments[0].sourceAlphaBlendFactor = .one
        descriptor.colorAttachments[0].destinationAlphaBlendFactor = .oneMinusSourceAlpha
        pipeline = try? device.makeRenderPipelineState(descriptor: descriptor)
        queue = device.makeCommandQueue()
    }
    func mtkView(_ view: MTKView, drawableSizeWillChange size: CGSize) {}

    func draw(in view: MTKView) {
        guard let queue,
              let drawable = view.currentDrawable,
              let pass = view.currentRenderPassDescriptor,
              let command = queue.makeCommandBuffer(),
              let encoder = command.makeRenderCommandEncoder(descriptor: pass) else { return }
        // Actual Metal render pass. Nothing is drawn until genuine translated
        // game OpenGL calls are connected; a test triangle is NOT a game frame.
        // Explicit simulator-only shader/Metal validation. This triangle
        // comes from synthetic test commands, never the MX Bikes binary.
        // True indexed draw passes through guest-addressed positions, colors,
        // and indices. This fixture is SYNTHETIC, not actual game execution.
        if isRendererProbe && (mxb_gl_indexed_fixture(guestGL) == 0 ||
                               mxb_gl_texture_fixture(textureBank) == 0) {
            encoder.endEncoding()
            command.commit()
            return
        }
        let count = Int(mxb_gl_vertex_count(guestGL))
        if let pipeline, let device = view.device,
           let vertices = mxb_gl_vertices(guestGL), count > 0 {
            let size = count * MemoryLayout<MXBGLVertex>.stride
            if let buf = device.makeBuffer(bytes: vertices, length: size,
                                           options: .storageModeShared) {
                encoder.setRenderPipelineState(pipeline)
                encoder.setVertexBuffer(buf, offset: 0, index: 0)

                // Blank fallback is white; the probe uses real native RGBA data.
                var w: UInt32 = 0
                var h: UInt32 = 0
                let texels = mxb_tex_current_rgba(textureBank, &w, &h)
                let tw = texels != nil ? Int(w) : 1
                let th = texels != nil ? Int(h) : 1
                let desc = MTLTextureDescriptor.texture2DDescriptor(
                    pixelFormat: .rgba8Unorm, width: tw, height: th, mipmapped: false
                )
                desc.usage = [.shaderRead]
                if let texture = device.makeTexture(descriptor: desc) {
                    let region = MTLRegionMake2D(0, 0, tw, th)
                    if let texels {
                        texture.replace(region: region, mipmapLevel: 0,
                                        withBytes: texels, bytesPerRow: tw * 4)
                    } else {
                        let white: [UInt8] = [255, 255, 255, 255]
                        white.withUnsafeBytes { bytes in
                            texture.replace(region: region, mipmapLevel: 0,
                                            withBytes: bytes.baseAddress!, bytesPerRow: 4)
                        }
                    }
                    encoder.setFragmentTexture(texture, index: 0)
                }

                encoder.drawPrimitives(type: .triangle, vertexStart: 0, vertexCount: count)
            }
        }
        encoder.endEncoding()
        command.present(drawable)
        command.commit()
        mxb_gl_clear_frame(guestGL)
    }
}
