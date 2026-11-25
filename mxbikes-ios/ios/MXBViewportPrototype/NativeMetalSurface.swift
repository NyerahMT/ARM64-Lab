import SwiftUI
import MetalKit

/// Standalone render bridge, not an original-game emulation result.
struct NativeMetalSurface: UIViewRepresentable {
    func makeCoordinator() -> GPUBridge { GPUBridge() }

    func makeUIView(context: Context) -> MTKView {
        let view = MTKView(frame: .zero, device: MTLCreateSystemDefaultDevice())
        view.colorPixelFormat = .bgra8Unorm
        view.depthStencilPixelFormat = .depth32Float
        view.clearDepth = 1.0
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
    private var blendPipelines: [UInt32: MTLRenderPipelineState] = [:]
    private var pipelineDescriptor: MTLRenderPipelineDescriptor?
    private var depthStates: [UInt32: MTLDepthStencilState] = [:]
    private var probeTextureReady = false
    private var probeGPUTexture: MTLTexture?
    private let guestGL = mxb_gl_create()
    private let textureBank = mxb_tex_create()
    private let isRendererProbe = ProcessInfo.processInfo.arguments.contains("--renderer-probe-only")

    deinit {
        mxb_gl_destroy(guestGL)
        mxb_tex_destroy(textureBank)
    }

    func configure(_ view: MTKView) {
        // Keep Swift buffer stride synchronized with C and the MSL scalar lanes.
        guard MemoryLayout<MXBGLVertex>.stride == 40,
              let device = view.device,
              let library = device.makeDefaultLibrary(),
              let vertex = library.makeFunction(name: "mxb_vertex"),
              let fragment = library.makeFunction(name: "mxb_fragment") else { return }
        let descriptor = MTLRenderPipelineDescriptor()
        descriptor.vertexFunction = vertex
        descriptor.fragmentFunction = fragment
        descriptor.colorAttachments[0].pixelFormat = view.colorPixelFormat
        descriptor.depthAttachmentPixelFormat = view.depthStencilPixelFormat
        descriptor.colorAttachments[0].isBlendingEnabled = false
        pipelineDescriptor = descriptor
        pipeline = try? device.makeRenderPipelineState(descriptor: descriptor)
        blendPipelines.removeAll()
        queue = device.makeCommandQueue()
        probeGPUTexture = nil
        depthStates.removeAll()
    }

    private func blendFactor(_ raw: UInt32) -> MTLBlendFactor? {
        switch raw {
        case 0: return .zero
        case 1: return .one
        case 0x0302: return .sourceAlpha
        case 0x0303: return .oneMinusSourceAlpha
        default: return nil
        }
    }
    private func drawPipeline(_ batch: MXBGLDrawBatch, device: MTLDevice) -> MTLRenderPipelineState? {
        if batch.blend_enabled == 0 { return pipeline }
        let key = (batch.blend_src << 16) | batch.blend_dst
        if let cached = blendPipelines[key] { return cached }
        guard let descriptor = pipelineDescriptor?.copy() as? MTLRenderPipelineDescriptor,
              let src = blendFactor(batch.blend_src),
              let dst = blendFactor(batch.blend_dst) else { return nil }
        let color = descriptor.colorAttachments[0]!
        color.isBlendingEnabled = true
        color.rgbBlendOperation = .add
        color.alphaBlendOperation = .add
        color.sourceRGBBlendFactor = src
        color.destinationRGBBlendFactor = dst
        color.sourceAlphaBlendFactor = src
        color.destinationAlphaBlendFactor = dst
        guard let state = try? device.makeRenderPipelineState(descriptor: descriptor) else { return nil }
        blendPipelines[key] = state
        return state
    }
    private func depthState(_ batch: MXBGLDrawBatch, device: MTLDevice) -> MTLDepthStencilState? {
        // GL with depth test disabled must never write depth, even if mask is true.
        let enabled = batch.depth_test != 0
        let write = enabled && batch.depth_write != 0
        let compare: MTLCompareFunction
        if !enabled { compare = .always }
        else {
            switch batch.depth_func {
            case 0x0200: compare = .never
            case 0x0201: compare = .less
            case 0x0202: compare = .equal
            case 0x0203: compare = .lessEqual
            case 0x0204: compare = .greater
            case 0x0205: compare = .notEqual
            case 0x0206: compare = .greaterEqual
            case 0x0207: compare = .always
            default: return nil
            }
        }
        let key = UInt32(compare.rawValue) * 2 + (write ? 1 : 0)
        if let cached = depthStates[key] { return cached }
        let descriptor = MTLDepthStencilDescriptor()
        descriptor.depthCompareFunction = compare
        descriptor.isDepthWriteEnabled = write
        guard let state = device.makeDepthStencilState(descriptor: descriptor) else { return nil }
        depthStates[key] = state
        return state
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
        if isRendererProbe {
            // The synthetic texture is immutable. Allocate its guest name once,
            // not once per 60 Hz frame (the bounded bank has eight slots).
            if !probeTextureReady {
                mxb_tex_reset(textureBank)
                probeTextureReady = mxb_gl_texture_fixture(textureBank) == 1
            }
            if !probeTextureReady || mxb_gl_indexed_fixture(guestGL) == 0 {
                mxb_gl_clear_frame(guestGL)
                encoder.endEncoding()
                command.present(drawable)
                command.commit()
                return
            }
        }
        let count = Int(mxb_gl_vertex_count(guestGL))
        if let device = view.device,
           let vertices = mxb_gl_vertices(guestGL), count > 0 {
            let size = count * MemoryLayout<MXBGLVertex>.stride
            if let buf = device.makeBuffer(bytes: vertices, length: size,
                                           options: .storageModeShared) {
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
                if let cached = isRendererProbe ? probeGPUTexture : nil {
                    encoder.setFragmentTexture(cached, index: 0)
                } else if let texture = device.makeTexture(descriptor: desc) {
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
                    if isRendererProbe { probeGPUTexture = texture }
                } else {
                    // Never issue a textured draw with an unbound texture.
                    encoder.endEncoding()
                    command.present(drawable)
                    command.commit()
                    mxb_gl_clear_frame(guestGL)
                    return
                }

                // Depth, blend and alpha state are captured per original draw.
                // Texture storage is still shared by the prototype.
                if let batches = mxb_gl_batches(guestGL) {
                    for index in 0..<Int(mxb_gl_batch_count(guestGL)) {
                        let batch = batches[index]
                        let first = Int(batch.first_vertex)
                        let length = Int(batch.vertex_count)
                        guard first <= count, length <= count - first,
                              let depth = depthState(batch, device: device),
                              let drawPipeline = drawPipeline(batch, device: device) else { break }
                        encoder.setRenderPipelineState(drawPipeline)
                        encoder.setDepthStencilState(depth)
                        let alpha: [UInt32] = [batch.alpha_test, batch.alpha_func, batch.alpha_ref.bitPattern]
                        alpha.withUnsafeBytes { bytes in
                            encoder.setFragmentBytes(bytes.baseAddress!, length: bytes.count, index: 0)
                        }
                        encoder.drawPrimitives(type: .triangle, vertexStart: first, vertexCount: length)
                    }
                }
            }
        }
        encoder.endEncoding()
        command.present(drawable)
        command.commit()
        mxb_gl_clear_frame(guestGL)
    }
}
