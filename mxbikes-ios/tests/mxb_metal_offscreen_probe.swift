import Foundation
import Metal
import Darwin

// Synthetic offscreen GPU regression for the actual iOS shader. This is
// never original-game execution. Hosted CI without a Metal device skips
// GPU execution explicitly; the Swift probe still must compile.
struct ProbeFailure: Error, CustomStringConvertible {
    let description: String
    init(_ text: String) { description = text }
}
func require<T>(_ value: T?, _ what: String) throws -> T {
    guard let value else { throw ProbeFailure(what) }
    return value
}

func run(_ device: MTLDevice, shaderPath: String) throws {
    let source = try String(contentsOfFile: shaderPath, encoding: .utf8)
    let library = try device.makeLibrary(source: source, options: nil)
    let desc = MTLRenderPipelineDescriptor()
    desc.vertexFunction = try require(library.makeFunction(name: "mxb_vertex"), "Missing vertex shader")
    desc.fragmentFunction = try require(library.makeFunction(name: "mxb_fragment"), "Missing fragment shader")
    desc.colorAttachments[0].pixelFormat = .rgba8Unorm
    desc.depthAttachmentPixelFormat = .depth32Float
    let pipeline = try device.makeRenderPipelineState(descriptor: desc)
    let queue = try require(device.makeCommandQueue(), "No command queue")
    let dimension = 64
    let stride = dimension * 4
    let colorDesc = MTLTextureDescriptor.texture2DDescriptor(pixelFormat: .rgba8Unorm,
        width: dimension, height: dimension, mipmapped: false)
    colorDesc.storageMode = .private
    colorDesc.usage = .renderTarget
    let depthDesc = MTLTextureDescriptor.texture2DDescriptor(pixelFormat: .depth32Float,
        width: dimension, height: dimension, mipmapped: false)
    depthDesc.storageMode = .private
    depthDesc.usage = .renderTarget
    let whiteDesc = MTLTextureDescriptor.texture2DDescriptor(pixelFormat: .rgba8Unorm,
        width: 1, height: 1, mipmapped: false)
    whiteDesc.storageMode = device.hasUnifiedMemory ? .shared : .managed
    whiteDesc.usage = .shaderRead
    let white = try require(device.makeTexture(descriptor: whiteDesc), "No white texture")
    let whiteBytes: [UInt8] = [255,255,255,255]
    whiteBytes.withUnsafeBytes {
        white.replace(region: MTLRegionMake2D(0,0,1,1), mipmapLevel: 0,
                      withBytes: $0.baseAddress!, bytesPerRow: 4)
    }
    // Exactly ten float32 lanes per vertex, matching the C ABI. Three
    // overlapping triangles: red at z=.6, green at z=-.5, blue at z=.2.
    // Negative GL clip Z must not be discarded by Metal.
    var lanes: [Float] = []
    for (z, rgba) in [(Float(0.6), [Float(1),0,0,1]),
                      (Float(-0.5), [Float(0),1,0,1]),
                      (Float(0.2), [Float(0),0,1,1])] {
        for (x,y) in [(Float(-0.8),Float(-0.8)),(Float(0.8),Float(-0.8)),(Float(0),Float(0.8))] {
            lanes.append(contentsOf: [x,y,z,1])
            lanes.append(contentsOf: rgba)
            lanes.append(contentsOf: [0.5,0.5])
        }
    }
    let vertexBuffer = try require(lanes.withUnsafeBytes {
        device.makeBuffer(bytes: $0.baseAddress!, length: $0.count, options: .storageModeShared)
    }, "No vertex buffer")
    func depth(_ compare: MTLCompareFunction, _ write: Bool) throws -> MTLDepthStencilState {
        let d = MTLDepthStencilDescriptor()
        d.depthCompareFunction = compare
        d.isDepthWriteEnabled = write
        return try require(device.makeDepthStencilState(descriptor: d), "No depth state")
    }
    let lessWrite = try depth(.less, true)
    let lessRead = try depth(.less, false)
    let disabled = try depth(.always, false)

    func sample(_ states: [MTLDepthStencilState]) throws -> [UInt8] {
        let color = try require(device.makeTexture(descriptor: colorDesc), "No color target")
        let depthTarget = try require(device.makeTexture(descriptor: depthDesc), "No depth target")
        let readback = try require(device.makeBuffer(length: stride * dimension, options: .storageModeShared),
                                   "No readback buffer")
        let pass = MTLRenderPassDescriptor()
        pass.colorAttachments[0].texture = color
        pass.colorAttachments[0].loadAction = .clear
        pass.colorAttachments[0].storeAction = .store
        pass.colorAttachments[0].clearColor = MTLClearColorMake(0,0,0,1)
        pass.depthAttachment.texture = depthTarget
        pass.depthAttachment.loadAction = .clear
        pass.depthAttachment.storeAction = .dontCare
        pass.depthAttachment.clearDepth = 1
        let command = try require(queue.makeCommandBuffer(), "No command buffer")
        let encoder = try require(command.makeRenderCommandEncoder(descriptor: pass), "No render encoder")
        encoder.setRenderPipelineState(pipeline)
        encoder.setVertexBuffer(vertexBuffer, offset: 0, index: 0)
        encoder.setFragmentTexture(white, index: 0)
        for (i,state) in states.enumerated() {
            encoder.setDepthStencilState(state)
            encoder.drawPrimitives(type: .triangle, vertexStart: 3*i, vertexCount: 3)
        }
        encoder.endEncoding()
        let blit = try require(command.makeBlitCommandEncoder(), "No blit encoder")
        blit.copy(from: color, sourceSlice: 0, sourceLevel: 0,
                  sourceOrigin: MTLOriginMake(0,0,0),
                  sourceSize: MTLSizeMake(dimension,dimension,1),
                  to: readback, destinationOffset: 0,
                  destinationBytesPerRow: stride, destinationBytesPerImage: stride * dimension)
        blit.endEncoding()
        command.commit()
        command.waitUntilCompleted()
        guard command.status == .completed else {
            throw ProbeFailure("GPU command failed: " + String(describing: command.error))
        }
        let pixel = readback.contents().assumingMemoryBound(to: UInt8.self) + stride*(dimension/2)+4*(dimension/2)
        return Array(UnsafeBufferPointer(start: pixel, count: 4))
    }
    let cases: [([MTLDepthStencilState], [UInt8], String)] = [
        ([lessWrite,lessWrite,lessWrite], [0,255,0,255], "near triangle wins"),
        ([lessWrite,lessRead,lessWrite], [0,0,255,255], "depth write disabled"),
        ([lessWrite,lessWrite,disabled], [0,0,255,255], "depth test disabled"),
        ([disabled,disabled,disabled], [0,0,255,255], "submission order"),
    ]
    for (states, expected, label) in cases {
        let actual = try sample(states)
        guard actual == expected else {
            throw ProbeFailure(label + ": expected " + String(describing: expected) +
                               ", got " + String(describing: actual))
        }
        print("PASS: actual Metal shader RGBA readback — " + label)
    }
    print("PASS: synthetic Metal geometry, 40-byte stride, GL clip depth, and depth-state readback")
}

do {
    guard CommandLine.arguments.count == 2 else { throw ProbeFailure("Expected shader source path") }
    if let device = MTLCreateSystemDefaultDevice() {
        try run(device, shaderPath: CommandLine.arguments[1])
    } else {
        print("SKIP: no Metal GPU available on this macOS runner; probe compiled, GPU execution unverified")
    }
} catch {
    FileHandle.standardError.write(Data(("Metal probe failed: " + String(describing: error) + "\n").utf8))
    exit(1)
}
