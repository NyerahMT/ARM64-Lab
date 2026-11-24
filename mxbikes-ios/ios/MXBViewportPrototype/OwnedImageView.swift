import CryptoKit
import SwiftUI
import UniformTypeIdentifiers

/// Owns the backing store for the lifetime of the guest mappings.
final class OwnedImage {
    static let fileSize = 4_113_408
    static let digest = "4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
    let memory: MXBGuestMemory
    private let process: UnsafeMutablePointer<MXBOwnedStartup>
    let directory: String?
    var startupPC: UInt64 { process.pointee.pc }
    var startupServices: UInt32 { process.pointee.services }
    var startupSteps: UInt32 { process.pointee.instructions }
    let plan: MXBPEImage
    private let backing: UnsafeMutablePointer<UInt8>

    init(data: Data, filename: String) throws {
        guard data.count == Self.fileSize,
              SHA256.hash(data: data).map({ String(format: "%02x", $0) }).joined() == Self.digest else {
            throw LoadError.wrongBuild
        }
        var mapped = MXBGuestMemory()
        var layout = MXBPEImage()
        let storage = try data.withUnsafeBytes { raw in
            let file = raw.bindMemory(to: UInt8.self)
            guard mxb_pe_plan(file.baseAddress, file.count, &layout) == 1 else {
                throw LoadError.mapping
            }
            let capacity = Int(layout.image_size)
            let bytes = UnsafeMutablePointer<UInt8>.allocate(capacity: capacity)
            guard mxb_pe_map(&mapped, file.baseAddress, file.count, bytes, capacity, &layout) == 1 else {
                bytes.deallocate()
                throw LoadError.mapping
            }
            return bytes
        }
        let state = UnsafeMutablePointer<MXBOwnedStartup>.allocate(capacity: 1)
        state.initialize(to: MXBOwnedStartup())
        let started = mxb_owned_startup(state, &mapped, layout.image_base + UInt64(layout.entry_rva))
        var result = [CChar](repeating: 0, count: 262)
        let resolved = ("C:\\MX Bikes\\" + filename).withCString { path in
            result.withUnsafeMutableBufferPointer { buffer in
                mxb_owned_directory(&mapped, path, buffer.baseAddress, buffer.count)
            }
        }
        if started == 0 || resolved == 0 {
            state.deinitialize(count: 1)
            state.deallocate()
            storage.deallocate()
            throw started == 0 ? LoadError.startup : LoadError.directory
        }
        directory = resolved == 1 ? String(cString: result) : nil
        process = state
        backing = storage
        memory = mapped
        plan = layout
    }

    deinit {
        process.deinitialize(count: 1)
        process.deallocate()
        backing.deallocate()
    }

    static func read(_ url: URL) throws -> OwnedImage {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        guard try handle.seekToEnd() == UInt64(fileSize) else { throw LoadError.wrongBuild }
        try handle.seek(toOffset: 0)
        var data = Data()
        while data.count < fileSize {
            guard let block = try handle.read(upToCount: fileSize - data.count), !block.isEmpty else {
                throw LoadError.wrongBuild
            }
            data.append(block)
        }
        return try OwnedImage(data: data, filename: url.lastPathComponent)
    }

    enum LoadError: LocalizedError {
        case wrongBuild, mapping, directory, startup
        var errorDescription: String? {
            switch self {
            case .wrongBuild: return "This file differs from the MX Bikes build verified by the port."
            case .startup: return "The original startup routine stopped before the second CRT stage."
            case .directory: return "The original directory routine stopped before returning."
            case .mapping: return "The native loader could not map this executable."
            }
        }
    }
}

struct OwnedImageView: View {
    @State private var choosingFile = false
    @State private var loading = false
    @State private var loaded: OwnedImage?
    @State private var failure: String?

    var body: some View {
        VStack(alignment: .leading) {
            Button(loading ? "Loading MX Bikes…" : "Open MX Bikes executable") { choosingFile = true }
                .buttonStyle(.borderedProminent)
                .disabled(loading)
            if let image = loaded {
                Text("Mapped \(image.plan.section_count) sections · \(image.plan.image_size) bytes")
                if image.startupSteps > 0 {
                    Text("Startup paused at " + String(format: "0x%llX", image.startupPC))
                    Text("\(image.startupSteps) guest instructions · \(image.startupServices) host service calls")
                }
                if let directory = image.directory { Text("Game directory " + directory) }
                Text("Game entry " + String(format: "0x%llX", image.plan.image_base + UInt64(image.plan.entry_rva)))
            }
            if let failure { Text(failure) }
        }
        .font(.caption)
        .fileImporter(isPresented: $choosingFile, allowedContentTypes: [.data]) { result in
            switch result {
            case .success(let url):
                loading = true
                failure = nil
                Task { @MainActor in
                    defer { loading = false }
                    do { loaded = try await Task.detached { try OwnedImage.read(url) }.value }
                    catch { failure = error.localizedDescription }
                }
            case .failure(let error):
                if (error as NSError).code != NSUserCancelledError { failure = error.localizedDescription }
            }
        }
    }
}
