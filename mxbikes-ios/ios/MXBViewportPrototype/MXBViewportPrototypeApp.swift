import SwiftUI

// Native renderer lab only; the original MX Bikes engine is not running.
@main
struct MXBViewportPrototypeApp: App {
    var body: some Scene {
        WindowGroup {
            ZStack(alignment: .bottom) {
                NativeMetalSurface().ignoresSafeArea()
                VStack(alignment: .leading, spacing: 4) {
                    Text("Native Metal surface").font(.headline)
                    Text("Original MX Bikes engine not connected").font(.caption)
                    Text(ProcessInfo.processInfo.arguments.contains("--renderer-probe-only")
                         ? "SYNTHETIC GPU TEST — NOT MX BIKES"
                         : "Awaiting authentic game graphics commands")
                        .font(.caption2)
                }
                .foregroundStyle(.white)
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.black.opacity(0.8))
            }
        }
    }
}
