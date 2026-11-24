import SwiftUI

// This is a *synthetic guest-state* smoke check of compiled native C, not
// original game execution, Steam authentication, or evidence of gameplay.
private func nativePostSteamTimerSmoke() -> Bool {
    var state = mxb_poststeam_timer_guest(
        rip: 0x140133f66,
        rax: 0x1234567887654321,
        rcx: 0xFFFFFFFFFFFFFFFF,
        rdx: 0xABCDEF0000000000,
        rflags: 0x246,
        global_time_ms: 0xBAD00BAD,
        reserved: 0
    )
    let accepted = mxb_poststeam_timer_apply(&state)
    return accepted == 1 &&
        state.rip == 0x140133f76 &&
        state.rax == 0x1234567887654321 &&
        state.rcx == 0xD3B8 &&
        state.rdx == 1 &&
        state.rflags == 0x246 &&
        state.global_time_ms == 0x87654321
}

// Native renderer lab only; the original MX Bikes engine is not running.
@main
struct MXBViewportPrototypeApp: App {
    private let session: NativeSession

    init() {
        let launched = NativeSession()
        session = launched
        // Explicit CI-only runtime marker: a successful simulator launch must
        // actually call the linked generated native module, not merely build.
        if ProcessInfo.processInfo.arguments.contains("--compiled-startup-selftest"),
           let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first {
            let passed = launched.result == 1 && launched.pc == 0x140136710 &&
                         launched.services == 29 && launched.instructions > 655
            try? Data((passed ? "PASS" : "FAIL").utf8).write(
                to: docs.appendingPathComponent("mxb-compiled-startup.txt"), options: .atomic)
        }
        if ProcessInfo.processInfo.arguments.contains("--native-selftest") {
            let passed = mxb_native_probe_smoke() == 1 &&
                         mxb_poststeam_joined_synthetic_smoke() == 1 &&
                         nativePostSteamTimerSmoke()
            let marker = passed ? "PASS: synthetic generated native runtime" :
                                  "FAIL: synthetic generated native runtime"
            if let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first {
                let destination = docs.appendingPathComponent("mxb-native-selftest.txt")
                try? Data((marker + "\n").utf8).write(to: destination, options: .atomic)
            }
        }
    }
    var body: some Scene {
        WindowGroup {
            ZStack(alignment: .bottom) {
                NativeMetalSurface().ignoresSafeArea()
                VStack(alignment: .leading, spacing: 4) {
                    Text("MX Bikes · Native development build").font(.headline)
                    if session.result == 1 {
                        Text("Startup reached " + String(format: "0x%llX", session.pc))
                        Text("\(session.instructions) instructions · \(session.services) host calls")
                    } else if session.result == -1 {
                        Text("Renderer development build")
                    } else {
                        Text("Native startup failed")
                    }
                }
                .foregroundStyle(.white)
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.black.opacity(0.8))
            }
        }
    }
}
