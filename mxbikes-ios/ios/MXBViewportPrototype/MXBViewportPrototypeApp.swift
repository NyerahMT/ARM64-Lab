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
    var body: some Scene {
        WindowGroup {
            ZStack(alignment: .bottom) {
                NativeMetalSurface().ignoresSafeArea()
                VStack(alignment: .leading, spacing: 4) {
                    Text("Native Metal surface").font(.headline)
                    Text("Original MX Bikes engine not connected").font(.caption)
                    Text(mxb_poststeam_joined_synthetic_smoke() == 1
                         ? "Native timer → helper entry: synthetic check passed"
                         : "Native timer → helper entry: synthetic check failed")
                        .font(.caption2)
                    Text(nativePostSteamTimerSmoke()
                         ? "Native post-Steam timer: synthetic state check passed"
                         : "Native post-Steam timer: synthetic state check failed")
                        .font(.caption2)
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
