import Foundation

/// Keeps the native startup state alive at the next untranslated routine.
final class NativeSession {
    private let state = UnsafeMutablePointer<MXBOwnedStartup>.allocate(capacity: 1)
    let result: Int32

    init() {
        state.initialize(to: MXBOwnedStartup())
        result = mxb_native_launch(state)
    }

    var pc: UInt64 { state.pointee.pc }
    var instructions: UInt32 { state.pointee.instructions }
    var services: UInt32 { state.pointee.services }

    deinit {
        mxb_owned_startup_dispose(state)
        state.deinitialize(count: 1)
        state.deallocate()
    }
}
