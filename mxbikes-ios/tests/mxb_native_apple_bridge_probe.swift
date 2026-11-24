import Foundation
import Darwin

// Actual Swift-to-C native module execution on the macOS CI host.
// The input is the same public synthetic fixture as the iOS app.
guard mxb_native_probe_smoke() == 1 else {
    FileHandle.standardError.write(Data("FAIL: Apple Swift/C generated runtime\n".utf8))
    exit(1)
}
print("PASS: Apple Swift/C generated runtime")
