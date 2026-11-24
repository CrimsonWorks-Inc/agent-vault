import Foundation

// Running the installed agent-vault CLI and reading its `--json` output.

public struct Failure: Error, Equatable, CustomStringConvertible {
    public var message: String
    public init(_ message: String) { self.message = message }
    public var description: String { message }
}

public struct CLI {
    /// Most commands answer at once; this bounds a stuck one.
    public static let timeout: TimeInterval = 20
    /// `cred test --all` calls every key's service in turn.
    public static let slow: TimeInterval = 90

    /// The root-owned CLI the vault's installer puts in place. The companion
    /// never looks the CLI up on PATH: an agent can put a fake `agent-vault`
    /// earlier on PATH, and a companion that ran it would show whatever it chose.
    public static var installPath: String? {
        #if os(macOS)
        return "/var/db/agent-vault/app/bin/agent-vault"
        #elseif os(Linux)
        return "/usr/libexec/agent-vault/app/bin/agent-vault"
        #else
        return nil
        #endif
    }

    public let path: String

    /// Find the install, and refuse it unless the file and its folder belong to
    /// root and nobody else can write to them. Looked up again on every
    /// refresh, so a vault set up while the companion runs is found.
    public static func locate(at path: String? = CLI.installPath) -> Result<CLI, Missing> {
        guard let path else { return .failure(.unsupported) }
        guard FileManager.default.fileExists(atPath: path) else { return .failure(.notInstalled) }
        if let why = rootOwnedProblem(path) { return .failure(.untrusted(why)) }
        if let why = rootOwnedProblem((path as NSString).deletingLastPathComponent) {
            return .failure(.untrusted(why))
        }
        return .success(CLI(path: path))
    }

    /// Why `path` is not a root-owned install, or `nil` when it is.
    public static func rootOwnedProblem(_ path: String) -> String? {
        var st = stat()
        guard stat(path, &st) == 0 else {
            return "cannot inspect \(path): \(String(cString: strerror(errno)))"
        }
        if st.st_uid != 0 || (st.st_mode & 0o022) != 0 {
            return "\(path) is not a root-owned install, so the companion will not run it"
        }
        return nil
    }

    /// Child processes get a fixed, minimal environment. Anything else could
    /// be steering: `AGENT_VAULT_DIR`, for one, points the CLI at a different
    /// control socket, and the companion may have been started from a shell an
    /// agent set up.
    public static func cleanEnvironment(_ from: [String: String] = ProcessInfo.processInfo.environment) -> [String: String] {
        var env: [String: String] = [:]
        for key in ["HOME", "USER", "LOGNAME", "LANG", "TMPDIR"] {
            if let v = from[key] { env[key] = v }
        }
        env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
        return env
    }

    func process(_ args: [String]) -> Process {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args + ["--json"]
        p.environment = CLI.cleanEnvironment()
        p.currentDirectoryURL = URL(fileURLWithPath: "/")
        p.standardInput = FileHandle.nullDevice
        return p
    }

    /// Run one command to completion and return the envelope's `data`.
    /// `input`, when given, is written to the command's stdin and closed: the
    /// companion's proof, and a key's value after it. It is never put in an
    /// argument, where another process could read it.
    public func run(_ args: [String], input: String? = nil, timeout: TimeInterval = CLI.timeout) -> Result<JSON, Failure> {
        let p = process(args)
        let out = Pipe()
        let err = Pipe()
        let stdin = Pipe()
        p.standardOutput = out
        p.standardError = err
        if input != nil { p.standardInput = stdin }
        let exited = DispatchSemaphore(value: 0)
        p.terminationHandler = { _ in exited.signal() }
        do {
            try p.run()
        } catch {
            return .failure(Failure("could not start agent-vault: \(error.localizedDescription)"))
        }
        if let input {
            let writer = stdin.fileHandleForWriting
            try? writer.write(contentsOf: Data(input.utf8))
            try? writer.close()
        }
        let stdout = Drain(out.fileHandleForReading)
        let stderr = Drain(err.fileHandleForReading)
        if exited.wait(timeout: .now() + timeout) == .timedOut {
            p.terminate()
            p.waitUntilExit()
            return .failure(Failure("agent-vault \(args.joined(separator: " ")) timed out"))
        }
        let text = String(decoding: stdout.result(), as: UTF8.self)
        let why = String(decoding: stderr.result(), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        switch parseEnvelope(text) {
        case .success(let data):
            return .success(data)
        case .failure(let e):
            return .failure(why.isEmpty ? e : Failure(firstLine(why)))
        }
    }

    /// `agent-vault watch --json --no-notify`: a long-lived stream of
    /// pending-approval events. The caller reads the returned handle.
    public func watch() throws -> (Process, FileHandle) {
        let p = process(["watch", "--no-notify"])
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        try p.run()
        return (p, out.fileHandleForReading)
    }

    /// Start `agent-vault ui --json --no-open` and wait for its single-use
    /// link. Returns the process (which serves the UI until it idles out or is
    /// stopped) and the link, after checking that nothing else is listening
    /// where the link points.
    public func ui() -> Result<(Process, String), Failure> {
        let p = process(["ui", "--no-open"])
        let out = Pipe()
        let err = Pipe()
        p.standardOutput = out
        p.standardError = err
        do {
            try p.run()
        } catch {
            return .failure(Failure("could not start the vault UI: \(error.localizedDescription)"))
        }
        let stderr = Drain(err.fileHandleForReading)
        let first = DispatchSemaphore(value: 0)
        let box = Box<JSON>()
        let reader = out.fileHandleForReading
        Thread.detachNewThread {
            var lines = LineSplitter(cap: LineSplitter.cap)
            var json = JSONLines()
            var sent = false
            // Keep reading after the link so a full pipe never stalls the server.
            while true {
                let chunk = reader.availableData
                if chunk.isEmpty { break }
                for line in lines.feed(chunk) where !sent {
                    if let v = json.push(line) {
                        box.value = v
                        sent = true
                        first.signal()
                    }
                }
            }
            if !sent { first.signal() }
        }
        func stop(_ why: String) -> Result<(Process, String), Failure> {
            p.terminate()
            p.waitUntilExit()
            return .failure(Failure(why))
        }
        guard first.wait(timeout: .now() + 10) == .success, let v = box.value else {
            let why = p.isRunning ? "" : firstLine(String(decoding: stderr.result(), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))
            return stop(why.isEmpty ? "the vault UI did not start" : why)
        }
        let url = (v["data"]?["url"] ?? v["url"])?.string ?? ""
        guard let checked = checkedUIURL(url) else {
            return stop(envelopeError(v) ?? "the vault UI gave an unexpected link")
        }
        if let why = onlyListener(port: uiPort(checked) ?? 0, ours: p.processIdentifier) {
            return stop(why)
        }
        return .success((p, checked))
    }
}

/// The browser resolves `localhost` to IPv6 as well as IPv4, and the vault's
/// UI server quietly skips IPv6 when that port is taken. So before opening a
/// single-use link, make sure every listener on the port is the UI process the
/// companion just started; anything else could receive the link. Returns why
/// not, or `nil` when it is.
public func onlyListener(port: UInt16, ours: Int32) -> String? {
    guard port != 0 else { return "the vault UI gave an unexpected link" }
    guard let lsof = ["/usr/sbin/lsof", "/usr/bin/lsof"].first(where: FileManager.default.fileExists(atPath:)) else {
        return "cannot check who is listening on the vault UI's port (lsof is missing)"
    }
    let p = Process()
    p.executableURL = URL(fileURLWithPath: lsof)
    p.arguments = ["-nP", "-iTCP:\(port)", "-sTCP:LISTEN", "-Fp"]
    p.environment = CLI.cleanEnvironment()
    p.standardInput = FileHandle.nullDevice
    p.standardError = FileHandle.nullDevice
    let out = Pipe()
    p.standardOutput = out
    do {
        try p.run()
    } catch {
        return "cannot check the vault UI's port: \(error.localizedDescription)"
    }
    let data = out.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    let pids = listenerPids(String(decoding: data, as: UTF8.self))
    if pids.isEmpty { return "the vault UI is not listening" }
    if pids.contains(where: { $0 != ours }) {
        return "another program is listening on the vault UI's port \(port), so the link was not opened. Check what holds it: lsof -nP -iTCP:\(port)"
    }
    return nil
}

/// The process ids in `lsof -Fp` output.
public func listenerPids(_ output: String) -> [Int32] {
    output.split(separator: "\n").compactMap { line in
        line.hasPrefix("p") ? Int32(line.dropFirst()) : nil
    }
}

public func uiPort(_ url: String) -> UInt16? {
    guard url.hasPrefix("http://localhost:") else { return nil }
    let rest = url.dropFirst("http://localhost:".count)
    guard let slash = rest.firstIndex(of: "/") else { return nil }
    return UInt16(rest[..<slash])
}

/// Only a loopback link to the vault's own UI is opened.
public func checkedUIURL(_ url: String) -> String? {
    guard url.hasPrefix("http://localhost:") else { return nil }
    let rest = url.dropFirst("http://localhost:".count)
    guard let slash = rest.firstIndex(of: "/") else { return nil }
    let port = rest[..<slash]
    guard !port.isEmpty, port.allSatisfy({ $0.isASCII && $0.isNumber }) else { return nil }
    let tail = rest[rest.index(after: slash)...]
    guard tail.hasPrefix("?t=") else { return nil }
    let token = tail.dropFirst(3)
    guard !token.isEmpty, token.utf8.allSatisfy({ b in
        (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A)
            || b == UInt8(ascii: "_") || b == UInt8(ascii: "-") || b == UInt8(ascii: ".") || b == UInt8(ascii: "~")
    }) else { return nil }
    return url
}

/// `{"ok":true,"data":…}` → data; anything else → a readable error.
public func parseEnvelope(_ stdout: String) -> Result<JSON, Failure> {
    guard let v = JSON(text: stdout.trimmingCharacters(in: .whitespacesAndNewlines)) else {
        return .failure(Failure("agent-vault gave no readable answer"))
    }
    if v["ok"]?.bool == true {
        return .success(v["data"] ?? .null)
    }
    return .failure(Failure(envelopeError(v) ?? "agent-vault refused"))
}

func envelopeError(_ v: JSON) -> String? {
    guard let e = v["error"] else { return nil }
    guard let msg = e.string ?? e["message"]?.string ?? e["detail"]?.string else { return nil }
    return firstLine(msg)
}

func firstLine(_ s: String) -> String {
    String((s.split(separator: "\n", omittingEmptySubsequences: false).first ?? "").prefix(200))
}

/// Splits a byte stream into lines without their newline. A line longer than
/// `cap` bytes is consumed and given as an empty string: the vault's own JSON
/// lines are far shorter, and nothing should be able to make the companion
/// hold an unbounded line in memory.
public struct LineSplitter {
    public static let cap = 64 * 1024

    let cap: Int
    var line = Data()
    var overflow = false
    var started = false

    public init(cap: Int) { self.cap = cap }

    public mutating func feed(_ chunk: Data) -> [String] {
        var out: [String] = []
        for b in chunk {
            if b == UInt8(ascii: "\n") {
                out.append(take())
                continue
            }
            started = true
            if overflow { continue }
            if line.count + 1 > cap {
                overflow = true
                line = Data()
            } else {
                line.append(b)
            }
        }
        return out
    }

    /// At the end of the stream: the last line, if it had no newline.
    public mutating func finish() -> String? {
        started ? take() : nil
    }

    private mutating func take() -> String {
        let text = overflow ? "" : String(decoding: line, as: UTF8.self)
        line = Data()
        overflow = false
        started = false
        return text
    }
}

/// Gathers lines until they form one JSON value: the CLI prints some
/// envelopes on one line and some pretty-printed over several.
public struct JSONLines {
    var buf = ""

    public init() {}

    public mutating func push(_ line: String) -> JSON? {
        if line.isEmpty && buf.isEmpty { return nil }
        buf += line + "\n"
        if let v = JSON(text: buf) {
            buf = ""
            return v
        }
        if buf.utf8.count > LineSplitter.cap { buf = "" }
        return nil
    }
}

/// The inside of an AppleScript string literal: backslash and double quote
/// are its only special characters.
public func applescriptString(_ text: String) -> String {
    text.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
}

/// The AppleScript that opens Terminal on one fixed command.
public func terminalAppleScript(_ command: String) -> String {
    "tell application \"Terminal\"\nactivate\ndo script \"\(applescriptString(command))\"\nend tell"
}

/// Reads a pipe to its end on its own thread, so a chatty child never blocks
/// on a full pipe while the companion waits for it.
final class Drain {
    private let box = Box<Data>()
    private let done = DispatchSemaphore(value: 0)

    init(_ handle: FileHandle) {
        let (box, done) = (box, done)
        Thread.detachNewThread {
            box.value = handle.readDataToEndOfFile()
            done.signal()
        }
    }

    /// Everything read, waiting briefly for the end of the stream. Empty when
    /// the stream did not end in time.
    func result() -> Data {
        guard done.wait(timeout: .now() + 2) == .success else { return Data() }
        return box.value ?? Data()
    }
}

final class Box<T> {
    private let lock = NSLock()
    private var stored: T?
    var value: T? {
        get { lock.lock(); defer { lock.unlock() }; return stored }
        set { lock.lock(); stored = newValue; lock.unlock() }
    }
}
