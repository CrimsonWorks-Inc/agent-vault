import Foundation

/// A JSON value as the CLI prints it. Read-only, with just the accessors the
/// companion needs; a missing key and a wrong type both read as `nil`.
public enum JSON: Equatable {
    case object([String: JSON])
    case array([JSON])
    case string(String)
    case number(Double)
    case bool(Bool)
    case null

    public init?(data: Data) {
        guard let any = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
        else { return nil }
        self.init(any: any)
    }

    public init?(text: String) {
        self.init(data: Data(text.utf8))
    }

    init?(any: Any) {
        switch any {
        case let dict as [String: Any]:
            var out: [String: JSON] = [:]
            for (k, v) in dict {
                guard let j = JSON(any: v) else { return nil }
                out[k] = j
            }
            self = .object(out)
        case let list as [Any]:
            var out: [JSON] = []
            for v in list {
                guard let j = JSON(any: v) else { return nil }
                out.append(j)
            }
            self = .array(out)
        case let s as String:
            self = .string(s)
        case let n as NSNumber:
            // JSONSerialization gives booleans as NSNumber too.
            if CFGetTypeID(n) == CFBooleanGetTypeID() {
                self = .bool(n.boolValue)
            } else {
                self = .number(n.doubleValue)
            }
        case is NSNull:
            self = .null
        default:
            return nil
        }
    }

    public subscript(key: String) -> JSON? {
        if case .object(let o) = self { return o[key] }
        return nil
    }

    public var string: String? {
        if case .string(let s) = self { return s }
        return nil
    }

    public var bool: Bool? {
        if case .bool(let b) = self { return b }
        return nil
    }

    public var array: [JSON]? {
        if case .array(let a) = self { return a }
        return nil
    }

    public var isNull: Bool {
        if case .null = self { return true }
        return false
    }
}

extension Optional where Wrapped == JSON {
    /// Present and not `null`.
    var isSet: Bool {
        switch self {
        case .none, .some(.null): return false
        default: return true
        }
    }
}
