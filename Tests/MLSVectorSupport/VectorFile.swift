import Foundation

/// Loads a vendored test-vector JSON file (see `Vectors/README.md` for
/// provenance) and, for the "emit" half of the harness, re-serializes a
/// record set to the same JSON shape for round-trip self-checks and for
/// producing vectors from a profile this repo defines itself.
public enum VectorFile {
    public enum LoadError: Error {
        case resourceNotFound(String)
    }

    public static func load<T: Decodable>(_ name: String, as type: T.Type = T.self) throws -> T {
        guard let url = Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Vectors") else {
            throw LoadError.resourceNotFound(name)
        }
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(T.self, from: data)
    }

    /// Encodes to the same JSON shape a vector file uses, for the "emit"
    /// direction: producing vectors describing a profile this repo defines,
    /// not only consuming ones published elsewhere.
    public static func emit<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(value)
    }
}
