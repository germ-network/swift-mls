// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "swift-mls",
    // macOS 14 / iOS 17, not the lower floor the rest of swift-crypto allows:
    // CryptoKit's own HPKE type (which `import Crypto` resolves to on Apple
    // platforms) is @available(iOS 17.0, macOS 14.0, ...) — stricter than the
    // 10.15/13 annotation on swift-crypto's own HPKE source, which only
    // applies when swift-crypto compiles its own implementation. HPKE
    // underlies EncryptWithLabel, so this floor is not avoidable while every
    // suite delegates to swift-crypto's HPKE. See SwiftCryptoProvider.swift.
    platforms: [.macOS(.v14), .iOS(.v17), .tvOS(.v17), .watchOS(.v10)],
    products: [
        .library(name: "MLSCodec", targets: ["MLSCodec"]),
        .library(name: "MLSCrypto", targets: ["MLSCrypto"]),
        .library(name: "MLSTreeMath", targets: ["MLSTreeMath"]),
        .library(name: "MLSKeySchedule", targets: ["MLSKeySchedule"]),
        .library(name: "MLSFraming", targets: ["MLSFraming"]),
        .library(name: "MLSProfileRFC9420", targets: ["MLSProfileRFC9420"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.0.0")
    ],
    targets: [
        .target(name: "MLSCodec"),
        .testTarget(name: "MLSCodecTests", dependencies: ["MLSCodec"]),

        .target(
            name: "MLSCrypto",
            dependencies: [
                "MLSCodec",
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .target(name: "MLSTreeMath", dependencies: ["MLSCodec"]),
        .target(
            name: "MLSKeySchedule",
            dependencies: ["MLSCodec", "MLSCrypto", "MLSTreeMath"]
        ),
        .target(
            name: "MLSFraming",
            dependencies: ["MLSCodec", "MLSCrypto", "MLSTreeMath"]
        ),
        .target(
            // Does not depend on MLSKeySchedule: the RFC 9420 profile's
            // types and codecs are independent of how its secrets are
            // derived. MLSKeySchedule is linked by the *test* target only,
            // to drive real secrets through Protect.swift's unprotect path
            // (message-protection.json needs the secret tree ratchet).
            name: "MLSProfileRFC9420",
            dependencies: ["MLSCodec", "MLSCrypto", "MLSTreeMath", "MLSFraming"]
        ),
        .target(
            name: "MLSVectorSupport",
            dependencies: [],
            path: "Tests/MLSVectorSupport",
            exclude: ["Vectors"],
            resources: [.copy("Vectors")]
        ),
        .testTarget(
            name: "MLSCryptoTests",
            dependencies: ["MLSCrypto", "MLSVectorSupport"]
        ),
        .testTarget(
            name: "MLSTreeMathTests",
            dependencies: ["MLSTreeMath", "MLSVectorSupport"]
        ),
        .testTarget(
            name: "MLSKeySchedTests",
            dependencies: ["MLSKeySchedule", "MLSCrypto", "MLSVectorSupport"]
        ),
        .testTarget(
            // Deliberately does not link MLSProfileRFC9420. Framing's
            // mechanisms (TBS/TBM assembly, tags, transcript hashes) take
            // and return Data; this target proves they work against
            // hand-assembled bytes with no profile decoder in existence,
            // which is the actual test that MLSFraming doesn't secretly
            // depend on RFC 9420's concrete types.
            name: "MLSFramingTests",
            dependencies: ["MLSFraming", "MLSCrypto", "MLSVectorSupport"]
        ),
        .testTarget(
            name: "MLSProfileRFC9420Tests",
            dependencies: [
                "MLSProfileRFC9420", "MLSFraming", "MLSCrypto", "MLSKeySchedule", "MLSVectorSupport",
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)
