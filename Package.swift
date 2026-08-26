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
    ],
    swiftLanguageModes: [.v6]
)
