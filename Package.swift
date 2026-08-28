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
        .library(name: "MLSTreeKEM", targets: ["MLSTreeKEM"]),
        .library(name: "MLSProfileRFC9420", targets: ["MLSProfileRFC9420"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.0.0"),
        // Zeroizing storage for held secrets. Floor is iOS 16 / macOS 13,
        // below this package's own, so it imposes nothing on adopters.
        // Interop-harness only — never a dependency of any library product
        // (grpc-swift 2 requires macOS 15+; the executable target below is
        // the sole consumer). Pinned major versions keep the checked-in
        // generated stubs valid.
        .package(url: "https://github.com/grpc/grpc-swift-2.git", from: "2.0.0"),
        .package(url: "https://github.com/grpc/grpc-swift-protobuf.git", from: "2.0.0"),
        .package(url: "https://github.com/grpc/grpc-swift-nio-transport.git", from: "2.0.0"),
        .package(url: "https://github.com/apple/swift-protobuf.git", from: "1.28.0"),
    ],
    targets: [
        .target(name: "MLSCodec"),
        .testTarget(name: "MLSCodecTests", dependencies: ["MLSCodec", "MLSVectorSupport"]),

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
            // Does not depend on MLSKeySchedule, and must not: the key
            // schedule is the anchor every evolution mechanism lands on,
            // and TreeKEM is one such mechanism among several a profile
            // might substitute (SlimMLS's non-tree KEM is exactly this).
            // It produces a commit_secret as plain Data -- MLS.KeySchedule
            // .advance's `commitSecret` parameter -- and consumes nothing
            // from it.
            //
            // Does not depend on MLSProfileRFC9420 either: the ratchet tree
            // stores a leaf *projection* (encryption key, parent hash, and
            // the leaf's encoded bytes), not MLS.RFC9420.LeafNode itself,
            // so MLS.Slim can reuse the tree unchanged. See
            // Sources/MLSTreeKEM/LeafRecord.swift.
            name: "MLSTreeKEM",
            dependencies: ["MLSCodec", "MLSCrypto", "MLSTreeMath"]
        ),
        .target(
            // The wire structures and codecs in this target are
            // independent of how secrets are derived -- that part of the
            // original comment here still holds. `MLS.RFC9420.Group`
            // (phase 5) is the one place the independence stops: a group
            // is the composed protocol, and running the key schedule is
            // what "processing a commit" or "joining via Welcome" means.
            // This project's one-target-per-profile design puts exactly
            // this composition at the profile layer, not a new target, so
            // the dependency belongs here rather than being routed around.
            name: "MLSProfileRFC9420",
            dependencies: [
                "MLSCodec", "MLSCrypto", "MLSTreeMath", "MLSFraming", "MLSTreeKEM",
                "MLSKeySchedule",
            ]
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
            // MLSFraming only for its SenderData/SenderDataAAD wire types
            // and senderDataKeyNonce, to check secret-tree.json's
            // `sender_data` field alongside the rest of the same vector's
            // per-leaf entries rather than fragmenting one vector's
            // coverage across two test targets. The dedicated
            // sender-data-key vector's own test lives in MLSFramingTests.
            name: "MLSKeySchedTests",
            dependencies: ["MLSKeySchedule", "MLSCrypto", "MLSFraming", "MLSVectorSupport"]
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
            // Deliberately does not link MLSProfileRFC9420 or
            // MLSKeySchedule -- same mechanical-isolation argument as
            // MLSFramingTests above. The official tree vectors
            // (tree-validation.json, tree-operations.json, treekem.json)
            // need a ratchet_tree *decoder*, and a LeafNode has no length
            // prefix on the wire so it can't be skipped without parsing --
            // that decoder is profile policy, so those vectors run in
            // MLSProfileRFC9420Tests instead. What runs here is everything
            // provable against synthetic leaf payloads: resolution,
            // filtered direct path, tree-hash input assembly, the
            // path-secret chain, and the structural mutation tests that
            // need no wire format at all.
            name: "MLSTreeKEMTests",
            dependencies: ["MLSTreeKEM", "MLSCrypto", "MLSTreeMath", "MLSVectorSupport"]
        ),
        .testTarget(
            name: "MLSProfileRFC9420Tests",
            dependencies: [
                "MLSProfileRFC9420", "MLSFraming", "MLSCrypto", "MLSKeySchedule", "MLSTreeKEM",
                "MLSVectorSupport",
            ]
        ),
        .executableTarget(
            name: "mls-interop-server",
            dependencies: [
                "MLSProfileRFC9420", "MLSCrypto", "MLSKeySchedule", "MLSTreeKEM",
                "MLSFraming", "MLSCodec", "MLSTreeMath",
                .product(
                    name: "GRPCCore", package: "grpc-swift-2",
                    condition: .when(platforms: [.macOS, .linux])),
                .product(
                    name: "GRPCProtobuf", package: "grpc-swift-protobuf",
                    condition: .when(platforms: [.macOS, .linux])),
                .product(
                    name: "GRPCNIOTransportHTTP2Posix",
                    package: "grpc-swift-nio-transport",
                    condition: .when(platforms: [.macOS, .linux])),
                .product(
                    name: "SwiftProtobuf", package: "swift-protobuf",
                    condition: .when(platforms: [.macOS, .linux])),
            ],
            exclude: ["Generated/README.md", "Generated/.swift-format-ignore"]
        ),
    ],
    swiftLanguageModes: [.v6]
)
