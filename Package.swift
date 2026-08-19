// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "swift-mls",
    platforms: [.macOS(.v13), .iOS(.v16), .tvOS(.v16), .watchOS(.v9)],
    products: [
        .library(name: "MLSCodec", targets: ["MLSCodec"])
    ],
    targets: [
        .target(name: "MLSCodec"),
        .testTarget(name: "MLSCodecTests", dependencies: ["MLSCodec"]),
    ]
)
