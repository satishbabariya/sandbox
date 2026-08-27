// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "sandbox",
    platforms: [.macOS("26.0")],
    products: [
        .library(name: "SandboxKit", targets: ["SandboxKit"]),
        .executable(name: "sandbox", targets: ["sandbox"]),
    ],
    dependencies: [
        // .package(path: "../containerization"),
        .package(url: "https://github.com/apple/containerization.git", from: "0.41.0"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.7.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.10.1"),
        .package(url: "https://github.com/apple/swift-system.git", from: "1.6.4"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        .package(url: "https://github.com/jpsim/Yams.git", from: "5.0.0"),
    ],
    targets: [
        .target(
            name: "SandboxKit",
            dependencies: [
                .product(name: "Containerization", package: "containerization"),
                .product(name: "ContainerizationOCI", package: "containerization"),
                .product(name: "ContainerizationEXT4", package: "containerization"),
                .product(name: "ContainerizationExtras", package: "containerization"),
                .product(name: "ContainerizationOS", package: "containerization"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "SystemPackage", package: "swift-system"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Yams", package: "Yams"),
            ]
        ),
        .executableTarget(
            name: "sandbox",
            dependencies: [
                "SandboxKit",
                .product(name: "Containerization", package: "containerization"),
                .product(name: "ContainerizationOS", package: "containerization"),
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]
        ),
        .testTarget(
            name: "SandboxKitTests",
            dependencies: ["SandboxKit"]
        ),
    ]
)
