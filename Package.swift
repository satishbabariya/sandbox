// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "airlock",
    platforms: [.macOS("26.0")],
    products: [
        .library(name: "AirlockKit", targets: ["AirlockKit"]),
        .executable(name: "airlock", targets: ["airlock"]),
    ],
    dependencies: [
        .package(path: "../containerization"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.7.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.10.1"),
    ],
    targets: [
        .target(
            name: "AirlockKit",
            dependencies: [
                .product(name: "Containerization", package: "containerization"),
                .product(name: "ContainerizationOCI", package: "containerization"),
                .product(name: "ContainerizationEXT4", package: "containerization"),
                .product(name: "ContainerizationExtras", package: "containerization"),
                .product(name: "Logging", package: "swift-log"),
            ]
        ),
        .executableTarget(
            name: "airlock",
            dependencies: [
                "AirlockKit",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]
        ),
        .testTarget(
            name: "AirlockKitTests",
            dependencies: ["AirlockKit"]
        ),
    ]
)
