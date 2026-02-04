// swift-tools-version: 6.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "EchoForge",
    platforms: [.iOS(.v13), .macOS(.v11)],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "EchoForge",
            targets: ["EchoForge"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/CoderQuinn/ForgeBase.git", from: "0.2.1"),
        .package(url: "https://github.com/CoderQuinn/ForgeLogKit.git", from: "0.2.0"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.0.0"),
        .package(url: "https://github.com/apple/swift-nio-transport-services.git", from: "1.19.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "EchoForge",
            dependencies: [
                .product(name: "ForgeBase", package: "ForgeBase"),
                .product(name: "ForgeLogKit", package: "ForgeLogKit"),
                .product(name: "NIO", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOTransportServices", package: "swift-nio-transport-services"),
            ],
            swiftSettings: [
                .define("FORGELOG_DISABLED", .when(configuration: .release))
            ]
        ),
        .testTarget(
            name: "EchoForgeTests",
            dependencies: [
                "EchoForge",
                .product(name: "ForgeLogKit", package: "ForgeLogKit"),
                .product(name: "ForgeBase", package: "ForgeBase"),
                .product(name: "NIO", package: "swift-nio"),
            ],
            path: "Tests/EchoForgeTests"
        ),
    ]
)
