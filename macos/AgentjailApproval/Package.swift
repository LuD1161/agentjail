// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "AgentjailApproval",
    platforms: [
        .macOS(.v13),
    ],
    products: [
        .library(
            name: "AgentjailApprovalCore",
            targets: ["AgentjailApprovalCore"]
        ),
        .executable(
            name: "AgentjailApproval",
            targets: ["AgentjailApprovalApp"]
        ),
    ],
    targets: [
        .target(name: "AgentjailApprovalCore"),
        .executableTarget(
            name: "AgentjailApprovalApp",
            dependencies: ["AgentjailApprovalCore"],
            resources: [.process("Resources")]
        ),
        .testTarget(
            name: "AgentjailApprovalCoreTests",
            dependencies: ["AgentjailApprovalCore"]
        ),
        .testTarget(
            name: "AgentjailApprovalAppTests",
            dependencies: ["AgentjailApprovalApp", "AgentjailApprovalCore"]
        ),
    ]
)
