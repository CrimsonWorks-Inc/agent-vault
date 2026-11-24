// swift-tools-version: 6.0
import PackageDescription

// The companion is its own package: it links none of the daemon's crates and
// talks to the vault only through the installed CLI's `--json` output.
let package = Package(
    name: "AgentVaultCompanion",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "agent-vault-companion", targets: ["Companion"]),
    ],
    targets: [
        // Everything that decides what is shown and what is run: pure
        // Foundation, so every rule is covered by the tests.
        .target(
            name: "CompanionCore",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        // The island, the menu bar fallback, dialogs and notifications.
        .executableTarget(
            name: "Companion",
            dependencies: ["CompanionCore"],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .testTarget(
            name: "CompanionCoreTests",
            dependencies: ["CompanionCore"],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
