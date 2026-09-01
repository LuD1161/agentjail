import Testing
@testable import AgentjailApprovalApp

struct RegoSyntaxHighlighterTests {
    @Test func classifiesCommentsKeywordsStringsNumbersAndOperatorsWithoutChangingSource() {
        let source = "# guard\npackage agentjail\ndefault allow := false\nmessage := \"value # literal\"\ncount > 12"
        let tokens = RegoSyntaxHighlighter.tokens(in: source)

        #expect(tokens.map(\.text).joined() == source)
        #expect(tokens.contains(RegoSyntaxToken(kind: .comment, text: "# guard")))
        #expect(tokens.contains(RegoSyntaxToken(kind: .keyword, text: "package")))
        #expect(tokens.contains(RegoSyntaxToken(kind: .keyword, text: "default")))
        #expect(tokens.contains(RegoSyntaxToken(kind: .string, text: "\"value # literal\"")))
        #expect(tokens.contains(RegoSyntaxToken(kind: .number, text: "12")))
        #expect(tokens.contains(RegoSyntaxToken(kind: .operatorSymbol, text: ":=")))
        #expect(String(RegoSyntaxHighlighter.highlight(source).characters) == source)
    }

    @Test func policyPresentationUsesDistinctIconsForCommonPolicyDomains() {
        #expect(PolicyPresentationResolver.presentation(for: policy(
            id: "command_policy/allow-git-push", name: "Allow Git Push", file: "command_policy.rego"
        )).systemImage == "arrow.triangle.branch")
        #expect(PolicyPresentationResolver.presentation(for: policy(
            id: "command_policy/confirm-curl-download", name: "Confirm Curl Download", file: "command_policy.rego"
        )).systemImage == "network")
        #expect(PolicyPresentationResolver.presentation(for: policy(
            id: "file_policy/default", name: "Default", file: "file_policy.rego"
        )).systemImage == "folder.fill")
    }

    @Test func highlightsAndCachesALargeSharedModuleWithoutChangingItsSource() async {
        let rule = """
        # policy explanation
        candidate contains {"action": "ask", "reason": "confirm"} if {
            input.tool_name == "Bash"
            input.tool_input.command != ""
        }

        """
        let source = String(repeating: rule, count: 800)
        let cache = RegoHighlightCache(capacity: 2)

        let first = await cache.highlighted(source)
        let cached = await cache.highlighted(source)

        #expect(String(first.characters) == source)
        #expect(cached == first)
    }

    @Test func policyTablePrioritizesDefaultsThenBashThenGitAndFiltersByCategoryAndText() {
        let policies = [
            policy(id: "file_policy/read-home", name: "Read Home", file: "file_policy.rego"),
            policy(id: "command_policy/allow-git-push", name: "Allow Git Push", file: "command_policy.rego"),
            policy(id: "command_policy/no-sudo", name: "No Sudo", file: "command_policy.rego"),
            policy(id: "command_policy/default-allow", name: "Default Allow", file: "command_policy.rego"),
        ]

        #expect(PolicyTableProjection.filtered(policies, category: .all, searchText: "").map(\.id) == [
            "command_policy/default-allow",
            "command_policy/no-sudo",
            "command_policy/allow-git-push",
            "file_policy/read-home",
        ])
        #expect(PolicyTableProjection.filtered(policies, category: .git, searchText: "push").map(\.id) == [
            "command_policy/allow-git-push",
        ])
    }

    private func policy(id: String, name: String, file: String) -> PolicyInventorySnapshot.Policy {
        PolicyInventorySnapshot.Policy(
            id: id,
            name: name,
            description: "",
            source: .core,
            sourceFile: file,
            locked: false,
            matchedCount: 0,
            agentCount: 0,
            sessionCount: 0,
            breakdownLimited: false,
            examples: [],
            evaluations: []
        )
    }
}
