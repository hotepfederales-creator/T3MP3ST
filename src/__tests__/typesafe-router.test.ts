import { describe, it, expect } from "vitest";
import type { LLMBackbone } from "../llm/index.js";
import type { MissionFamily } from "../resources/index.js";
import {
  OpGeneral,
  YES_THRESHOLD,
  NO_THRESHOLD,
  DEFAULT_TYPESAFE_API_URL,
  DEFAULT_TYPESAFE_MODEL,
  ALL_MISSION_FAMILIES,
  MISSION_ROUTER_QUESTIONS,
  TypeSafeRouterError,
  HttpTypeSafeJudgmentProvider,
  createLiveTypeSafeJudgmentProvider,
  resolveTypeSafeApiKey,
  resolveTypeSafeApiKeyInfo,
  validateTypeSafeEndpointUrl,
  buildMissionRoutingState,
  buildTypeSafeMissionRequestPayload,
  parseTypeSafeMissionResponse,
  estimateMissionJudgmentsOffline,
  combineMissionRouteFromJudgments,
  classifyProbabilityBand,
  evaluateMissionRouteOffline,
  type MissionJudgmentVector,
  type MissionJudgmentProvider,
  type PrimaryTargetModality,
} from "../general/index.js";

function makeSyntheticJudgments(overrides: {
  pHasConcreteSecurityScope?: number;
  primaryModality?: PrimaryTargetModality;
  families?: Partial<Record<MissionFamily, number>>;
}): MissionJudgmentVector {
  const familyProbabilities = {} as Record<MissionFamily, number>;
  for (const family of ALL_MISSION_FAMILIES) {
    familyProbabilities[family] = overrides.families?.[family] ?? 0.05;
  }
  return {
    pHasConcreteSecurityScope: overrides.pHasConcreteSecurityScope ?? 0.92,
    primaryModality: overrides.primaryModality ?? "web_endpoint",
    familyProbabilities,
    providerSource: "custom",
  };
}

describe("TypeSafe System One Mission Router — Registry & Payload Craft", () => {
  it("centralizes thresholds (0.7 / 0.3), all 11 MissionFamily Nouls, modality Choice, and companion null-case Noul", () => {
    expect(YES_THRESHOLD).toBe(0.7);
    expect(NO_THRESHOLD).toBe(0.3);
    expect(MISSION_ROUTER_QUESTIONS.thresholds).toEqual({
      yes: 0.7,
      no: 0.3,
    });

    expect(ALL_MISSION_FAMILIES).toHaveLength(11);
    const seenIds = new Set<string>([
      MISSION_ROUTER_QUESTIONS.nullScopeNoul.id,
    ]);

    for (const family of ALL_MISSION_FAMILIES) {
      const spec = MISSION_ROUTER_QUESTIONS.familyNouls[family];
      expect(spec).toBeDefined();
      expect(spec.kind).toBe("noul");
      expect(spec.question.endsWith("?")).toBe(true);
      expect(spec.criteria.yes.length).toBeGreaterThan(25);
      expect(spec.criteria.no.length).toBeGreaterThan(25);
      // Concrete false criteria: never a bare "not ..." negation
      expect(spec.criteria.no.toLowerCase().startsWith("not ")).toBe(false);
      expect(seenIds.has(spec.id)).toBe(false);
      seenIds.add(spec.id);
    }

    // Companion null-case Noul replaces any "none_of_the_above" option in Choice
    const choiceOptions = Object.keys(
      MISSION_ROUTER_QUESTIONS.modalityChoice.options,
    );
    expect(choiceOptions).not.toContain("none_of_the_above");
    expect(choiceOptions).not.toContain("none");
    expect(choiceOptions).not.toContain("other");
    expect(MISSION_ROUTER_QUESTIONS.modalityChoice.nullCompanionNoulId).toBe(
      "has_concrete_security_scope",
    );
  });

  it("serializes structured named-field state and all atomic questions into an inspectable Jev payload", () => {
    const state = buildMissionRoutingState({
      directive: {
        objective: "Audit src/auth/jwt.ts for CWE-347 signature bypass",
        constraints: "Read-only local source audit",
      },
      targets: [{ address: "src/auth/jwt.ts", expectedType: "source" }],
      sourceRoot: "/workspace/service",
    });

    expect(state.sourceRootConfigured).toBe(true);
    expect(state.targets[0]?.inferredKind).toBe("source");

    const payload = buildTypeSafeMissionRequestPayload(state);
    expect(payload.model).toBe(DEFAULT_TYPESAFE_MODEL);
    expect(payload.model).toBe("jev-latest");
    expect(payload.state).toEqual(state);
    // 11 family Nouls + 1 null-case Noul + 1 modality Choice = 13 atomic questions
    expect(Object.keys(payload.questions)).toHaveLength(13);
    expect(payload.questions.has_concrete_security_scope).toMatchObject({
      type: "noul",
      instructions: MISSION_ROUTER_QUESTIONS.nullScopeNoul.question,
      criteria: {
        true: MISSION_ROUTER_QUESTIONS.nullScopeNoul.criteria.yes,
        false: MISSION_ROUTER_QUESTIONS.nullScopeNoul.criteria.no,
      },
    });
    expect(payload.questions.primary_target_modality).toMatchObject({
      type: "choice",
      instructions: MISSION_ROUTER_QUESTIONS.modalityChoice.question,
      criteria: MISSION_ROUTER_QUESTIONS.modalityChoice.options,
    });
  });
});

describe("TypeSafe System One Mission Router — Layer 2 Deterministic Truth Table", () => {
  it("classifies exact threshold boundaries and rejects out-of-range probabilities", () => {
    expect(classifyProbabilityBand(0.7)).toBe("CONFIDENT_YES");
    expect(classifyProbabilityBand(1.0)).toBe("CONFIDENT_YES");
    expect(classifyProbabilityBand(0.3)).toBe("CONFIDENT_NO");
    expect(classifyProbabilityBand(0.0)).toBe("CONFIDENT_NO");
    expect(classifyProbabilityBand(0.3001)).toBe("UNCERTAIN_BAND");
    expect(classifyProbabilityBand(0.5)).toBe("UNCERTAIN_BAND");
    expect(classifyProbabilityBand(0.6999)).toBe("UNCERTAIN_BAND");

    expect(() => classifyProbabilityBand(-0.01)).toThrow(TypeSafeRouterError);
    expect(() => classifyProbabilityBand(1.05)).toThrow(TypeSafeRouterError);
    expect(() => classifyProbabilityBand(Number.NaN)).toThrow(
      TypeSafeRouterError,
    );
  });

  it("routes companion null-case Noul (p_has_concrete_security_scope <= 0.3, all families <= 0.3) to fallback_null_scope", () => {
    const decision = combineMissionRouteFromJudgments(
      makeSyntheticJudgments({
        pHasConcreteSecurityScope: 0.12,
        primaryModality: "source_tree",
        families: { web_api: 0.08, code_audit: 0.19 },
      }),
    );

    expect(decision.truthTableRow).toBe("null_scope_fallback");
    expect(decision.routeConfidence).toBe("fallback_null_scope");
    expect(decision.primaryFamily).toBe("web_api");
    expect(decision.selectedFamilies).toEqual(["web_api"]);
    expect(decision.uncertainFamilies).toEqual([]);
    expect(decision.requiresScopeClarification).toBe(true);
  });

  it("routes a single confident family (>= 0.7) cleanly to single_lane", () => {
    const decision = combineMissionRouteFromJudgments(
      makeSyntheticJudgments({
        pHasConcreteSecurityScope: 0.94,
        primaryModality: "blockchain_contract",
        families: { smart_contract: 0.88, crypto_secrets: 0.22 },
      }),
    );

    expect(decision.truthTableRow).toBe("confident_single_family");
    expect(decision.routeConfidence).toBe("confident_primary");
    expect(decision.fanOutStrategy).toBe("single_lane");
    expect(decision.primaryFamily).toBe("smart_contract");
    expect(decision.selectedFamilies).toEqual(["smart_contract"]);
    expect(decision.uncertainFamilies).toEqual([]);
  });

  it("preserves (0.3, 0.7) uncertain families as secondary lanes alongside a confident primary", () => {
    const decision = combineMissionRouteFromJudgments(
      makeSyntheticJudgments({
        pHasConcreteSecurityScope: 0.91,
        primaryModality: "web_endpoint",
        families: {
          web_api: 0.86,
          crypto_secrets: 0.58,
          cloud_infra: 0.44,
          code_audit: 0.15,
        },
      }),
    );

    expect(decision.truthTableRow).toBe("confident_with_uncertain_secondary");
    expect(decision.routeConfidence).toBe("confident_with_uncertain_secondary");
    expect(decision.fanOutStrategy).toBe("primary_plus_uncertain_secondary");
    expect(decision.primaryFamily).toBe("web_api");
    expect(decision.confidentFamilies).toEqual(["web_api"]);
    expect(decision.uncertainFamilies).toEqual([
      "crypto_secrets",
      "cloud_infra",
    ]);
    expect(decision.selectedFamilies).toEqual([
      "web_api",
      "crypto_secrets",
      "cloud_infra",
    ]);
  });

  it("handles multi-family confident (>= 0.7) routing and uses modality Choice to break near-ties", () => {
    const decision = combineMissionRouteFromJudgments(
      makeSyntheticJudgments({
        pHasConcreteSecurityScope: 0.96,
        primaryModality: "repository_pipeline",
        families: {
          code_audit: 0.84,
          code_supply_chain: 0.82,
          crypto_secrets: 0.48,
        },
      }),
    );

    expect(decision.truthTableRow).toBe("confident_multi_family");
    expect(decision.routeConfidence).toBe("confident_multi_lane");
    // Modality `repository_pipeline` breaks the 0.02 near-tie in favor of code_supply_chain
    expect(decision.primaryFamily).toBe("code_supply_chain");
    expect(decision.selectedFamilies).toEqual([
      "code_supply_chain",
      "code_audit",
    ]);
    expect(decision.uncertainFamilies).toEqual(["crypto_secrets"]);
  });

  it("fans out explicitly when all leading candidates sit inside the (0.3, 0.7) uncertain band", () => {
    const decision = combineMissionRouteFromJudgments(
      makeSyntheticJudgments({
        pHasConcreteSecurityScope: 0.78,
        primaryModality: "cloud_control_plane",
        families: {
          web_api: 0.56,
          cloud_infra: 0.51,
          code_supply_chain: 0.39,
          reverse_binary: 0.08,
        },
      }),
    );

    expect(decision.truthTableRow).toBe("uncertain_band_fanout");
    expect(decision.routeConfidence).toBe("uncertain_fanout");
    expect(decision.fanOutStrategy).toBe("uncertain_multi_lane_fanout");
    // Modality `cloud_control_plane` is within 0.10 of top uncertain candidate and leads fan-out
    expect(decision.primaryFamily).toBe("cloud_infra");
    expect(decision.uncertainFamilies).toEqual([
      "web_api",
      "cloud_infra",
      "code_supply_chain",
    ]);
    expect(decision.selectedFamilies).toEqual([
      "cloud_infra",
      "web_api",
      "code_supply_chain",
    ]);
  });

  it("uses modality fallback when scope Noul > 0.3 but all specific family Nouls <= 0.3", () => {
    const decision = combineMissionRouteFromJudgments(
      makeSyntheticJudgments({
        pHasConcreteSecurityScope: 0.81,
        primaryModality: "compiled_artifact",
        families: { reverse_binary: 0.28, web_api: 0.12 },
      }),
    );

    expect(decision.truthTableRow).toBe("modality_tiebreak_fallback");
    expect(decision.routeConfidence).toBe("modality_tiebreak_fallback");
    expect(decision.primaryFamily).toBe("reverse_binary");
    expect(decision.selectedFamilies).toEqual(["reverse_binary"]);
    expect(decision.requiresScopeClarification).toBe(true);
  });
});

describe("TypeSafe System One Mission Router — Layer 1 Offline Estimator & Disambiguation", () => {
  it("routes clear representative directives across all 11 MissionFamily domains into CONFIDENT_YES", () => {
    const cases: Array<{
      expected: MissionFamily;
      objective: string;
      target?: { address: string; expectedType: string };
      sourceRoot?: string;
    }> = [
      {
        expected: "web_api",
        objective:
          "Authorized OWASP web/API assessment for SSRF and IDOR on staging REST API",
        target: {
          address: "https://staging-api.example.internal/v1",
          expectedType: "api",
        },
      },
      {
        expected: "ai_red_team",
        objective:
          "Probe indirect prompt injection, jailbreak guardrails, and RAG context poisoning in the customer LLM chatbot",
        target: { address: "support-llm-gateway", expectedType: "llm" },
      },
      {
        expected: "cloud_infra",
        objective:
          "Audit AWS IAM role escalation paths, S3 bucket policies, and Kubernetes RBAC in Terraform",
        target: {
          address: "arn:aws:iam::123456789012:role/app",
          expectedType: "cloud",
        },
      },
      {
        expected: "smart_contract",
        objective:
          "Run Foundry and Slither audit for reentrancy and flash loan manipulation in Solidity ERC-20 vault",
        target: { address: "contracts/Vault.sol", expectedType: "contract" },
      },
      {
        expected: "code_audit",
        objective:
          "Perform white-box static source-code taint analysis for CWE-89 and line-pinned sink verification",
        target: { address: "src/db/query.ts", expectedType: "source" },
        sourceRoot: "/repo/app",
      },
      {
        expected: "code_supply_chain",
        objective:
          "Harden GitHub Actions CI/CD workflow permissions, npm lockfile dependency confusion, and SLSA provenance",
        target: {
          address: "https://github.com/acme/platform",
          expectedType: "repo",
        },
      },
      {
        expected: "crypto_secrets",
        objective:
          "Analyze JWT RS256/HS256 signature confusion, ECDSA nonce reuse, and hardcoded private keys",
      },
      {
        expected: "reverse_binary",
        objective:
          "Reverse engineer router firmware ELF binary with Ghidra to verify stack buffer overflow and ROP chain",
        target: { address: "httpd.elf", expectedType: "binary" },
      },
      {
        expected: "agent_warfare",
        objective:
          "Test multi-agent delegation role confusion, MCP tool-output injection, and shared agent memory poisoning across subagent handoffs",
        target: { address: "swarm-orchestrator", expectedType: "agent" },
      },
      {
        expected: "social_osint",
        objective:
          "Conduct public-source OSINT footprint attribution and design an authorized spear-phishing simulation",
      },
      {
        expected: "reporting_remediation",
        objective:
          "Draft executive risk briefing, prioritized remediation roadmap, and fix-verification acceptance criteria",
      },
    ];

    for (const testCase of cases) {
      const decision = evaluateMissionRouteOffline({
        directive: { objective: testCase.objective },
        targets: testCase.target ? [testCase.target] : [],
        sourceRoot: testCase.sourceRoot ?? null,
      });

      expect(
        decision.judgments.familyProbabilities[testCase.expected],
        `Expected ${testCase.expected} >= ${YES_THRESHOLD} for: ${testCase.objective}`,
      ).toBeGreaterThanOrEqual(YES_THRESHOLD);
      expect(decision.confidentFamilies).toContain(testCase.expected);
      expect(decision.primaryFamily).toBe(testCase.expected);
    }
  });

  it("disambiguates 'prompt' in Windows command prompt vs LLM prompt injection", () => {
    const cliPromptState = buildMissionRoutingState({
      directive: {
        objective:
          "Perform white-box source code audit of Windows command prompt cmd.exe argument quoting for CWE-78",
      },
      targets: [{ address: "src/spawn.ts", expectedType: "source" }],
      sourceRoot: "/workspace/cli",
    });
    const cliJudgments = estimateMissionJudgmentsOffline(cliPromptState);
    expect(cliJudgments.familyProbabilities.ai_red_team).toBeLessThanOrEqual(
      NO_THRESHOLD,
    );
    expect(cliJudgments.familyProbabilities.code_audit).toBeGreaterThanOrEqual(
      YES_THRESHOLD,
    );

    const llmPromptState = buildMissionRoutingState({
      directive: {
        objective:
          "Test indirect prompt injection and system prompt leakage in the RAG LLM assistant",
      },
    });
    const llmJudgments = estimateMissionJudgmentsOffline(llmPromptState);
    expect(llmJudgments.familyProbabilities.ai_red_team).toBeGreaterThanOrEqual(
      YES_THRESHOLD,
    );
  });

  it("disambiguates 'token' across lexer tokens, JWT bearer tokens, and ERC-20 smart contract tokens", () => {
    const lexerDecision = evaluateMissionRouteOffline({
      directive: {
        objective:
          "White-box code audit of lexer token and AST token parser bounds in parser.c for CWE-125",
      },
      targets: [{ address: "src/parser.c", expectedType: "source" }],
      sourceRoot: "/workspace/compiler",
    });
    expect(
      lexerDecision.judgments.familyProbabilities.smart_contract,
    ).toBeLessThanOrEqual(NO_THRESHOLD);
    expect(
      lexerDecision.judgments.familyProbabilities.crypto_secrets,
    ).toBeLessThanOrEqual(NO_THRESHOLD);
    expect(lexerDecision.primaryFamily).toBe("code_audit");

    const jwtDecision = evaluateMissionRouteOffline({
      directive: {
        objective:
          "Verify JWT bearer token HMAC signing secret rotation and JWK verification",
      },
    });
    expect(
      jwtDecision.judgments.familyProbabilities.smart_contract,
    ).toBeLessThanOrEqual(NO_THRESHOLD);
    expect(
      jwtDecision.judgments.familyProbabilities.crypto_secrets,
    ).toBeGreaterThanOrEqual(YES_THRESHOLD);

    const erc20Decision = evaluateMissionRouteOffline({
      directive: {
        objective:
          "Audit Solidity ERC-20 governance token and DeFi liquidity pool contract for flash loan exploits",
      },
      targets: [
        {
          address: "0x1111111111111111111111111111111111111111",
          expectedType: "contract",
        },
      ],
    });
    expect(
      erc20Decision.judgments.familyProbabilities.smart_contract,
    ).toBeGreaterThanOrEqual(YES_THRESHOLD);
    expect(erc20Decision.primaryFamily).toBe("smart_contract");
  });

  it("disambiguates 'model' in SPICE diode / ORM data models vs ML foundation models", () => {
    const spiceDecision = evaluateMissionRouteOffline({
      directive: {
        objective:
          "Audit C++ parser handling of SPICE diode model .model cards in netlist_loader.cpp for CWE-120",
      },
      targets: [{ address: "src/netlist_loader.cpp", expectedType: "source" }],
      sourceRoot: "/workspace/eda",
    });
    expect(
      spiceDecision.judgments.familyProbabilities.ai_red_team,
    ).toBeLessThanOrEqual(NO_THRESHOLD);
    expect(spiceDecision.primaryFamily).toBe("code_audit");

    const ormDecision = evaluateMissionRouteOffline({
      directive: {
        objective:
          "Check REST API endpoint authorization on ORM data model updates at https://app.example.com/api",
      },
      targets: [
        { address: "https://app.example.com/api", expectedType: "api" },
      ],
    });
    expect(
      ormDecision.judgments.familyProbabilities.ai_red_team,
    ).toBeLessThanOrEqual(NO_THRESHOLD);
    expect(ormDecision.primaryFamily).toBe("web_api");
  });

  it("disambiguates 'memory' and 'agent' in heap memory / User-Agent vs agent memory poisoning", () => {
    const binaryDecision = evaluateMissionRouteOffline({
      directive: {
        objective:
          "Reverse engineer daemon.elf to trace heap memory usage, HTTP User-Agent header parsing, and buffer overflow",
      },
      targets: [{ address: "daemon.elf", expectedType: "binary" }],
    });
    expect(
      binaryDecision.judgments.familyProbabilities.ai_red_team,
    ).toBeLessThanOrEqual(NO_THRESHOLD);
    expect(
      binaryDecision.judgments.familyProbabilities.agent_warfare,
    ).toBeLessThanOrEqual(NO_THRESHOLD);
    expect(binaryDecision.primaryFamily).toBe("reverse_binary");

    const agentPoisonDecision = evaluateMissionRouteOffline({
      directive: {
        objective:
          "Assess multi-agent delegation and episodic agent memory poisoning across subagent handoffs",
      },
    });
    expect(
      agentPoisonDecision.judgments.familyProbabilities.agent_warfare,
    ).toBeGreaterThanOrEqual(YES_THRESHOLD);
  });

  it("produces fallback_null_scope on vague unscoped directives with no targets", () => {
    const vagueDecision = evaluateMissionRouteOffline({
      directive: { objective: "Find weird machines wherever they may be" },
      targets: [],
    });
    expect(
      vagueDecision.judgments.pHasConcreteSecurityScope,
    ).toBeLessThanOrEqual(NO_THRESHOLD);
    expect(vagueDecision.routeConfidence).toBe("fallback_null_scope");
    expect(vagueDecision.primaryFamily).toBe("web_api");
    expect(vagueDecision.selectedFamilies).toEqual(["web_api"]);
  });
});

describe("TypeSafe System One Mission Router — HTTPS Validation & Error Propagation", () => {
  it("enforces strict https:// scheme without embedded credentials on endpoint URLs", () => {
    const valid = validateTypeSafeEndpointUrl("https://api.typesafe.ai/v1/ask");
    expect(valid.protocol).toBe("https:");
    expect(valid.hostname).toBe("api.typesafe.ai");

    const invalidUrls = [
      "",
      "http://api.typesafe.ai/v1/ask",
      "file:///etc/passwd",
      "ftp://api.typesafe.ai/v1/ask",
      "javascript:alert(1)",
      "https://user:secret@api.typesafe.ai/v1/ask",
      "not-a-url",
    ];

    for (const badUrl of invalidUrls) {
      expect(
        () => validateTypeSafeEndpointUrl(badUrl),
        `Expected ${badUrl} to be rejected`,
      ).toThrowError(TypeSafeRouterError);
    }
  });

  it("resolves TypeSafe API keys in strict priority order (explicit -> TYPESAFE_API_KEY -> JEV_TYPESAFE_API_KEY -> JEV_HOTEP_API_KEY)", () => {
    const fullEnv = {
      TYPESAFE_API_KEY: "key_primary",
      JEV_TYPESAFE_API_KEY: "key_jev",
      JEV_HOTEP_API_KEY: "key_hotep",
    } as unknown as NodeJS.ProcessEnv;

    expect(resolveTypeSafeApiKeyInfo("  key_explicit  ", fullEnv)).toEqual({
      apiKey: "key_explicit",
      source: "explicit",
    });
    expect(resolveTypeSafeApiKeyInfo(undefined, fullEnv)).toEqual({
      apiKey: "key_primary",
      source: "TYPESAFE_API_KEY",
    });
    expect(
      resolveTypeSafeApiKeyInfo(undefined, {
        TYPESAFE_API_KEY: "   ",
        JEV_TYPESAFE_API_KEY: "key_jev",
        JEV_HOTEP_API_KEY: "key_hotep",
      } as unknown as NodeJS.ProcessEnv),
    ).toEqual({
      apiKey: "key_jev",
      source: "JEV_TYPESAFE_API_KEY",
    });
    expect(
      resolveTypeSafeApiKeyInfo(undefined, {
        JEV_HOTEP_API_KEY: "key_hotep",
      } as unknown as NodeJS.ProcessEnv),
    ).toEqual({
      apiKey: "key_hotep",
      source: "JEV_HOTEP_API_KEY",
    });
    expect(
      resolveTypeSafeApiKey(undefined, {} as unknown as NodeJS.ProcessEnv),
    ).toBeNull();
    expect(
      createLiveTypeSafeJudgmentProvider({
        env: {} as unknown as NodeJS.ProcessEnv,
      }),
    ).toBeNull();
  });

  it("parses real TypeSafe v1 /v1/systemone Jev responses (noul + choice + usage) and mocked formats without external network calls", async () => {
    let capturedAuthHeader = "";
    let capturedModel = "";
    let capturedUrl = "";

    const answersPayload: Record<string, unknown> = {
      has_concrete_security_scope: { type: "noul", noul: 0.95 },
      primary_target_modality: {
        type: "choice",
        choice: "cloud_control_plane",
        confidence: 0.92,
      },
    };
    for (const fam of ALL_MISSION_FAMILIES) {
      const id = MISSION_ROUTER_QUESTIONS.familyNouls[fam].id;
      answersPayload[id] = {
        type: "noul",
        noul: fam === "cloud_infra" ? 0.91 : 0.07,
      };
    }

    const provider = createLiveTypeSafeJudgmentProvider({
      env: {
        JEV_TYPESAFE_API_KEY: "ts_test_mock_key",
      } as unknown as NodeJS.ProcessEnv,
      transport: async (req) => {
        capturedUrl = req.url;
        capturedAuthHeader = req.headers.Authorization ?? "";
        const parsedReq = JSON.parse(req.body) as { model: string };
        capturedModel = parsedReq.model;
        return {
          status: 200,
          bodyText: JSON.stringify({
            model: "jev-1.14.0",
            answers: answersPayload,
            usage: { input_tokens: 412, output_tokens: 68 },
          }),
        };
      },
    });

    expect(provider).not.toBeNull();
    if (!provider) {
      throw new Error("Expected live provider to be created");
    }
    expect(provider.getApiKeySource()).toBe("JEV_TYPESAFE_API_KEY");
    expect(provider.getEndpointUrl()).toBe(DEFAULT_TYPESAFE_API_URL);

    const state = buildMissionRoutingState({
      directive: { objective: "Audit EKS IAM roles" },
    });
    const judgments = await provider.evaluate(state);
    const decision = combineMissionRouteFromJudgments(judgments);

    expect(capturedUrl).toBe("https://api.typesafe.ai/v1/systemone");
    expect(capturedAuthHeader).toBe("Bearer ts_test_mock_key");
    expect(capturedModel).toBe("jev-latest");
    expect(judgments.resolvedModel).toBe("jev-1.14.0");
    expect(judgments.modalityConfidence).toBe(0.92);
    expect(judgments.usage).toEqual({ inputTokens: 412, outputTokens: 68 });
    expect(typeof judgments.latencyMs).toBe("number");
    expect(decision.primaryFamily).toBe("cloud_infra");
    expect(decision.routeConfidence).toBe("confident_primary");
  });

  it("surfaces transport, HTTP status, JSON, and schema errors as TypeSafeRouterError instead of 0.0/false", async () => {
    const sampleState = buildMissionRoutingState({
      directive: { objective: "Audit https://example.com" },
      targets: [{ address: "https://example.com", expectedType: "api" }],
    });

    const networkFailProvider = new HttpTypeSafeJudgmentProvider({
      endpointUrl: "https://api.typesafe.ai/v1/jev",
      apiKey: "ts_key",
      transport: async () => {
        throw new Error("ECONNRESET simulated offline failure");
      },
    });
    await expect(
      networkFailProvider.evaluate(sampleState),
    ).rejects.toMatchObject({
      name: "TypeSafeRouterError",
      code: "TRANSPORT_ERROR",
    });

    const http503Provider = new HttpTypeSafeJudgmentProvider({
      endpointUrl: "https://api.typesafe.ai/v1/jev",
      apiKey: "ts_key",
      transport: async () => ({ status: 503, bodyText: "Service Unavailable" }),
    });
    await expect(http503Provider.evaluate(sampleState)).rejects.toMatchObject({
      name: "TypeSafeRouterError",
      code: "HTTP_STATUS_ERROR",
      statusCode: 503,
    });

    const badJsonProvider = new HttpTypeSafeJudgmentProvider({
      endpointUrl: "https://api.typesafe.ai/v1/jev",
      apiKey: "ts_key",
      transport: async () => ({ status: 200, bodyText: "{truncated" }),
    });
    await expect(badJsonProvider.evaluate(sampleState)).rejects.toMatchObject({
      name: "TypeSafeRouterError",
      code: "MALFORMED_RESPONSE",
    });

    // Missing questions or out-of-range probability must throw SCHEMA_VALIDATION_ERROR
    expect(() =>
      parseTypeSafeMissionResponse({
        has_concrete_security_scope: 0.9,
        primary_target_modality: "web_endpoint",
        // Missing the 11 family Nouls!
      }),
    ).toThrowError(TypeSafeRouterError);

    expect(() =>
      parseTypeSafeMissionResponse({
        has_concrete_security_scope: 1.4,
        primary_target_modality: "web_endpoint",
      }),
    ).toThrowError(TypeSafeRouterError);
  });
});

describe("OpGeneral Integration with TypeSafe Calibrated Router", () => {
  it("eliminates false-friend family pollution on sparse LLM plans and exposes getLastRoutingDecision()", async () => {
    const sparsePayload = {
      codename: "CLEAN LEXER",
      summary:
        "White-box CWE-125 audit of SPICE diode model and lexer token parser.",
      targets: [
        {
          address: "src/spice_lexer.c",
          expectedType: "source",
          priority: 1,
          rationale: "Local C lexer",
        },
      ],
      objectives: [
        {
          description:
            "Verify bounds on command prompt and lexer token buffers",
          priority: 1,
          successCriteria: "Line-pinned proof",
          phase: "reconnaissance",
        },
      ],
      operators: [
        {
          archetype: "analyst",
          count: 1,
          deployPhase: "reconnaissance",
          briefing: "Audit C parser",
        },
      ],
      roe: {
        scope: ["src/spice_lexer.c"],
        exclusions: [],
        maxDetections: 1,
        destructiveAllowed: false,
        requireApproval: [],
      },
      complexity: "low",
      rationale: "Focused white-box source review.",
    };

    const llm = {
      prompt: async () =>
        `\`\`\`json\n${JSON.stringify(sparsePayload)}\n\`\`\``,
    } as unknown as LLMBackbone;

    const general = new OpGeneral(llm, { sourceRoot: "/workspace/eda" });
    const plan = await general.planOperation({
      objective:
        "Perform white-box source code audit of command prompt flags, SPICE diode model cards, and lexer token parsing in src/spice_lexer.c for CWE-125",
    });

    const decision = general.getLastRoutingDecision();
    expect(decision).not.toBeNull();
    expect(plan.missionFamily).toBe("code_audit");
    // Old regex router would have polluted huntLanes with ai_red_team ("prompt", "model") and smart_contract ("token")!
    const laneFamilies = plan.huntLanes.map((l) => l.family);
    expect(laneFamilies).toContain("code_audit");
    expect(laneFamilies).not.toContain("ai_red_team");
    expect(laneFamilies).not.toContain("smart_contract");
  });

  it("supports async MissionJudgmentProvider hook in planOperation and propagates TypeSafeRouterError", async () => {
    const llm = {
      prompt: async () =>
        `\`\`\`json\n${JSON.stringify({
          codename: "ASYNC JEV",
          summary: "Cloud cluster assessment",
          targets: [
            {
              address: "eks-prod",
              expectedType: "cloud",
              priority: 1,
              rationale: "Cluster",
            },
          ],
        })}\n\`\`\``,
    } as unknown as LLMBackbone;

    const mockProvider: MissionJudgmentProvider = {
      evaluate: async () =>
        makeSyntheticJudgments({
          pHasConcreteSecurityScope: 0.95,
          primaryModality: "cloud_control_plane",
          families: { cloud_infra: 0.93, code_supply_chain: 0.52 },
        }),
    };

    const general = new OpGeneral(llm, { judgmentProvider: mockProvider });
    const plan = await general.planOperation({
      objective: "Assess EKS cluster and deployment pipeline",
    });

    expect(plan.missionFamily).toBe("cloud_infra");
    expect(plan.huntLanes.map((l) => l.family)).toEqual([
      "cloud_infra",
      "code_supply_chain",
    ]);
    expect(general.getLastRoutingDecision()?.uncertainFamilies).toEqual([
      "code_supply_chain",
    ]);

    // Verify provider failure propagates explicitly rather than silently falling back:
    const failingProvider: MissionJudgmentProvider = {
      evaluate: async () => {
        throw new TypeSafeRouterError(
          "HTTP_STATUS_ERROR",
          "Simulated Jev 502 Bad Gateway",
          { statusCode: 502 },
        );
      },
    };
    general.setJudgmentProvider(failingProvider);
    await expect(
      general.planOperation({ objective: "Assess EKS cluster" }),
    ).rejects.toThrowError(TypeSafeRouterError);
  });

  it("auto-wires live TypeSafe Jev provider in OpGeneral when JEV_TYPESAFE_API_KEY is present and honors forceOfflineRouting", async () => {
    let transportCalls = 0;
    const answersPayload: Record<string, unknown> = {
      has_concrete_security_scope: { type: "noul", noul: 0.96 },
      primary_target_modality: {
        type: "choice",
        choice: "blockchain_contract",
        confidence: 0.94,
      },
    };
    for (const fam of ALL_MISSION_FAMILIES) {
      const id = MISSION_ROUTER_QUESTIONS.familyNouls[fam].id;
      answersPayload[id] = {
        type: "noul",
        noul: fam === "smart_contract" ? 0.94 : 0.05,
      };
    }

    const llm = {
      prompt: async () =>
        `\`\`\`json\n${JSON.stringify({
          codename: "AUTO JEV",
          summary: "Solidity vault audit",
          targets: [
            {
              address: "contracts/Vault.sol",
              expectedType: "contract",
              priority: 1,
              rationale: "DeFi vault",
            },
          ],
        })}\n\`\`\``,
    } as unknown as LLMBackbone;

    const mockEnv = {
      JEV_TYPESAFE_API_KEY: "mock_env_jev_key",
    } as unknown as NodeJS.ProcessEnv;

    const autoGeneral = new OpGeneral(llm, {
      typesafeEnv: mockEnv,
      typesafeTransport: async () => {
        transportCalls += 1;
        return {
          status: 200,
          bodyText: JSON.stringify({
            model: "jev-1.14.0",
            answers: answersPayload,
            usage: { input_tokens: 300, output_tokens: 50 },
          }),
        };
      },
    });

    const plan = await autoGeneral.planOperation({
      objective: "Audit Vault.sol ERC-20 token withdrawal reentrancy",
    });
    expect(transportCalls).toBe(1);
    expect(plan.missionFamily).toBe("smart_contract");
    expect(
      autoGeneral.getLastRoutingDecision()?.judgments.providerSource,
    ).toBe("typesafe_jev_http");

    // Explicit forceOfflineRouting bypasses HTTP even when env key is set
    const offlineGeneral = new OpGeneral(llm, {
      forceOfflineRouting: true,
      typesafeEnv: mockEnv,
      typesafeTransport: async () => {
        transportCalls += 1;
        throw new Error("Should not be called in offline mode");
      },
    });
    const offlinePlan = await offlineGeneral.planOperation({
      objective: "Audit Vault.sol ERC-20 token withdrawal reentrancy",
    });
    expect(transportCalls).toBe(1);
    expect(offlinePlan.missionFamily).toBe("smart_contract");
    expect(
      offlineGeneral.getLastRoutingDecision()?.judgments.providerSource,
    ).toBe("offline_calibrated_estimator");
  });
});
