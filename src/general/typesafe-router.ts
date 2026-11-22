/**
 * TypeSafe System One (Jev) Calibrated Probability Router for OpGeneral
 *
 * Architecture (following TypeSafe System One integration craft):
 * 1. Centralized Question & Criteria Registry:
 *    - All atomic Noul / Choice questions, concrete yes/no situation criteria,
 *      disambiguation anchors, and calibrated probability thresholds
 *      (YES_THRESHOLD = 0.7, NO_THRESHOLD = 0.3) live in one auditable module.
 *    - Covers all 11 MissionFamily domains as independent Nouls (since real
 *      operations often span multiple hunt lanes simultaneously), a primary
 *      target modality Choice, and a companion null-case Noul
 *      (`has_concrete_security_scope`) instead of a "none of the above" option.
 * 2. Layer 1 — Atomic Judgment Providers:
 *    - Structured state builder (`buildMissionRoutingState`) passing named fields
 *      rather than raw concatenated strings.
 *    - Exact Jev request payload builder (`buildTypeSafeMissionRequestPayload`)
 *      and strict response parser (`parseTypeSafeMissionResponse`) that surfaces
 *      transport, HTTP, and schema failures as `TypeSafeRouterError` rather than
 *      silently coercing failures into 0.0 / false.
 *    - `HttpTypeSafeJudgmentProvider` gated behind explicit `https://` endpoint
 *      validation and caller-supplied `apiKey` (never called implicitly).
 *    - `estimateMissionJudgmentsOffline`: deterministic calibrated log-odds
 *      evidence estimator over positive cues, false-friend disambiguators,
 *      target artifact modalities, and `sourceRoot` presence.
 * 3. Layer 2 — Pure Deterministic Truth-Table Combiner:
 *    - `combineMissionRouteFromJudgments` operates strictly on calibrated
 *      probabilities, mapping >= 0.7 (CONFIDENT_YES), <= 0.3 (CONFIDENT_NO),
 *      and (0.3, 0.7) (UNCERTAIN_BAND) plus the companion null-case Noul into
 *      an explicit, auditable routing decision.
 */

import type { MissionFamily } from "../resources/index.js";
import type { Directive, OpPlanTarget } from "./index.js";

// =============================================================================
// 1. CENTRALIZED THRESHOLDS, QUESTION DEFINITIONS & CALIBRATION CRITERIA
// =============================================================================

/** Probability at or above which a Noul judgment is treated as settled YES. */
export const YES_THRESHOLD = 0.7;

/** Probability at or below which a Noul judgment is treated as settled NO. */
export const NO_THRESHOLD = 0.3;

/** Default TypeSafe v1 System One REST endpoint URL. */
export const DEFAULT_TYPESAFE_API_URL = "https://api.typesafe.ai/v1/systemone";

/** Default TypeSafe System One model alias (`jev-latest` -> latest stable Jev). */
export const DEFAULT_TYPESAFE_MODEL = "jev-latest";

/**
 * Environment variable names checked in priority order when no explicit `apiKey`
 * argument is passed.
 */
export const TYPESAFE_ENV_KEY_NAMES = [
  "TYPESAFE_API_KEY",
  "JEV_TYPESAFE_API_KEY",
  "JEV_HOTEP_API_KEY",
] as const;

export type TypeSafeEnvKeyName = (typeof TYPESAFE_ENV_KEY_NAMES)[number];
export type TypeSafeApiKeySource = "explicit" | TypeSafeEnvKeyName;

export interface ResolvedTypeSafeApiKey {
  readonly apiKey: string;
  readonly source: TypeSafeApiKeySource;
}

/** Canonical ordering of all 11 T3MP3ST MissionFamily domains. */
export const ALL_MISSION_FAMILIES: readonly MissionFamily[] = [
  "web_api",
  "ai_red_team",
  "cloud_infra",
  "smart_contract",
  "code_audit",
  "code_supply_chain",
  "crypto_secrets",
  "reverse_binary",
  "agent_warfare",
  "social_osint",
  "reporting_remediation",
] as const;

/**
 * Concrete target artifact modalities for the Choice question.
 * Descriptive names are sent to the model; no "none_of_the_above" option is
 * included—the companion `has_concrete_security_scope` Noul handles null scope.
 */
export type PrimaryTargetModality =
  | "web_endpoint"
  | "ai_agent_system"
  | "cloud_control_plane"
  | "blockchain_contract"
  | "source_tree"
  | "repository_pipeline"
  | "cryptographic_material"
  | "compiled_artifact"
  | "public_identity_surface"
  | "governance_artifact";

export const ALL_TARGET_MODALITIES: readonly PrimaryTargetModality[] = [
  "web_endpoint",
  "ai_agent_system",
  "cloud_control_plane",
  "blockchain_contract",
  "source_tree",
  "repository_pipeline",
  "cryptographic_material",
  "compiled_artifact",
  "public_identity_surface",
  "governance_artifact",
] as const;

export interface NoulQuestionSpec {
  readonly id: string;
  readonly kind: "noul";
  readonly question: string;
  readonly criteria: {
    readonly yes: string;
    readonly no: string;
  };
}

export interface ChoiceQuestionSpec<TOption extends string = string> {
  readonly id: string;
  readonly kind: "choice";
  readonly question: string;
  readonly options: Readonly<Record<TOption, string>>;
  readonly nullCompanionNoulId: string;
}

export interface MissionRouterQuestionRegistry {
  readonly model: string;
  readonly thresholds: {
    readonly yes: number;
    readonly no: number;
  };
  readonly nullScopeNoul: NoulQuestionSpec;
  readonly modalityChoice: ChoiceQuestionSpec<PrimaryTargetModality>;
  readonly familyNouls: Readonly<Record<MissionFamily, NoulQuestionSpec>>;
}

/**
 * Single centralized registry of all System One questions, option descriptions,
 * concrete yes/no calibration anchors, and probability thresholds.
 */
export const MISSION_ROUTER_QUESTIONS: MissionRouterQuestionRegistry = {
  model: DEFAULT_TYPESAFE_MODEL,
  thresholds: {
    yes: YES_THRESHOLD,
    no: NO_THRESHOLD,
  },
  nullScopeNoul: {
    id: "has_concrete_security_scope",
    kind: "noul",
    question:
      "Does `directive`, `targets`, or `sourceRootConfigured` identify a concrete software, network, system, or governance security scope to assess?",
    criteria: {
      yes: "The state names an explicit target URL, host, repository, source tree, smart contract, binary artifact, AI system, cloud environment, or specific security assessment deliverable.",
      no: "The input is empty, conversational chitchat, an unscoped daydream with no target or security domain (such as 'find something somewhere'), or a non-security engineering task such as simulating an analog circuit.",
    },
  },
  modalityChoice: {
    id: "primary_target_modality",
    kind: "choice",
    question:
      "Which concrete artifact or environment surface is the primary subject of `directive` and `targets`?",
    nullCompanionNoulId: "has_concrete_security_scope",
    options: {
      web_endpoint:
        "An HTTP web application, REST/GraphQL API endpoint, browser UI route, or networked localhost/staging web service.",
      ai_agent_system:
        "An LLM application, RAG pipeline, model guardrail boundary, or tool-calling autonomous AI agent workflow.",
      cloud_control_plane:
        "An AWS, GCP, Azure, Kubernetes, container cluster, or Terraform cloud infrastructure environment.",
      blockchain_contract:
        "An on-chain Solidity/EVM smart contract, DeFi liquidity protocol, wallet signing flow, or ERC token contract.",
      source_tree:
        "A local source-code directory or source file set audited white-box for CWE sinks and taint paths.",
      repository_pipeline:
        "A Git repository, package manifest, lockfile, SBOM, or CI/CD build and release workflow.",
      cryptographic_material:
        "A cryptographic protocol, cipher/signature implementation, JWT signing verification path, or secret/key store.",
      compiled_artifact:
        "A compiled ELF/PE/Mach-O executable, Intel HEX/Motorola S-Record/U-Boot/Device-Tree firmware image, KiCad hardware EDA schematic/PCB debug surface, Android APK, or binary exploitation target.",
      public_identity_surface:
        "Publicly exposed organization footprint, domain/identity attribution records, or authorized phishing simulation scope.",
      governance_artifact:
        "An executive risk briefing, remediation roadmap, engineering fix plan, or finding verification report.",
    },
  },
  familyNouls: {
    web_api: {
      id: "family_web_api",
      kind: "noul",
      question:
        "Does the mission in `directive` and `targets` test an HTTP web application, API endpoint, or browser-accessible service?",
      criteria: {
        yes: "Targets include `http://` or `https://` URLs, localhost/staging web origins, REST/GraphQL routes, session/cookie auth, SSRF, XSS, SQLi, or OWASP web/API surfaces.",
        no: "The scope is strictly an offline binary, local C/Rust source directory with no HTTP surface, on-chain Solidity contract, or executive report rewrite.",
      },
    },
    ai_red_team: {
      id: "family_ai_red_team",
      kind: "noul",
      question:
        "Does `directive` evaluate an AI/LLM model, prompt-injection boundary, RAG retrieval pipeline, or model guardrail?",
      criteria: {
        yes: "The objective tests LLM prompt injection, system-prompt extraction, jailbreaks, RAG context poisoning, embedding inversion, or ML model safety boundaries.",
        no: "The text mentions 'command prompt' / 'shell prompt' for Windows/CLI terminals, 'SPICE diode model' / 'ORM data model' / 'threat model', or OS 'memory usage' with no AI/ML model in scope.",
      },
    },
    cloud_infra: {
      id: "family_cloud_infra",
      kind: "noul",
      question:
        "Does `directive` or `targets` assess cloud provider IAM, Kubernetes clusters, container runtime isolation, or infrastructure-as-code?",
      criteria: {
        yes: "The scope targets AWS/GCP/Azure accounts, IAM role escalation, S3/GCS buckets, instance metadata services, Kubernetes RBAC/pods, Docker daemon exposure, or Terraform/CloudFormation configs.",
        no: "The target is an ordinary application URL or local source repo where cloud control planes, IAM policies, and cluster configs are outside scope.",
      },
    },
    smart_contract: {
      id: "family_smart_contract",
      kind: "noul",
      question:
        "Does `directive` or `targets` audit blockchain smart contracts, DeFi protocols, wallet signing, or on-chain token logic?",
      criteria: {
        yes: "The scope covers Solidity/Vyper contracts, EVM bytecode, `0x` contract addresses, DeFi vaults/AMMs, ERC-20/ERC-721 token transfers, flash loans, or Foundry/Slither verification.",
        no: "The word 'token' refers to a lexer/parser syntax token, an HTTP JWT bearer/session token, or an API rate-limit token, or 'chain' refers to a TLS certificate chain, supply chain, or exploit chain.",
      },
    },
    code_audit: {
      id: "family_code_audit",
      kind: "noul",
      question:
        "Does `directive` or `sourceRootConfigured` call for white-box source-code vulnerability auditing and source-to-sink CWE taint analysis?",
      criteria: {
        yes: "A local `sourceRoot` or source file path is provided, or the directive requests static white-box code review, CWE sink verification, AST/taint tracing, or line-pinned patch proofs.",
        no: "The assessment only probes a remote black-box URL without source access, or strictly reviews third-party lockfiles/CI pipelines without auditing application source logic.",
      },
    },
    code_supply_chain: {
      id: "family_code_supply_chain",
      kind: "noul",
      question:
        "Does `directive` or `targets` examine repository CI/CD workflows, package dependencies, build provenance, or release hardening?",
      criteria: {
        yes: "The scope inspects GitHub Actions/GitLab CI pipelines, npm/pip/Cargo lockfiles, dependency confusion, typosquatting, SLSA provenance, SBOMs, or repository secret hygiene.",
        no: "The scope tests live runtime web endpoints or binary memory corruption without repository, package-manager, or CI/CD pipeline artifacts.",
      },
    },
    crypto_secrets: {
      id: "family_crypto_secrets",
      kind: "noul",
      question:
        "Does `directive` focus on cryptographic primitives, key/credential leakage, signature verification, or JWT/cipher implementation flaws?",
      criteria: {
        yes: "The mission analyzes RSA/ECDSA/AES/HMAC implementations, weak nonce/RNG usage, padding oracles, JWT signature confusion, hardcoded API keys, or vault/credential rotation flaws.",
        no: "The text mentions lexer/parser tokens, ERC-20 DeFi pool math without key/signature flaws, or generic database primary/foreign keys.",
      },
    },
    reverse_binary: {
      id: "family_reverse_binary",
      kind: "noul",
      question:
        "Does `directive` or `targets` involve reverse engineering compiled binaries, embedded firmware images, hardware EDA debug attack surfaces, mobile APKs, or native memory-corruption exploits?",
      criteria: {
        yes: "Targets include ELF/PE/Mach-O binaries, `.apk`/`.ipa` packages, Intel HEX/Motorola S-Record/U-Boot/Device-Tree firmware blobs, KiCad `.kicad_sch`/`.kicad_pcb` JTAG/SWD/UART/SPI hardware debug surfaces, disassembly/decompilation, format-string bugs, buffer overflows, or ROP/heap exploitation.",
        no: "The scope consists solely of interpreted web apps, TypeScript/Python source repositories, or cloud IAM configurations with no compiled binary, firmware, or hardware debug artifact.",
      },
    },
    agent_warfare: {
      id: "family_agent_warfare",
      kind: "noul",
      question:
        "Does `directive` test multi-agent delegation, cross-agent handoffs, tool-output trust boundaries, or persistent agent memory poisoning?",
      criteria: {
        yes: "The mission probes orchestrator-to-subagent delegation, role confusion across agent handoffs, untrusted MCP/tool output steering, workflow drift, or shared agent memory poisoning.",
        no: "The text refers to an HTTP `User-Agent` header, a CI build agent VM, an OS monitoring daemon, or process heap/RAM memory usage unrelated to autonomous AI agents.",
      },
    },
    social_osint: {
      id: "family_social_osint",
      kind: "noul",
      question:
        "Does `directive` conduct open-source intelligence (OSINT) collection, external identity/footprint mapping, or authorized social/phishing simulation?",
      criteria: {
        yes: "The objective gathers public domain/WHOIS/certificate/recon exposure, maps organizational identity footprints from public sources, or designs an authorized phishing readiness exercise.",
        no:
          "The scope tests technical OAuth/OIDC login endpoints (" +
          "'social login'" +
          ") or internal source code with no public-source OSINT or social-engineering component.",
      },
    },
    reporting_remediation: {
      id: "family_reporting_remediation",
      kind: "noul",
      question:
        "Does `directive` request executive risk synthesis, engineering remediation planning, disclosure drafting, or fix-verification acceptance criteria?",
      criteria: {
        yes: "The user asks for a leadership/executive summary, prioritized remediation roadmap, CVSS/KEV triage report, disclosure package, or concrete acceptance criteria for verifying fixes.",
        no: "The directive only requests raw technical discovery or exploitation probes without a dedicated reporting, disclosure, or remediation-planning deliverable.",
      },
    },
  },
};

export const MODALITY_TO_DEFAULT_FAMILY: Readonly<
  Record<PrimaryTargetModality, MissionFamily>
> = {
  web_endpoint: "web_api",
  ai_agent_system: "ai_red_team",
  cloud_control_plane: "cloud_infra",
  blockchain_contract: "smart_contract",
  source_tree: "code_audit",
  repository_pipeline: "code_supply_chain",
  cryptographic_material: "crypto_secrets",
  compiled_artifact: "reverse_binary",
  public_identity_surface: "social_osint",
  governance_artifact: "reporting_remediation",
};

// =============================================================================
// 2. STRUCTURED STATE & ATOMIC JUDGMENT TYPES
// =============================================================================

export type TargetArtifactKind =
  | "url"
  | "host"
  | "source"
  | "repo"
  | "contract"
  | "binary"
  | "cloud"
  | "agent"
  | "unknown";

export interface MissionRoutingTargetState {
  address: string;
  expectedType: string;
  inferredKind: TargetArtifactKind;
}

/**
 * Clean, named-field state passed to Jev (or the offline calibrated estimator).
 * Structured so a human shown only this state and a single question can answer
 * immediately without parsing serialized prompt soup.
 */
export interface MissionRoutingState {
  directive: {
    objective: string;
    constraints: string;
    scopeHints: string;
  };
  planSummary: string;
  targets: MissionRoutingTargetState[];
  sourceRootConfigured: boolean;
  explicitModelFamily: MissionFamily | null;
  explicitHuntLaneFamilies: MissionFamily[];
}

export interface BuildMissionRoutingStateInput {
  directive: Directive;
  planSummary?: string;
  targets?: ReadonlyArray<Pick<OpPlanTarget, "address" | "expectedType">>;
  sourceRoot?: string | null;
  explicitModelFamily?: MissionFamily | null;
  explicitHuntLaneFamilies?: ReadonlyArray<MissionFamily>;
}

/** Calibrated System One judgment vector returned by Layer 1. */
export interface MissionJudgmentVector {
  /** Companion null-case Noul in [0.0, 1.0]. */
  pHasConcreteSecurityScope: number;
  /** Top option from the `primary_target_modality` Choice question. */
  primaryModality: PrimaryTargetModality;
  /** Optional full probability distribution across modality Choice options. */
  modalityProbabilities?: Readonly<Record<PrimaryTargetModality, number>>;
  /** Optional model-reported Choice concentration confidence in [0.0, 1.0]. */
  modalityConfidence?: number;
  /** Calibrated probabilities in [0.0, 1.0] for each of the 11 MissionFamilies. */
  familyProbabilities: Readonly<Record<MissionFamily, number>>;
  /** Source of the judgments for auditability. */
  providerSource:
    "typesafe_jev_http" | "offline_calibrated_estimator" | "custom";
  /** Versioned model identifier returned by the live TypeSafe API (e.g. `jev-1.14.0`). */
  resolvedModel?: string;
  /** Token usage reported by the live TypeSafe API. */
  usage?: {
    readonly inputTokens: number;
    readonly outputTokens: number;
  };
  /** Measured round-trip latency in milliseconds for HTTP evaluations. */
  latencyMs?: number;
}

export type JudgmentBand = "CONFIDENT_YES" | "UNCERTAIN_BAND" | "CONFIDENT_NO";

export type RouteConfidenceKind =
  | "confident_primary"
  | "confident_multi_lane"
  | "confident_with_uncertain_secondary"
  | "uncertain_fanout"
  | "modality_tiebreak_fallback"
  | "fallback_null_scope";

export type RouteFanOutStrategy =
  | "single_lane"
  | "multi_lane_confident"
  | "primary_plus_uncertain_secondary"
  | "uncertain_single_lane_probe"
  | "uncertain_multi_lane_fanout"
  | "fallback_default";

export type MissionTruthTableRow =
  | "null_scope_fallback"
  | "confident_single_family"
  | "confident_with_uncertain_secondary"
  | "confident_multi_family"
  | "uncertain_band_fanout"
  | "modality_tiebreak_fallback";

/** Structured deterministic routing output produced by Layer 2. */
export interface MissionRouteDecision {
  primaryFamily: MissionFamily;
  selectedFamilies: MissionFamily[];
  confidentFamilies: MissionFamily[];
  uncertainFamilies: MissionFamily[];
  excludedFamilies: MissionFamily[];
  nullScopeBand: JudgmentBand;
  familyBands: Record<MissionFamily, JudgmentBand>;
  routeConfidence: RouteConfidenceKind;
  fanOutStrategy: RouteFanOutStrategy;
  truthTableRow: MissionTruthTableRow;
  requiresScopeClarification: boolean;
  rationale: string;
  judgments: MissionJudgmentVector;
  requestPayload?: TypeSafeJevRequestPayload;
}

// =============================================================================
// 3. TYPED ERRORS & ENDPOINT VALIDATION
// =============================================================================

export type TypeSafeRouterErrorCode =
  | "INVALID_CONFIG"
  | "INSECURE_ENDPOINT_URL"
  | "TRANSPORT_ERROR"
  | "HTTP_STATUS_ERROR"
  | "MALFORMED_RESPONSE"
  | "SCHEMA_VALIDATION_ERROR";

/**
 * Explicit typed error surfaced whenever TypeSafe configuration, transport,
 * HTTP status, or response schema validation fails. Never swallowed as `false`
 * or `0.0`.
 */
export class TypeSafeRouterError extends Error {
  public readonly code: TypeSafeRouterErrorCode;
  public readonly statusCode?: number;
  public override readonly cause?: unknown;

  constructor(
    code: TypeSafeRouterErrorCode,
    message: string,
    options?: { statusCode?: number; cause?: unknown },
  ) {
    super(message);
    this.name = "TypeSafeRouterError";
    this.code = code;
    this.statusCode = options?.statusCode;
    this.cause = options?.cause;
  }
}

/**
 * Validate that a configured TypeSafe endpoint uses `https://` with an explicit
 * host and no embedded URL credentials (preventing `file://`, `http://`, or SSRF
 * scheme confusion).
 */
export function validateTypeSafeEndpointUrl(rawUrl: string): URL {
  const trimmed = rawUrl.trim();
  if (!trimmed) {
    throw new TypeSafeRouterError(
      "INSECURE_ENDPOINT_URL",
      "TypeSafe endpoint URL must be a non-empty https:// URL.",
    );
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch (err) {
    throw new TypeSafeRouterError(
      "INSECURE_ENDPOINT_URL",
      `Invalid TypeSafe endpoint URL: ${JSON.stringify(rawUrl)}`,
      { cause: err },
    );
  }

  if (parsed.protocol !== "https:") {
    throw new TypeSafeRouterError(
      "INSECURE_ENDPOINT_URL",
      `TypeSafe endpoint URL must use https:// scheme, got ${JSON.stringify(parsed.protocol)} in ${JSON.stringify(rawUrl)}`,
    );
  }

  if (!parsed.hostname) {
    throw new TypeSafeRouterError(
      "INSECURE_ENDPOINT_URL",
      `TypeSafe endpoint URL is missing a hostname: ${JSON.stringify(rawUrl)}`,
    );
  }

  if (parsed.username || parsed.password) {
    throw new TypeSafeRouterError(
      "INSECURE_ENDPOINT_URL",
      "TypeSafe endpoint URL must not embed credentials; pass API key via Authorization header.",
    );
  }

  return parsed;
}

/**
 * Resolve the TypeSafe API key and its non-secret source identifier in exact
 * priority order:
 *   1. Explicit `explicitApiKey` argument
 *   2. `TYPESAFE_API_KEY`
 *   3. `JEV_TYPESAFE_API_KEY`
 *   4. `JEV_HOTEP_API_KEY`
 */
export function resolveTypeSafeApiKeyInfo(
  explicitApiKey?: string | null,
  env: NodeJS.ProcessEnv = process.env,
): ResolvedTypeSafeApiKey | null {
  if (typeof explicitApiKey === "string") {
    const trimmed = explicitApiKey.trim();
    if (trimmed.length > 0) {
      return { apiKey: trimmed, source: "explicit" };
    }
  }

  for (const envName of TYPESAFE_ENV_KEY_NAMES) {
    const raw = env[envName];
    if (typeof raw === "string") {
      const trimmed = raw.trim();
      if (trimmed.length > 0) {
        return { apiKey: trimmed, source: envName };
      }
    }
  }

  return null;
}

/**
 * Resolve the TypeSafe API key string in priority order:
 * explicit `apiKey` -> `TYPESAFE_API_KEY` -> `JEV_TYPESAFE_API_KEY` -> `JEV_HOTEP_API_KEY`.
 */
export function resolveTypeSafeApiKey(
  explicitApiKey?: string | null,
  env: NodeJS.ProcessEnv = process.env,
): string | null {
  return resolveTypeSafeApiKeyInfo(explicitApiKey, env)?.apiKey ?? null;
}

/**
 * Resolve the TypeSafe System One endpoint URL:
 * explicit `endpointUrl` -> `TYPESAFE_API_URL` -> `https://api.typesafe.ai/v1/systemone`.
 */
export function resolveTypeSafeEndpointUrl(
  explicitUrl?: string | null,
  env: NodeJS.ProcessEnv = process.env,
): string {
  if (explicitUrl !== undefined && explicitUrl !== null) {
    return explicitUrl;
  }
  const fromEnv = env.TYPESAFE_API_URL;
  if (typeof fromEnv === "string" && fromEnv.trim().length > 0) {
    return fromEnv.trim();
  }
  return DEFAULT_TYPESAFE_API_URL;
}

// =============================================================================
// 4. STATE CONSTRUCTION & PAYLOAD / RESPONSE SERIALIZATION (LAYER 1)
// =============================================================================

export function inferTargetArtifactKind(
  address: string,
  expectedType: string,
): TargetArtifactKind {
  const addr = address.trim();
  const lowAddr = addr.toLowerCase();
  const lowType = expectedType.trim().toLowerCase();

  if (
    /^0x[a-f0-9]{40}$/i.test(addr) ||
    /\.(sol|vy)$/i.test(lowAddr) ||
    lowType.includes("contract") ||
    lowType.includes("defi")
  ) {
    return "contract";
  }

  if (
    /\.(elf|exe|dll|so|dylib|apk|ipa|bin|fw|img|rom|hex|ihex|srec|s19|s28|s37|mot|uf2|uimage|itb|dtb|dts|dtsi|kicad_sch|kicad_pcb)$/i.test(
      lowAddr,
    ) ||
    lowType.includes("binary") ||
    lowType.includes("firmware") ||
    lowType.includes("mobile") ||
    lowType.includes("hardware") ||
    lowType.includes("eda") ||
    lowType.includes("pcb") ||
    lowType.includes("iot") ||
    lowType.includes("embedded")
  ) {
    return "binary";
  }

  if (
    lowType === "cloud" ||
    lowType.includes("kubernetes") ||
    lowType.includes("aws") ||
    lowType.includes("gcp") ||
    lowType.includes("azure") ||
    /^(arn:aws:|s3:\/\/|gs:\/\/)/i.test(addr) ||
    /\.(tf|tfvars)$/i.test(lowAddr)
  ) {
    return "cloud";
  }

  if (
    lowType.includes("agent") ||
    lowType.includes("llm") ||
    lowType.includes("model")
  ) {
    return "agent";
  }

  if (
    /(github\.com|gitlab\.com|bitbucket\.org)\/[^/\s]+\/[^/\s]+/i.test(addr) ||
    /\.git$/i.test(lowAddr) ||
    /(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|requirements\.txt|poetry\.lock|cargo\.lock|\.github\/workflows)/i.test(
      lowAddr,
    ) ||
    lowType.includes("repo")
  ) {
    return "repo";
  }

  if (
    /\.(ts|tsx|js|jsx|mjs|cjs|py|rs|go|c|cc|cpp|h|hpp|java|kt|rb|php|cs)$/i.test(
      lowAddr,
    ) ||
    /^(\.\/|\.\.\/|\/|[a-z]:\\)/i.test(addr) ||
    lowType.includes("source")
  ) {
    return "source";
  }

  if (
    /^https?:\/\//i.test(addr) ||
    lowType === "web_application" ||
    lowType === "api"
  ) {
    return "url";
  }

  if (
    lowAddr === "localhost" ||
    /^\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?(?::\d+)?$/.test(lowAddr) ||
    /\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:com|org|net|io|dev|app|co|gov|edu)\b/i.test(
      lowAddr,
    ) ||
    lowType === "host" ||
    lowType === "network"
  ) {
    return "host";
  }

  return "unknown";
}

export function buildMissionRoutingState(
  input: BuildMissionRoutingStateInput,
): MissionRoutingState {
  const targets: MissionRoutingTargetState[] = (input.targets ?? [])
    .filter((t) => Boolean(t.address && t.address.trim()))
    .map((t) => {
      const address = t.address.trim();
      const expectedType = (t.expectedType || "unknown").trim();
      return {
        address,
        expectedType,
        inferredKind: inferTargetArtifactKind(address, expectedType),
      };
    });

  const seenLanes = new Set<MissionFamily>();
  const explicitHuntLaneFamilies: MissionFamily[] = [];
  for (const fam of input.explicitHuntLaneFamilies ?? []) {
    if (ALL_MISSION_FAMILIES.includes(fam) && !seenLanes.has(fam)) {
      seenLanes.add(fam);
      explicitHuntLaneFamilies.push(fam);
    }
  }

  return {
    directive: {
      objective: input.directive.objective.trim(),
      constraints: (input.directive.constraints ?? "").trim(),
      scopeHints: (input.directive.scopeHints ?? "").trim(),
    },
    planSummary: (input.planSummary ?? "").trim(),
    targets,
    sourceRootConfigured: Boolean(input.sourceRoot && input.sourceRoot.trim()),
    explicitModelFamily:
      input.explicitModelFamily &&
      ALL_MISSION_FAMILIES.includes(input.explicitModelFamily)
        ? input.explicitModelFamily
        : null,
    explicitHuntLaneFamilies,
  };
}

export type TypeSafeSerializedQuestion =
  | {
      type: "noul";
      instructions: string;
      criteria?: {
        true: string;
        false: string;
      };
    }
  | {
      type: "choice";
      instructions: string;
      criteria: Readonly<Record<string, string>>;
    };

export interface TypeSafeJevRequestPayload {
  model: string;
  state: MissionRoutingState;
  questions: Record<string, TypeSafeSerializedQuestion>;
}

/**
 * Build the exact TypeSafe v1 `/v1/systemone` HTTP request payload from
 * centralized question definitions so callers can inspect, log, or replay
 * every request verbatim.
 */
export function buildTypeSafeMissionRequestPayload(
  state: MissionRoutingState,
  model: string = MISSION_ROUTER_QUESTIONS.model,
): TypeSafeJevRequestPayload {
  const questions: Record<string, TypeSafeSerializedQuestion> = {
    [MISSION_ROUTER_QUESTIONS.nullScopeNoul.id]: {
      type: "noul",
      instructions: MISSION_ROUTER_QUESTIONS.nullScopeNoul.question,
      criteria: {
        true: MISSION_ROUTER_QUESTIONS.nullScopeNoul.criteria.yes,
        false: MISSION_ROUTER_QUESTIONS.nullScopeNoul.criteria.no,
      },
    },
    [MISSION_ROUTER_QUESTIONS.modalityChoice.id]: {
      type: "choice",
      instructions: MISSION_ROUTER_QUESTIONS.modalityChoice.question,
      criteria: MISSION_ROUTER_QUESTIONS.modalityChoice.options,
    },
  };

  for (const family of ALL_MISSION_FAMILIES) {
    const spec = MISSION_ROUTER_QUESTIONS.familyNouls[family];
    questions[spec.id] = {
      type: "noul",
      instructions: spec.question,
      criteria: {
        true: spec.criteria.yes,
        false: spec.criteria.no,
      },
    };
  }

  return {
    model,
    state,
    questions,
  };
}

function parseValidatedProbability(value: unknown, fieldName: string): number {
  if (typeof value === "number") {
    if (!Number.isFinite(value) || value < 0 || value > 1) {
      throw new TypeSafeRouterError(
        "SCHEMA_VALIDATION_ERROR",
        `Question "${fieldName}" probability must be a finite number in [0.0, 1.0], got ${String(value)}.`,
      );
    }
    return value;
  }

  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const candidate =
      record.noul ??
      record.probability ??
      record.p ??
      record.true_probability ??
      record.yes;
    if (typeof candidate === "number") {
      return parseValidatedProbability(candidate, fieldName);
    }
  }

  throw new TypeSafeRouterError(
    "SCHEMA_VALIDATION_ERROR",
    `Question "${fieldName}" is missing a numeric calibrated probability in [0.0, 1.0].`,
  );
}

function parseValidatedChoice(
  value: unknown,
  fieldName: string,
): {
  topOption: PrimaryTargetModality;
  probabilities?: Record<PrimaryTargetModality, number>;
  confidence?: number;
} {
  if (typeof value === "string") {
    if ((ALL_TARGET_MODALITIES as readonly string[]).includes(value)) {
      return { topOption: value as PrimaryTargetModality };
    }
    throw new TypeSafeRouterError(
      "SCHEMA_VALIDATION_ERROR",
      `Choice "${fieldName}" returned unknown modality option ${JSON.stringify(value)}.`,
    );
  }

  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const topRaw =
      record.choice ?? record.top ?? record.answer ?? record.option;
    const probsRaw = record.probabilities ?? record.distribution;
    const confidence =
      typeof record.confidence === "number" &&
      Number.isFinite(record.confidence)
        ? record.confidence
        : undefined;

    let parsedDistribution: Record<PrimaryTargetModality, number> | undefined;
    if (probsRaw && typeof probsRaw === "object") {
      const distRecord = probsRaw as Record<string, unknown>;
      const dist = {} as Record<PrimaryTargetModality, number>;
      for (const modality of ALL_TARGET_MODALITIES) {
        dist[modality] = parseValidatedProbability(
          distRecord[modality],
          `${fieldName}.probabilities.${modality}`,
        );
      }
      parsedDistribution = dist;
    }

    if (
      typeof topRaw === "string" &&
      (ALL_TARGET_MODALITIES as readonly string[]).includes(topRaw)
    ) {
      return {
        topOption: topRaw as PrimaryTargetModality,
        probabilities: parsedDistribution,
        confidence,
      };
    }

    if (parsedDistribution) {
      let best: PrimaryTargetModality = ALL_TARGET_MODALITIES[0];
      let bestProb = -1;
      for (const modality of ALL_TARGET_MODALITIES) {
        if (parsedDistribution[modality] > bestProb) {
          bestProb = parsedDistribution[modality];
          best = modality;
        }
      }
      return {
        topOption: best,
        probabilities: parsedDistribution,
        confidence,
      };
    }
  }

  throw new TypeSafeRouterError(
    "SCHEMA_VALIDATION_ERROR",
    `Choice "${fieldName}" is missing a valid PrimaryTargetModality option.`,
  );
}

/**
 * Parse and validate a raw TypeSafe Jev JSON response object into a typed
 * `MissionJudgmentVector`. Throws `TypeSafeRouterError` on any missing or
 * out-of-range answer rather than defaulting failed fields to `0.0`.
 */
export function parseTypeSafeMissionResponse(
  raw: unknown,
): MissionJudgmentVector {
  if (!raw || typeof raw !== "object") {
    throw new TypeSafeRouterError(
      "MALFORMED_RESPONSE",
      "TypeSafe Jev response must be a JSON object.",
    );
  }

  const root = raw as Record<string, unknown>;
  const answers =
    root.answers && typeof root.answers === "object"
      ? (root.answers as Record<string, unknown>)
      : root;

  const nullId = MISSION_ROUTER_QUESTIONS.nullScopeNoul.id;
  const pHasConcreteSecurityScope = parseValidatedProbability(
    answers[nullId],
    nullId,
  );

  const choiceId = MISSION_ROUTER_QUESTIONS.modalityChoice.id;
  const parsedChoice = parseValidatedChoice(answers[choiceId], choiceId);

  const familyProbabilities = {} as Record<MissionFamily, number>;
  for (const family of ALL_MISSION_FAMILIES) {
    const spec = MISSION_ROUTER_QUESTIONS.familyNouls[family];
    const rawEntry =
      answers[spec.id] !== undefined ? answers[spec.id] : answers[family];
    familyProbabilities[family] = parseValidatedProbability(rawEntry, spec.id);
  }

  const resolvedModel =
    typeof root.model === "string" && root.model.trim().length > 0
      ? root.model.trim()
      : undefined;

  let usage: { inputTokens: number; outputTokens: number } | undefined;
  if (root.usage && typeof root.usage === "object") {
    const usageRecord = root.usage as Record<string, unknown>;
    if (
      typeof usageRecord.input_tokens === "number" &&
      typeof usageRecord.output_tokens === "number"
    ) {
      usage = {
        inputTokens: usageRecord.input_tokens,
        outputTokens: usageRecord.output_tokens,
      };
    }
  }

  return {
    pHasConcreteSecurityScope,
    primaryModality: parsedChoice.topOption,
    modalityProbabilities: parsedChoice.probabilities,
    modalityConfidence: parsedChoice.confidence,
    familyProbabilities,
    providerSource: "typesafe_jev_http",
    resolvedModel,
    usage,
  };
}

// =============================================================================
// 5. JUDGMENT PROVIDERS (HTTP GATED CLIENT & OFFLINE CALIBRATED ESTIMATOR)
// =============================================================================

export interface MissionJudgmentProvider {
  evaluate(state: MissionRoutingState): Promise<MissionJudgmentVector>;
}

export interface TypeSafeHttpTransportRequest {
  url: string;
  method: "POST";
  headers: Record<string, string>;
  body: string;
  timeoutMs: number;
}

export interface TypeSafeHttpTransportResponse {
  status: number;
  bodyText: string;
}

export type TypeSafeHttpTransport = (
  request: TypeSafeHttpTransportRequest,
) => Promise<TypeSafeHttpTransportResponse>;

/**
 * Default live HTTPS transport backed by Node's built-in `fetch` with an
 * `AbortController` deadline. Never logs or embeds `Authorization` headers in
 * error messages.
 */
export const defaultNodeFetchTypeSafeTransport: TypeSafeHttpTransport = async (
  request,
) => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), request.timeoutMs);
  try {
    const response = await fetch(request.url, {
      method: request.method,
      headers: {
        Accept: "application/json",
        "User-Agent": "t3mp3st-typesafe-router/1.0",
        ...request.headers,
      },
      body: request.body,
      signal: controller.signal,
    });
    const bodyText = await response.text();
    return {
      status: response.status,
      bodyText,
    };
  } finally {
    clearTimeout(timer);
  }
};

export interface HttpTypeSafeJudgmentProviderConfig {
  endpointUrl?: string;
  apiKey?: string;
  model?: string;
  timeoutMs?: number;
  env?: NodeJS.ProcessEnv;
  transport?: TypeSafeHttpTransport;
}

/**
 * Production/mockable TypeSafe v1 `/v1/systemone` HTTP judgment provider.
 * Enforces an explicit `https://` endpoint URL and non-empty API key (resolved
 * from explicit `apiKey`, `TYPESAFE_API_KEY`, `JEV_TYPESAFE_API_KEY`, or
 * `JEV_HOTEP_API_KEY`), with optional injected `transport` for offline tests.
 */
export class HttpTypeSafeJudgmentProvider implements MissionJudgmentProvider {
  private readonly validatedUrl: URL;
  private readonly apiKey: string;
  private readonly apiKeySource: TypeSafeApiKeySource;
  private readonly model: string;
  private readonly timeoutMs: number;
  private readonly transport: TypeSafeHttpTransport;

  constructor(config: HttpTypeSafeJudgmentProviderConfig) {
    const env = config.env ?? process.env;
    const rawUrl = resolveTypeSafeEndpointUrl(config.endpointUrl, env);
    this.validatedUrl = validateTypeSafeEndpointUrl(rawUrl);

    const resolvedKey = resolveTypeSafeApiKeyInfo(config.apiKey, env);
    if (!resolvedKey) {
      throw new TypeSafeRouterError(
        "INVALID_CONFIG",
        `TypeSafe API key must be provided via config.apiKey or one of [${TYPESAFE_ENV_KEY_NAMES.join(", ")}].`,
      );
    }

    const transport = config.transport ?? defaultNodeFetchTypeSafeTransport;
    if (typeof transport !== "function") {
      throw new TypeSafeRouterError(
        "INVALID_CONFIG",
        "HTTP transport must be a function in HttpTypeSafeJudgmentProvider.",
      );
    }

    this.apiKey = resolvedKey.apiKey;
    this.apiKeySource = resolvedKey.source;
    this.model = config.model?.trim() || MISSION_ROUTER_QUESTIONS.model;
    this.timeoutMs = config.timeoutMs ?? 15000;
    this.transport = transport;
  }

  /** Return the non-secret source name that supplied the API key. */
  getApiKeySource(): TypeSafeApiKeySource {
    return this.apiKeySource;
  }

  /** Return the validated HTTPS endpoint URL. */
  getEndpointUrl(): string {
    return this.validatedUrl.toString();
  }

  async evaluate(state: MissionRoutingState): Promise<MissionJudgmentVector> {
    const payload = buildTypeSafeMissionRequestPayload(state, this.model);
    const startedAt = performance.now();
    let response: TypeSafeHttpTransportResponse;
    try {
      response = await this.transport({
        url: this.validatedUrl.toString(),
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
        timeoutMs: this.timeoutMs,
      });
    } catch (err) {
      if (err instanceof TypeSafeRouterError) {
        throw err;
      }
      const detail = err instanceof Error ? err.message : String(err);
      throw new TypeSafeRouterError(
        "TRANSPORT_ERROR",
        `TypeSafe Jev request transport failed: ${detail}`,
        { cause: err },
      );
    }
    const latencyMs = Math.round((performance.now() - startedAt) * 100) / 100;

    if (response.status < 200 || response.status >= 300) {
      throw new TypeSafeRouterError(
        "HTTP_STATUS_ERROR",
        `TypeSafe Jev endpoint returned HTTP ${response.status}.`,
        { statusCode: response.status },
      );
    }

    let decoded: unknown;
    try {
      decoded = JSON.parse(response.bodyText);
    } catch (err) {
      throw new TypeSafeRouterError(
        "MALFORMED_RESPONSE",
        "TypeSafe Jev endpoint returned invalid JSON.",
        { cause: err },
      );
    }

    const parsed = parseTypeSafeMissionResponse(decoded);
    return {
      ...parsed,
      latencyMs,
    };
  }
}

export interface CreateLiveTypeSafeProviderOptions {
  apiKey?: string;
  endpointUrl?: string;
  model?: string;
  timeoutMs?: number;
  env?: NodeJS.ProcessEnv;
  transport?: TypeSafeHttpTransport;
}

/**
 * Create a live `HttpTypeSafeJudgmentProvider` when a TypeSafe API key is
 * available (explicit `apiKey` -> `TYPESAFE_API_KEY` -> `JEV_TYPESAFE_API_KEY`
 * -> `JEV_HOTEP_API_KEY`), or return `null` when no key is configured.
 * Surfaces `TypeSafeRouterError` if `endpointUrl` / `TYPESAFE_API_URL` is invalid.
 */
export function createLiveTypeSafeJudgmentProvider(
  options?: CreateLiveTypeSafeProviderOptions,
): HttpTypeSafeJudgmentProvider | null {
  const env = options?.env ?? process.env;
  const resolvedKey = resolveTypeSafeApiKeyInfo(options?.apiKey, env);
  if (!resolvedKey) {
    return null;
  }
  return new HttpTypeSafeJudgmentProvider({
    endpointUrl: options?.endpointUrl,
    apiKey: options?.apiKey,
    model: options?.model,
    timeoutMs: options?.timeoutMs,
    env,
    transport: options?.transport,
  });
}

function sigmoid(logit: number): number {
  if (logit >= 16) return 0.999999;
  if (logit <= -16) return 0.000001;
  return 1 / (1 + Math.exp(-logit));
}

interface WeightedPattern {
  readonly pattern: RegExp;
  readonly weight: number;
}

interface FamilyEvidenceModel {
  readonly priorLogit: number;
  readonly positiveCues: readonly WeightedPattern[];
  readonly negativeDisambiguators: readonly WeightedPattern[];
  readonly targetKindWeights: Partial<Record<TargetArtifactKind, number>>;
  readonly sourceRootBoost?: number;
}

const FAMILY_EVIDENCE_MODELS: Readonly<
  Record<MissionFamily, FamilyEvidenceModel>
> = {
  web_api: {
    priorLogit: -2.3,
    positiveCues: [
      {
        pattern:
          /\b(web\s*app(?:lication)?|web\s*\/?\s*api|rest\s*api|graphql|owasp|ssrf|xss|sqli|csrf|idor|http\s*endpoint|api\s*endpoint)\b/i,
        weight: 3.4,
      },
      {
        pattern:
          /\b(https?:\/\/|localhost|127\.0\.0\.1|route|endpoint|cookie|session|cors|webhook|reverse\s*proxy)\b/i,
        weight: 1.9,
      },
      {
        pattern:
          /\b(staging\s*app|browser|portal|login\s*flow|auth\s*bypass)\b/i,
        weight: 1.5,
      },
    ],
    negativeDisambiguators: [
      {
        pattern:
          /\b(offline\s*binary|firmware\s*blob|solidity\s*contract\s*only|spice\s*netlist)\b/i,
        weight: 2.2,
      },
    ],
    targetKindWeights: {
      url: 2.2,
      host: 1.5,
      source: -0.4,
      binary: -0.8,
      contract: -0.8,
    },
  },

  ai_red_team: {
    priorLogit: -2.5,
    positiveCues: [
      {
        pattern:
          /\b(ai\s*red[\s-]*team|prompt\s*injection|indirect\s*prompt|system\s*prompt|jailbreak|llm|rag\b|guardrail|mitre\s*atlas|owasp\s*llm)\b/i,
        weight: 3.7,
      },
      {
        pattern:
          /\b(language\s*model|foundation\s*model|ml\s*model|embedding\s*(?:model|inversion)|model\s*(?:weights|extraction|boundary)|context\s*poisoning|chatbot)\b/i,
        weight: 3.3,
      },
      {
        pattern: /\b(agent\s*boundary|retrieval\s*poisoning|eval\s*bypass)\b/i,
        weight: 2.4,
      },
      // Weak ambiguous lexical cues that require corroborating AI context to reach >= 0.7:
      {
        pattern: /\b(prompt|model)\b/i,
        weight: 1.1,
      },
    ],
    negativeDisambiguators: [
      // Disambiguate CLI/Windows "command prompt" / "shell prompt":
      {
        pattern:
          /\b(command\s*prompt|cmd\.exe|powershell\s*prompt|shell\s*prompt|bash\s*prompt|terminal\s*prompt|cli\s*prompt|login\s*prompt)\b/i,
        weight: 3.2,
      },
      // Disambiguate SPICE circuit models & software data/domain/threat models:
      {
        pattern:
          /\b(spice\s*(?:diode\s*)?model|diode\s*model|transistor\s*model|mosfet\s*model|bjt\s*model|\.model\b|subckt\s*model|data\s*model|domain\s*model|orm\s*model|threat\s*model|relational\s*model)\b/i,
        weight: 3.4,
      },
      // Disambiguate generic OS/heap memory metrics:
      {
        pattern:
          /\b(memory\s*usage|heap\s*memory|rss\s*memory|out\s*of\s*memory|memory\s*footprint|memory\s*leak|stack\s*memory|buffer\s*overflow|use[\s-]*after[\s-]*free)\b/i,
        weight: 2.5,
      },
    ],
    targetKindWeights: {
      agent: 2.6,
      binary: -0.6,
      contract: -0.6,
    },
  },

  cloud_infra: {
    priorLogit: -2.5,
    positiveCues: [
      {
        pattern:
          /\b(aws|gcp|azure|kubernetes|k8s|iam\s*(?:role|policy|escalation|misconfig)|terraform|cloudformation|eks|gke|aks)\b/i,
        weight: 3.6,
      },
      {
        pattern:
          /\b(s3\s*bucket|imds(?:v1|v2)?|instance\s*metadata|container\s*(?:escape|runtime)|docker\s*(?:socket|daemon)|cloud\s*(?:infra|control\s*plane|misconfig))\b/i,
        weight: 3.2,
      },
      {
        pattern: /\b(cloud|container|cluster|helm\s*chart|pod\s*security)\b/i,
        weight: 1.8,
      },
    ],
    negativeDisambiguators: [
      {
        pattern: /\b(cloudflare\s*turnstile|word\s*cloud|point\s*cloud)\b/i,
        weight: 2.8,
      },
    ],
    targetKindWeights: {
      cloud: 2.8,
    },
  },

  smart_contract: {
    priorLogit: -2.6,
    positiveCues: [
      {
        pattern:
          /\b(smart\s*contract|solidity|vyper|evm\b|defi\b|erc[\s-]*(?:20|721|1155|4626)|reentrancy|flash\s*loan|foundry|slither|mythril)\b/i,
        weight: 3.9,
      },
      {
        pattern:
          /\b(on[\s-]*chain|blockchain|liquidity\s*pool|amm\b|staking\s*vault|wallet\s*signing|mempool|mev\b)\b/i,
        weight: 3.3,
      },
      // Ambiguous words ("token", "wallet", "contract", "transaction") only contribute modest weight alone:
      {
        pattern: /\b(contract|wallet|transaction|token)\b/i,
        weight: 1.1,
      },
    ],
    negativeDisambiguators: [
      // Disambiguate lexer/parser/AST/SPICE tokens:
      {
        pattern:
          /\b(lexer\s*token|parser\s*token|syntax\s*token|ast\s*token|spice\s*token|token\s*stream|tokenizer|csrf\s*token)\b/i,
        weight: 3.6,
      },
      // Disambiguate web JWT/OAuth/session/API bearer tokens when no blockchain context exists:
      {
        pattern:
          /\b(jwt\b|bearer\s*token|session\s*token|oauth\s*token|refresh\s*token|api\s*token|access\s*token)\b/i,
        weight: 2.4,
      },
      // Disambiguate non-blockchain "chain" / "contract" phrases:
      {
        pattern:
          /\b(supply\s*chain|exploit\s*chain|certificate\s*chain|proxy\s*chain|rop\s*chain|api\s*contract|evidence\s*contract|service\s*contract|db\s*transaction|sql\s*transaction)\b/i,
        weight: 2.6,
      },
    ],
    targetKindWeights: {
      contract: 3.2,
      binary: -0.6,
    },
  },

  code_audit: {
    priorLogit: -2.5,
    positiveCues: [
      {
        pattern:
          /\b(code[\s-]*audit|source[\s-]*(?:code|file|tree)\s*(?:audit|review)|white[\s-]*box|taint\s*(?:path|analysis|trace)|source[\s-]*to[\s-]*sink|sink\s*line|cwe-\d+|static\s*analysis|semgrep|codeql)\b/i,
        weight: 3.7,
      },
      {
        pattern:
          /\b(ast\s*audit|dangerous\s*sink|unsafe\s*deserialization\s*in\s*source|patch\s*proof|line[\s-]*pinned)\b/i,
        weight: 2.8,
      },
      {
        pattern:
          /\b(source\s*code|static\s*review|audit\s*the\s*implementation)\b/i,
        weight: 1.9,
      },
    ],
    negativeDisambiguators: [
      {
        pattern:
          /\b(black[\s-]*box\s*only|no\s*source\s*access|external\s*url\s*only)\b/i,
        weight: 2.8,
      },
    ],
    targetKindWeights: {
      source: 2.6,
    },
    sourceRootBoost: 2.8,
  },

  code_supply_chain: {
    priorLogit: -2.5,
    positiveCues: [
      {
        pattern:
          /\b(supply[\s-]*chain|ci\/cd|github\s*actions|gitlab\s*ci|workflow\s*(?:hardening|permissions|injection)|slsa\b|sbom\b|openssf|dependency\s*(?:confusion|triage|audit)|typosquat)/i,
        weight: 3.7,
      },
      {
        pattern:
          /\b(lockfile|package\.json|npm\s*(?:package|audit|registry)|pip\s*(?:package|install)|pypi|cargo\.toml|release\s*provenance|branch\s*protection)\b/i,
        weight: 3.0,
      },
      {
        pattern:
          /\b(repository\s*hardening|repo\s*to\s*harden|build\s*pipeline)\b/i,
        weight: 2.5,
      },
    ],
    negativeDisambiguators: [
      {
        pattern: /\b(agent\s*workflow\s*drift)\b/i,
        weight: 1.5,
      },
    ],
    targetKindWeights: {
      repo: 2.8,
    },
  },

  crypto_secrets: {
    priorLogit: -2.5,
    positiveCues: [
      {
        pattern:
          /\b(jwt\s*(?:signing|alg|none|confusion|secret|token|verification)|hmac\b|ecdsa\b|rsa\b|aes[\s-]*(?:gcm|cbc|ecb)|padding\s*oracle|cipher|nonce\s*reuse|signature\s*(?:forgery|bypass|malleability))\b/i,
        weight: 3.7,
      },
      {
        pattern:
          /\b(hardcoded\s*(?:secret|key|credential)|secret\s*(?:leak|scanning|rotation|redaction)|private\s*key|jwk\b|jwks\b|hash\s*collision|weak\s*rng|key\s*derivation|pbkdf2|argon2)\b/i,
        weight: 3.4,
      },
      {
        pattern:
          /\b(crypto(?:graphic)?|credential|bearer\s*token|session\s*token|api\s*key)\b/i,
        weight: 2.0,
      },
    ],
    negativeDisambiguators: [
      // Disambiguate lexer/parser tokens and DB primary/foreign keys:
      {
        pattern:
          /\b(lexer\s*token|parser\s*token|syntax\s*token|ast\s*token|spice\s*token|primary\s*key|foreign\s*key|sort\s*key|react\s*key|json\s*key|crypto\s*exchange\s*ui)\b/i,
        weight: 3.4,
      },
      // Pure ERC-20 token transfer without cryptographic primitive context:
      {
        pattern: /\b(erc[\s-]*20\s*token|governance\s*token\s*vote)\b/i,
        weight: 1.8,
      },
    ],
    targetKindWeights: {},
  },

  reverse_binary: {
    priorLogit: -2.5,
    positiveCues: [
      {
        pattern:
          /\b(reverse\s*engineer(?:ing)?|decompile|disassembl(?:e|y)|elf\s*binary|pe\s*binary|firmware|apk\b|jadx|apktool|radare2|ghidra|binwalk)\b/i,
        weight: 3.8,
      },
      {
        pattern:
          /\b(firmware_audit_scan|intel\s*hex|ihex\b|s-?record|srec\b|u-?boot|uimage\b|bootcmd\b|tftpboot\b|device[\s-]*tree|\.dtsi?\b|\.hex\b|\.s19\b|\.mot\b|kicad|\.kicad_(?:sch|pcb)\b|jtag\b|swd\b|swdio\b|swclk\b|uart\s*(?:debug|console|header|txd|rxd)|spi[_\s-]*flash|soic-?8\b|boot0\b|boot_sel\b|pcb\s*(?:debug|attack|audit)|hardware\s*(?:debug|attack\s*surface|security\s*audit))\b/i,
        weight: 3.8,
      },
      {
        pattern:
          /\b(buffer\s*overflow|format\s*string|use[\s-]*after[\s-]*free|heap\s*exploitation|rop\s*chain|shellcode|binary\s*(?:pwn|exploit|sink))\b/i,
        weight: 3.5,
      },
      {
        pattern: /\b(binary|ctf\s*pwn|native\s*crash)\b/i,
        weight: 2.0,
      },
    ],
    negativeDisambiguators: [
      {
        pattern: /\b(binary\s*search|binary\s*tree|binary\s*classification)\b/i,
        weight: 3.4,
      },
    ],
    targetKindWeights: {
      binary: 3.2,
    },
  },

  agent_warfare: {
    priorLogit: -2.6,
    positiveCues: [
      {
        pattern:
          /\b(agent\s*(?:warfare|handoff|delegation|memory\s*poisoning|impersonation|collusion)|multi[\s-]*agent|subagent|tool[\s-]*output\s*(?:injection|trust)|orchestrator\s*(?:hijack|drift)|workflow\s*drift)\b/i,
        weight: 3.8,
      },
      {
        pattern:
          /\b(mcp\s*(?:tool|server)\s*(?:poisoning|rugpull|spoofing)|shared\s*memory\s*board|episodic\s*memory\s*poisoning|autonomous\s*delegation|role\s*confusion\s*across\s*agents)\b/i,
        weight: 3.6,
      },
      {
        pattern: /\b(agent\s*memory|tool\s*use\s*boundary|delegate|handoff)\b/i,
        weight: 2.4,
      },
    ],
    negativeDisambiguators: [
      // Disambiguate User-Agent header, OS/CI agents, and process memory usage:
      {
        pattern:
          /\b(user[\s-]*agent|ssh[\s-]*agent|gpg[\s-]*agent|snmp\s*agent|ci\s*build\s*agent|jenkins\s*agent|real\s*estate\s*agent)\b/i,
        weight: 3.5,
      },
      {
        pattern:
          /\b(memory\s*usage|heap\s*memory|rss\s*memory|out\s*of\s*memory|memory\s*footprint|memory\s*leak|memory\s*allocator|buffer\s*overflow)\b/i,
        weight: 3.2,
      },
    ],
    targetKindWeights: {
      agent: 2.2,
    },
  },

  social_osint: {
    priorLogit: -2.6,
    positiveCues: [
      {
        pattern:
          /\b(osint|open[\s-]*source\s*intelligence|phish(?:ing)?\s*simulation|spear[\s-]*phish|pretexting|public\s*(?:exposure|footprint|recon)|identity\s*attribution|social\s*engineering)\b/i,
        weight: 3.8,
      },
      {
        pattern:
          /\b(whois\s*footprint|employee\s*osint|dox\s*exposure\s*audit|brand\s*impersonation|public\s*source\s*recon)\b/i,
        weight: 3.2,
      },
    ],
    negativeDisambiguators: [
      {
        pattern:
          /\b(social\s*login\s*oauth|social\s*media\s*api\s*rate\s*limit)\b/i,
        weight: 2.8,
      },
    ],
    targetKindWeights: {},
  },

  reporting_remediation: {
    priorLogit: -2.6,
    positiveCues: [
      {
        pattern:
          /\b(executive\s*(?:summary|briefing|report)|remediation\s*(?:plan|roadmap|backlog)|leadership\s*brief|fix\s*plan|acceptance\s*criteria|disclosure\s*(?:report|package)|cve\s*(?:prioritization|triage\s*report))\b/i,
        weight: 3.7,
      },
      {
        pattern:
          /\b(remediation|post[\s-]*mortem\s*report|board\s*presentation)\b/i,
        weight: 2.3,
      },
    ],
    negativeDisambiguators: [
      {
        pattern:
          /\b(bug\s*report\s*endpoint|csp\s*report[\s-]*uri|crash\s*report\s*parser)\b/i,
        weight: 3.0,
      },
    ],
    targetKindWeights: {},
  },
};

const FAMILY_TO_PRIMARY_MODALITY: Readonly<
  Record<MissionFamily, PrimaryTargetModality>
> = {
  web_api: "web_endpoint",
  ai_red_team: "ai_agent_system",
  cloud_infra: "cloud_control_plane",
  smart_contract: "blockchain_contract",
  code_audit: "source_tree",
  code_supply_chain: "repository_pipeline",
  crypto_secrets: "cryptographic_material",
  reverse_binary: "compiled_artifact",
  agent_warfare: "ai_agent_system",
  social_osint: "public_identity_surface",
  reporting_remediation: "governance_artifact",
};

/**
 * Deterministic offline calibrated probability estimator (Layer 1 offline backend).
 * Computes log-odds evidence scores over positive domain cues, explicit
 * false-friend disambiguators, structured target artifact kinds, `sourceRoot`,
 * and structured plan hints, returning calibrated `[0.0, 1.0]` probabilities.
 */
export function estimateMissionJudgmentsOffline(
  state: MissionRoutingState,
): MissionJudgmentVector {
  const combinedText = [
    state.directive.objective,
    state.directive.constraints,
    state.directive.scopeHints,
    state.planSummary,
    ...state.targets.map((t) => `${t.address} ${t.expectedType}`),
  ]
    .filter(Boolean)
    .join(" ");

  const familyLogits = {} as Record<MissionFamily, number>;
  const familyProbabilities = {} as Record<MissionFamily, number>;

  for (const family of ALL_MISSION_FAMILIES) {
    const model = FAMILY_EVIDENCE_MODELS[family];
    let logit = model.priorLogit;

    for (const cue of model.positiveCues) {
      if (cue.pattern.test(combinedText)) {
        logit += cue.weight;
      }
    }

    for (const neg of model.negativeDisambiguators) {
      if (neg.pattern.test(combinedText)) {
        logit -= neg.weight;
      }
    }

    for (const target of state.targets) {
      const targetWeight = model.targetKindWeights[target.inferredKind];
      if (targetWeight !== undefined) {
        logit += targetWeight;
      }
    }

    if (state.sourceRootConfigured && model.sourceRootBoost !== undefined) {
      logit += model.sourceRootBoost;
    }

    if (state.explicitModelFamily === family) {
      logit += 3.0;
    } else if (state.explicitHuntLaneFamilies.includes(family)) {
      logit += 2.4;
    }

    familyLogits[family] = logit;
    familyProbabilities[family] = sigmoid(logit);
  }

  // Calibrate companion null-case Noul (`has_concrete_security_scope`):
  let scopeLogit = -2.4;
  if (state.targets.length > 0) {
    scopeLogit += 2.8;
  }
  if (state.sourceRootConfigured) {
    scopeLogit += 2.6;
  }
  if (
    state.explicitModelFamily !== null ||
    state.explicitHuntLaneFamilies.length > 0
  ) {
    scopeLogit += 2.2;
  }

  const maxFamilyLogit = Math.max(
    ...ALL_MISSION_FAMILIES.map((f) => familyLogits[f]),
  );
  if (maxFamilyLogit >= 0.85) {
    scopeLogit += 2.6;
  } else if (maxFamilyLogit > -0.8) {
    scopeLogit += 1.4;
  }

  // Vague / non-security / chitchat anchors pull null-scope probability down:
  if (!combinedText.trim()) {
    scopeLogit -= 3.0;
  }
  if (
    /\b(wherever\s+they\s+may\s+be|something\s+somewhere|weather\s+today|bake\s+a\s+cake|simulate\s+spice\s+diode|rc\s+lowpass\s+bode)\b/i.test(
      combinedText,
    ) &&
    state.targets.length === 0 &&
    !state.sourceRootConfigured
  ) {
    scopeLogit -= 2.2;
  }

  const pHasConcreteSecurityScope = sigmoid(scopeLogit);

  // Softmax over modality logits derived from family evidence + target kinds:
  const modalityRawLogits: Record<PrimaryTargetModality, number> = {
    web_endpoint: familyLogits.web_api,
    ai_agent_system: Math.max(
      familyLogits.ai_red_team,
      familyLogits.agent_warfare,
    ),
    cloud_control_plane: familyLogits.cloud_infra,
    blockchain_contract: familyLogits.smart_contract,
    source_tree: familyLogits.code_audit,
    repository_pipeline: familyLogits.code_supply_chain,
    cryptographic_material: familyLogits.crypto_secrets,
    compiled_artifact: familyLogits.reverse_binary,
    public_identity_surface: familyLogits.social_osint,
    governance_artifact: familyLogits.reporting_remediation,
  };

  if (state.explicitModelFamily) {
    const preferredModality =
      FAMILY_TO_PRIMARY_MODALITY[state.explicitModelFamily];
    modalityRawLogits[preferredModality] += 0.5;
  }

  const maxModLogit = Math.max(...Object.values(modalityRawLogits));
  let expSum = 0;
  const modalityExps = {} as Record<PrimaryTargetModality, number>;
  for (const modality of ALL_TARGET_MODALITIES) {
    const e = Math.exp(modalityRawLogits[modality] - maxModLogit);
    modalityExps[modality] = e;
    expSum += e;
  }

  const modalityProbabilities = {} as Record<PrimaryTargetModality, number>;
  let primaryModality: PrimaryTargetModality = "web_endpoint";
  let bestModProb = -1;
  for (const modality of ALL_TARGET_MODALITIES) {
    const p = modalityExps[modality] / expSum;
    modalityProbabilities[modality] = p;
    if (p > bestModProb) {
      bestModProb = p;
      primaryModality = modality;
    }
  }

  return {
    pHasConcreteSecurityScope,
    primaryModality,
    modalityProbabilities,
    familyProbabilities,
    providerSource: "offline_calibrated_estimator",
  };
}

export class OfflineCalibratedJudgmentProvider implements MissionJudgmentProvider {
  async evaluate(state: MissionRoutingState): Promise<MissionJudgmentVector> {
    return estimateMissionJudgmentsOffline(state);
  }
}

// =============================================================================
// 6. DETERMINISTIC TRUTH-TABLE COMBINER (LAYER 2 — ZERO REGEXES OR PROMPTS)
// =============================================================================

export function classifyProbabilityBand(
  probability: number,
  thresholds: { yes: number; no: number } = {
    yes: YES_THRESHOLD,
    no: NO_THRESHOLD,
  },
): JudgmentBand {
  if (
    typeof probability !== "number" ||
    !Number.isFinite(probability) ||
    probability < 0 ||
    probability > 1
  ) {
    throw new TypeSafeRouterError(
      "SCHEMA_VALIDATION_ERROR",
      `Probability must be a finite number in [0.0, 1.0], got ${String(probability)}.`,
    );
  }
  if (probability >= thresholds.yes) {
    return "CONFIDENT_YES";
  }
  if (probability <= thresholds.no) {
    return "CONFIDENT_NO";
  }
  return "UNCERTAIN_BAND";
}

/**
 * Layer 2: Pure deterministic truth-table combiner.
 * Operates exclusively on calibrated System One probability judgments—no string
 * matching, no regexes, and no silent coercion.
 */
export function combineMissionRouteFromJudgments(
  judgments: MissionJudgmentVector,
  options?: {
    thresholds?: { yes: number; no: number };
    requestPayload?: TypeSafeJevRequestPayload;
  },
): MissionRouteDecision {
  const thresholds = options?.thresholds ?? {
    yes: YES_THRESHOLD,
    no: NO_THRESHOLD,
  };

  const nullScopeBand = classifyProbabilityBand(
    judgments.pHasConcreteSecurityScope,
    thresholds,
  );

  if (
    !(ALL_TARGET_MODALITIES as readonly string[]).includes(
      judgments.primaryModality,
    )
  ) {
    throw new TypeSafeRouterError(
      "SCHEMA_VALIDATION_ERROR",
      `Invalid primaryModality ${JSON.stringify(judgments.primaryModality)}.`,
    );
  }

  const familyBands = {} as Record<MissionFamily, JudgmentBand>;
  for (const family of ALL_MISSION_FAMILIES) {
    const p = judgments.familyProbabilities[family];
    familyBands[family] = classifyProbabilityBand(p, thresholds);
  }

  // Sort families deterministically by descending probability, breaking exact
  // ties by canonical ALL_MISSION_FAMILIES order:
  const rankedFamilies = [...ALL_MISSION_FAMILIES].sort((a, b) => {
    const diff =
      judgments.familyProbabilities[b] - judgments.familyProbabilities[a];
    if (Math.abs(diff) > 1e-12) {
      return diff;
    }
    return ALL_MISSION_FAMILIES.indexOf(a) - ALL_MISSION_FAMILIES.indexOf(b);
  });

  const confidentFamilies = rankedFamilies.filter(
    (f) => familyBands[f] === "CONFIDENT_YES",
  );
  const uncertainFamilies = rankedFamilies.filter(
    (f) => familyBands[f] === "UNCERTAIN_BAND",
  );
  const excludedFamilies = rankedFamilies.filter(
    (f) => familyBands[f] === "CONFIDENT_NO",
  );

  const modalityFamily = MODALITY_TO_DEFAULT_FAMILY[judgments.primaryModality];

  // ---------------------------------------------------------------------------
  // Truth Table Row 1: Companion null-case Noul <= 0.3 & all families <= 0.3
  // ---------------------------------------------------------------------------
  if (
    nullScopeBand === "CONFIDENT_NO" &&
    confidentFamilies.length === 0 &&
    uncertainFamilies.length === 0
  ) {
    return {
      primaryFamily: "web_api",
      selectedFamilies: ["web_api"],
      confidentFamilies,
      uncertainFamilies,
      excludedFamilies,
      nullScopeBand,
      familyBands,
      routeConfidence: "fallback_null_scope",
      fanOutStrategy: "fallback_default",
      truthTableRow: "null_scope_fallback",
      requiresScopeClarification: true,
      rationale: `Companion null-case Noul settled NO (P=${judgments.pHasConcreteSecurityScope.toFixed(2)} <= ${thresholds.no}) and all 11 mission families scored <= ${thresholds.no}; routing to safe fallback web_api with scope-clarification flag.`,
      judgments,
      requestPayload: options?.requestPayload,
    };
  }

  // ---------------------------------------------------------------------------
  // Truth Table Row 2: Exactly 1 confident family (>= 0.7), 0 uncertain
  // ---------------------------------------------------------------------------
  if (confidentFamilies.length === 1 && uncertainFamilies.length === 0) {
    const primary = confidentFamilies[0];
    return {
      primaryFamily: primary,
      selectedFamilies: [primary],
      confidentFamilies,
      uncertainFamilies,
      excludedFamilies,
      nullScopeBand,
      familyBands,
      routeConfidence: "confident_primary",
      fanOutStrategy: "single_lane",
      truthTableRow: "confident_single_family",
      requiresScopeClarification: nullScopeBand === "CONFIDENT_NO",
      rationale: `Single confident family ${primary} (P=${judgments.familyProbabilities[primary].toFixed(2)} >= ${thresholds.yes}) with all other families <= ${thresholds.no}.`,
      judgments,
      requestPayload: options?.requestPayload,
    };
  }

  // ---------------------------------------------------------------------------
  // Truth Table Row 3: 1 confident family (>= 0.7) + >= 1 uncertain (0.3, 0.7)
  // ---------------------------------------------------------------------------
  if (confidentFamilies.length === 1 && uncertainFamilies.length >= 1) {
    const primary = confidentFamilies[0];
    const secondaryUncertain = uncertainFamilies.slice(0, 2);
    const selectedFamilies = [primary, ...secondaryUncertain];
    return {
      primaryFamily: primary,
      selectedFamilies,
      confidentFamilies,
      uncertainFamilies,
      excludedFamilies,
      nullScopeBand,
      familyBands,
      routeConfidence: "confident_with_uncertain_secondary",
      fanOutStrategy: "primary_plus_uncertain_secondary",
      truthTableRow: "confident_with_uncertain_secondary",
      requiresScopeClarification: nullScopeBand === "CONFIDENT_NO",
      rationale: `Confident primary ${primary} (P=${judgments.familyProbabilities[primary].toFixed(2)}) augmented with exploratory secondary lane(s) [${secondaryUncertain.join(", ")}] from the (${thresholds.no}, ${thresholds.yes}) uncertain band.`,
      judgments,
      requestPayload: options?.requestPayload,
    };
  }

  // ---------------------------------------------------------------------------
  // Truth Table Row 4: Multiple confident families (>= 0.7)
  // ---------------------------------------------------------------------------
  if (confidentFamilies.length >= 2) {
    const topProb = judgments.familyProbabilities[confidentFamilies[0]];
    let primary = confidentFamilies[0];
    // Near-tie breaker using modality Choice when within 0.03 probability:
    if (
      confidentFamilies.includes(modalityFamily) &&
      topProb - judgments.familyProbabilities[modalityFamily] <= 0.03
    ) {
      primary = modalityFamily;
    }
    const orderedSelected: MissionFamily[] = [
      primary,
      ...confidentFamilies.filter((f) => f !== primary),
    ];
    return {
      primaryFamily: primary,
      selectedFamilies: orderedSelected,
      confidentFamilies,
      uncertainFamilies,
      excludedFamilies,
      nullScopeBand,
      familyBands,
      routeConfidence: "confident_multi_lane",
      fanOutStrategy: "multi_lane_confident",
      truthTableRow: "confident_multi_family",
      requiresScopeClarification: nullScopeBand === "CONFIDENT_NO",
      rationale: `Multi-domain mission with ${confidentFamilies.length} confident families >= ${thresholds.yes} ([${orderedSelected.join(", ")}]); primary=${primary}.`,
      judgments,
      requestPayload: options?.requestPayload,
    };
  }

  // ---------------------------------------------------------------------------
  // Truth Table Row 5: 0 confident families, >= 1 uncertain family in (0.3, 0.7)
  // ---------------------------------------------------------------------------
  if (uncertainFamilies.length >= 1) {
    const topUncertainProb =
      judgments.familyProbabilities[uncertainFamilies[0]];
    let leadFamily = uncertainFamilies[0];
    // Use Choice modality to break close ties inside the uncertain band:
    if (
      uncertainFamilies.includes(modalityFamily) &&
      topUncertainProb - judgments.familyProbabilities[modalityFamily] <= 0.1
    ) {
      leadFamily = modalityFamily;
    }
    const orderedUncertain: MissionFamily[] = [
      leadFamily,
      ...uncertainFamilies.filter((f) => f !== leadFamily),
    ];
    const selectedFamilies = orderedUncertain.slice(0, 3);
    const fanOutStrategy: RouteFanOutStrategy =
      selectedFamilies.length > 1
        ? "uncertain_multi_lane_fanout"
        : "uncertain_single_lane_probe";

    return {
      primaryFamily: leadFamily,
      selectedFamilies,
      confidentFamilies,
      uncertainFamilies,
      excludedFamilies,
      nullScopeBand,
      familyBands,
      routeConfidence: "uncertain_fanout",
      fanOutStrategy,
      truthTableRow: "uncertain_band_fanout",
      requiresScopeClarification: nullScopeBand !== "CONFIDENT_YES",
      rationale: `No family exceeded ${thresholds.yes}; ${uncertainFamilies.length} family(ies) landed in (${thresholds.no}, ${thresholds.yes}) uncertain band ([${uncertainFamilies.join(", ")}]). Fanning out across [${selectedFamilies.join(", ")}] with lead=${leadFamily}.`,
      judgments,
      requestPayload: options?.requestPayload,
    };
  }

  // ---------------------------------------------------------------------------
  // Truth Table Row 6: Scope > 0.3, but all specific family Nouls <= 0.3
  // ---------------------------------------------------------------------------
  return {
    primaryFamily: modalityFamily,
    selectedFamilies: [modalityFamily],
    confidentFamilies,
    uncertainFamilies,
    excludedFamilies,
    nullScopeBand,
    familyBands,
    routeConfidence:
      nullScopeBand === "UNCERTAIN_BAND"
        ? "fallback_null_scope"
        : "modality_tiebreak_fallback",
    fanOutStrategy: "fallback_default",
    truthTableRow: "modality_tiebreak_fallback",
    requiresScopeClarification: true,
    rationale: `Scope Noul P=${judgments.pHasConcreteSecurityScope.toFixed(2)} > ${thresholds.no} while all family Nouls <= ${thresholds.no}; selecting modality fallback ${modalityFamily}.`,
    judgments,
    requestPayload: options?.requestPayload,
  };
}

// =============================================================================
// 7. HIGH-LEVEL ORCHESTRATION HELPERS (OFFLINE SYNC & PROVIDER ASYNC)
// =============================================================================

export function evaluateMissionRouteOffline(
  input: BuildMissionRoutingStateInput,
): MissionRouteDecision {
  const state = buildMissionRoutingState(input);
  const requestPayload = buildTypeSafeMissionRequestPayload(state);
  const judgments = estimateMissionJudgmentsOffline(state);
  return combineMissionRouteFromJudgments(judgments, { requestPayload });
}

export async function evaluateMissionRouteAsync(
  input: BuildMissionRoutingStateInput,
  provider: MissionJudgmentProvider,
): Promise<MissionRouteDecision> {
  const state = buildMissionRoutingState(input);
  const requestPayload = buildTypeSafeMissionRequestPayload(state);
  const judgments = await provider.evaluate(state);
  return combineMissionRouteFromJudgments(judgments, { requestPayload });
}

/**
 * Deterministically map a calibrated `MissionRouteDecision` (and optional
 * `MissionRoutingState`) to the primary built-in Arsenal scanners for execution.
 */
export function recommendToolsForMissionRoute(
  decision: MissionRouteDecision,
  state?: MissionRoutingState,
): string[] {
  const tools = new Set<string>();

  for (const family of decision.selectedFamilies) {
    if (family === "reverse_binary") {
      tools.add("firmware_audit_scan");
      tools.add("binary_sink_scan");
      tools.add("reap_playbook");
      tools.add("r2_analyze");
    } else if (family === "code_audit") {
      tools.add("code_audit_scan");
      tools.add("binary_sink_scan");
    } else if (family === "crypto_secrets") {
      tools.add("firmware_audit_scan");
      tools.add("jwt_decode");
    } else if (family === "web_api") {
      tools.add("http_request");
      tools.add("header_analysis");
      tools.add("js_analyze");
    } else if (family === "reporting_remediation") {
      tools.add("kev_check");
      tools.add("cve_lookup");
    }
  }

  if (
    state &&
    state.targets.some((t) =>
      /\.(hex|ihex|srec|s19|s28|s37|mot|dts|dtsi|dtb|uimage|itb|kicad_sch|kicad_pcb)$/i.test(
        t.address,
      ),
    )
  ) {
    return [
      "firmware_audit_scan",
      ...Array.from(tools).filter((t) => t !== "firmware_audit_scan"),
    ];
  }

  return Array.from(tools);
}
