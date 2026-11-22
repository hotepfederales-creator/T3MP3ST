/**
 * T3MP3ST Multi-Artifact Embedded Firmware & Hardware EDA CVE/CWE Benchmark (`firmware-vuln-bench`)
 *
 * Programmatically synthesizes a realistic multi-file embedded firmware & hardware EDA corpus
 * (with planted CWE vulnerabilities AND hardened production negative controls) inside an isolated
 * workspace, executes `firmware_audit_scan` + `reap_playbook` + `OpGeneral` / `typesafe-router`,
 * and computes deterministic scorecards:
 *   - Per-category & aggregate Precision, Recall, F1, False-Positive Rate (FPR on hardened controls)
 *   - CVSS-Weighted Recall & Net Score (`--cvss-weighted`)
 *   - Dual-Judge Cross-Validation (`--multi-judge`: Structural/Location Gate Judge vs. Playbook/Redaction Judge)
 *   - CWE Coverage Heatmap (`CWE-78`, `CWE-119`, `CWE-120`, `CWE-353`, `CWE-798`, `CWE-1244`)
 *   - `reap_playbook` Triage Accuracy (finding-level skill attribution + query-level playbook ranking)
 *   - `OpGeneral` / `typesafe-router` Calibrated Mission-Routing Accuracy (including non-firmware controls)
 *   - Strict Zero-Unredacted-Secret verification across all findings, JSON reports, and Markdown scorecards
 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  analyzeFirmwareBuffer,
  createToolContext,
  firmwareAuditScanTool,
  getReapPlaybookById,
  selectReapPlaybooks,
  type FirmwareArtifactFormat,
  type FirmwareAuditFinding,
  type ReapFirmwarePlaybookSkill,
  type ReapSelectionQuery,
} from "../arsenal/index.js";
import {
  OpGeneral,
  YES_THRESHOLD,
  buildMissionRoutingState,
  evaluateMissionRouteOffline,
  recommendToolsForMissionRoute,
  type Directive,
  type OpPlanTarget,
} from "../general/index.js";
import type { LLMBackbone } from "../llm/index.js";
import type { MissionFamily } from "../resources/index.js";
import type { Severity } from "../types/index.js";

// =============================================================================
// 1. TYPES & CONSTANTS
// =============================================================================

export type FirmwareBenchCategoryId =
  | "automotive_ihex"
  | "industrial_srec_elf"
  | "linux_soc_uboot_dts"
  | "kicad_mixed_signal_eda";

export type BenchTrackedCwe =
  | "CWE-78"
  | "CWE-119"
  | "CWE-120"
  | "CWE-353"
  | "CWE-798"
  | "CWE-1244";

export const REQUIRED_BENCH_CWES: readonly BenchTrackedCwe[] = [
  "CWE-78",
  "CWE-119",
  "CWE-120",
  "CWE-353",
  "CWE-798",
  "CWE-1244",
] as const;

export const CWE_LABELS: Readonly<Record<BenchTrackedCwe, string>> = {
  "CWE-78": "OS / Bootloader Command Injection",
  "CWE-119": "Memory Buffer & W^X / ASLR Protection",
  "CWE-120": "Classic Buffer Copy Without Size Check",
  "CWE-353": "Missing Integrity Check / Unsigned Image",
  "CWE-798": "Use of Hard-coded Credentials / Keys",
  "CWE-1244": "Internal Asset Exposed to Unsafe Debug",
};

export const CATEGORY_LABELS: Readonly<Record<FirmwareBenchCategoryId, string>> =
  {
    automotive_ihex: "Automotive / BMS Intel HEX Bootloader",
    industrial_srec_elf: "Industrial Gateway S-Record & ARM ELF32",
    linux_soc_uboot_dts: "Linux SoC U-Boot & Device-Tree (.dts)",
    kicad_mixed_signal_eda: "Mixed-Signal Power & IoT KiCad EDA",
  };

export interface GroundTruthFirmwareVuln {
  readonly id: string;
  readonly description: string;
  readonly ruleId: string;
  readonly cwePrimary: BenchTrackedCwe;
  readonly expectedCwes: readonly BenchTrackedCwe[];
  readonly severity: Severity;
  readonly cvss: number;
  readonly expectedReapPlaybook: ReapFirmwarePlaybookSkill;
  readonly expectedAddress?: string;
  readonly expectedLine?: number;
  readonly expectedDesignators?: readonly string[];
  readonly requiresRedaction?: boolean;
}

export interface GeneratedFirmwareArtifact {
  readonly id: string;
  readonly category: FirmwareBenchCategoryId;
  /** Corpus-relative POSIX path (deterministic across OS & temp dirs). */
  readonly relativePath: string;
  /** Absolute path inside the temporary corpus workspace. */
  readonly absolutePath: string;
  readonly expectedFormat: FirmwareArtifactFormat;
  readonly isNegativeControl: boolean;
  readonly description: string;
  readonly groundTruth: readonly GroundTruthFirmwareVuln[];
}

export interface ReapTriageBenchCase {
  readonly id: string;
  readonly category: FirmwareBenchCategoryId;
  readonly query: ReapSelectionQuery;
  readonly expectedPlaybookId: string;
  readonly expectedSkillName: ReapFirmwarePlaybookSkill;
}

export interface MissionRoutingBenchCase {
  readonly id: string;
  readonly description: string;
  readonly isNegativeControl: boolean;
  readonly directive: Directive;
  readonly targets: readonly OpPlanTarget[];
  readonly expectedPrimaryFamily: MissionFamily;
  readonly expectedFirmwareToolSelected: boolean;
}

export interface GeneratedFirmwareCorpus {
  readonly rootDir: string;
  readonly artifacts: readonly GeneratedFirmwareArtifact[];
  readonly reapTriageCases: readonly ReapTriageBenchCase[];
  readonly missionRoutingCases: readonly MissionRoutingBenchCase[];
  /**
   * Raw synthetic test-only secret strings planted inside vulnerable firmware
   * fixtures. Never copied into reports; used strictly to assert 0 leaks.
   */
  readonly plantedRawSecrets: readonly string[];
  cleanup(): void;
}

export interface FindingGateEvaluation {
  readonly ruleMatch: boolean;
  readonly cweMatch: boolean;
  readonly locationOrDesignatorMatch: boolean;
  readonly playbookMatch: boolean;
  readonly redactionClean: boolean;
  readonly gatesPassed: number;
  readonly maxGates: number;
  readonly isTruePositive: boolean;
}

export interface FindingJudgeVerdict {
  readonly structuralJudgeValid: boolean;
  readonly hygienePlaybookJudgeValid: boolean;
  readonly consensusValid: boolean;
  readonly disagreement: boolean;
  readonly modifier: number;
}

export interface MatchedFindingDetail {
  readonly vulnId: string;
  readonly ruleId: string;
  readonly cwePrimary: BenchTrackedCwe;
  readonly cvss: number;
  readonly cvssAwarded: number;
  readonly reapPlaybookId: ReapFirmwarePlaybookSkill;
  readonly expectedReapPlaybook: ReapFirmwarePlaybookSkill;
  readonly evidence: string;
  readonly gates: FindingGateEvaluation;
  readonly judge: FindingJudgeVerdict;
}

export interface UnmatchedFindingDetail {
  readonly ruleId: string;
  readonly cwe: readonly string[];
  readonly title: string;
  readonly evidence: string;
  readonly judge: FindingJudgeVerdict;
}

export interface ScoredFirmwareArtifact {
  readonly artifactId: string;
  readonly category: FirmwareBenchCategoryId;
  readonly relativePath: string;
  readonly detectedFormat: FirmwareArtifactFormat;
  readonly expectedFormat: FirmwareArtifactFormat;
  readonly formatMatched: boolean;
  readonly isNegativeControl: boolean;
  readonly toolExecutionSucceeded: boolean;
  readonly expectedCount: number;
  readonly findingsCount: number;
  readonly truePositives: number;
  readonly falsePositives: number;
  readonly falseNegatives: number;
  readonly cvssPossible: number;
  readonly cvssAwarded: number;
  readonly judgeDisagreements: number;
  readonly matchedFindings: readonly MatchedFindingDetail[];
  readonly falsePositiveFindings: readonly UnmatchedFindingDetail[];
  readonly missedVulnIds: readonly string[];
}

export interface CategoryBenchMetrics {
  readonly category: FirmwareBenchCategoryId;
  readonly label: string;
  readonly vulnerableArtifacts: number;
  readonly negativeControlArtifacts: number;
  readonly contaminatedControls: number;
  readonly truePositives: number;
  readonly falsePositives: number;
  readonly falsePositivesOnControls: number;
  readonly falseNegatives: number;
  readonly precision: number;
  readonly recall: number;
  readonly f1: number;
  readonly falsePositiveRate: number;
  readonly cvssAwarded: number;
  readonly cvssPossible: number;
  readonly cvssWeightedRecall: number;
}

export interface CweCoverageHeatmapRow {
  readonly cwe: BenchTrackedCwe;
  readonly label: string;
  readonly total: number;
  readonly detected: number;
  readonly missed: number;
  readonly recall: number;
  readonly cvssAwarded: number;
  readonly cvssPossible: number;
  readonly bar: string;
  readonly blindSpot: boolean;
  readonly missedVulnIds: readonly string[];
}

export interface ReapTriageBenchSummary {
  readonly findingPlaybookChecks: number;
  readonly findingPlaybookCorrect: number;
  readonly findingPlaybookAccuracy: number;
  readonly queryCasesTotal: number;
  readonly queryCasesCorrect: number;
  readonly queryTopMatchAccuracy: number;
  readonly combinedAccuracy: number;
  readonly unresolvedPlaybookIds: readonly string[];
}

export interface MissionRoutingCaseResult {
  readonly id: string;
  readonly isNegativeControl: boolean;
  readonly expectedPrimaryFamily: MissionFamily;
  readonly actualPrimaryFamily: MissionFamily;
  readonly reverseBinaryProbability: number;
  readonly expectedFirmwareToolSelected: boolean;
  readonly actualFirmwareToolSelected: boolean;
  readonly opGeneralFamilyMatched: boolean;
  readonly opGeneralToolPlanMatched: boolean;
  readonly passed: boolean;
}

export interface MissionRoutingBenchSummary {
  readonly totalCases: number;
  readonly passedCases: number;
  readonly accuracy: number;
  readonly firmwareCasesAccuracy: number;
  readonly negativeControlCasesAccuracy: number;
  readonly results: readonly MissionRoutingCaseResult[];
}

export interface SecretRedactionAuditSummary {
  readonly plantedSecretCount: number;
  readonly redactedFindingCount: number;
  readonly unredactedLeakCount: number;
  readonly leakedIdentifiers: readonly string[];
  readonly passed: boolean;
}

export interface FirmwareBenchAggregateMetrics {
  readonly totalArtifacts: number;
  readonly vulnerableArtifacts: number;
  readonly negativeControlArtifacts: number;
  readonly contaminatedControls: number;
  readonly totalGroundTruthVulns: number;
  readonly totalFindingsEmitted: number;
  readonly truePositives: number;
  readonly falsePositives: number;
  readonly falsePositivesOnControls: number;
  readonly falseNegatives: number;
  readonly precision: number;
  readonly recall: number;
  readonly f1: number;
  readonly falsePositiveRate: number;
  readonly cvssAwarded: number;
  readonly cvssPossible: number;
  readonly cvssWeightedRecall: number;
  readonly primaryScorePercent: number;
  readonly judgeAgreementRate: number;
  readonly judgeDisagreements: number;
}

export interface FirmwareBenchScorecard {
  readonly schema: "t3mp3st.bench.firmware-vuln/v1";
  readonly scoringMode: "flat" | "cvss_weighted";
  readonly multiJudgeEnabled: boolean;
  readonly aggregate: FirmwareBenchAggregateMetrics;
  readonly categories: readonly CategoryBenchMetrics[];
  readonly cweHeatmap: readonly CweCoverageHeatmapRow[];
  readonly reapTriage: ReapTriageBenchSummary;
  readonly missionRouting: MissionRoutingBenchSummary;
  readonly secretRedaction: SecretRedactionAuditSummary;
  readonly artifacts: readonly ScoredFirmwareArtifact[];
}

export interface FirmwareBenchOptions {
  readonly rootDir?: string;
  readonly keepWorkspace?: boolean;
  readonly category?: FirmwareBenchCategoryId;
  readonly cvssWeighted?: boolean;
  readonly multiJudge?: boolean;
  /** Optional custom detector hook for adversarial / regression unit tests. */
  readonly detectorOverride?: (
    buf: Buffer,
    filePath: string,
  ) => readonly FirmwareAuditFinding[];
}

export interface FirmwareBenchCliArgs {
  readonly cvssWeighted: boolean;
  readonly multiJudge: boolean;
  readonly category?: FirmwareBenchCategoryId;
  readonly jsonOut?: string;
  readonly markdownOut?: string;
  readonly selfTest: boolean;
}

export interface FirmwareBenchCliResult {
  readonly scorecard: FirmwareBenchScorecard;
  readonly json: string;
  readonly markdown: string;
}

function roundMetric(value: number, decimals = 4): number {
  const factor = 10 ** decimals;
  return Math.round(value * factor) / factor;
}

// =============================================================================
// 2. BINARY / HEX / S-RECORD / ELF32 ARTIFACT ENCODERS
// =============================================================================

/** Encode a valid Intel HEX record with two's-complement checksum. */
export function encodeIntelHexRecord(
  offset16: number,
  recordType: number,
  data: Uint8Array | Buffer,
): string {
  const len = data.length & 0xff;
  const header = [
    len,
    (offset16 >> 8) & 0xff,
    offset16 & 0xff,
    recordType & 0xff,
  ];
  let sum = 0;
  for (const b of header) sum = (sum + b) & 0xff;
  for (const b of data) sum = (sum + b) & 0xff;
  const checksum = (0x100 - sum) & 0xff;
  const raw = Buffer.concat([
    Buffer.from(header),
    Buffer.from(data),
    Buffer.from([checksum]),
  ]);
  return `:${raw.toString("hex").toUpperCase()}`;
}

/** Encode a valid Motorola S-Record with one's-complement checksum. */
export function encodeMotorolaSrecRecord(
  typeDigit: "0" | "1" | "2" | "3" | "7" | "8" | "9",
  address: number,
  data: Uint8Array | Buffer,
): string {
  const addrLen =
    typeDigit === "3" || typeDigit === "7"
      ? 4
      : typeDigit === "2" || typeDigit === "8"
        ? 3
        : 2;
  const addrBytes: number[] = [];
  let rem = Math.max(0, Math.floor(address));
  for (let i = 0; i < addrLen; i++) {
    addrBytes.unshift(rem & 0xff);
    rem = Math.floor(rem / 256);
  }
  const count = (addrBytes.length + data.length + 1) & 0xff;
  const body = [count, ...addrBytes, ...data];
  let sum = 0;
  for (const b of body) sum = (sum + b) & 0xff;
  const checksum = ~sum & 0xff;
  const hex = Buffer.from([...body, checksum])
    .toString("hex")
    .toUpperCase();
  return `S${typeDigit}${hex}`;
}

/** Build a minimal standards-compliant 32-bit ARM ELF binary with PT_LOAD + PT_GNU_STACK. */
export function buildSyntheticArmElf32(options: {
  elfType: 2 | 3; // 2 = ET_EXEC (non-PIE), 3 = ET_DYN (PIE)
  gnuStackFlags: number; // 0x7 = RWX, 0x6 = RW-
  loadVaddr: number;
  payload: Buffer;
}): Buffer {
  const ehdrSize = 52;
  const phentSize = 32;
  const phnum = 2;
  const payloadOffset = 0x100;
  const buf = Buffer.alloc(payloadOffset + options.payload.length, 0);

  // ELF32 little-endian ARM (EM_ARM = 0x28)
  buf[0] = 0x7f;
  buf[1] = 0x45;
  buf[2] = 0x4c;
  buf[3] = 0x46;
  buf[4] = 1; // ELFCLASS32
  buf[5] = 1; // ELFDATA2LSB
  buf[6] = 1; // EV_CURRENT

  buf.writeUInt16LE(options.elfType, 16);
  buf.writeUInt16LE(0x28, 18); // EM_ARM
  buf.writeUInt32LE(1, 20);
  buf.writeUInt32LE(options.loadVaddr >>> 0, 24); // e_entry
  buf.writeUInt32LE(ehdrSize, 28); // e_phoff
  buf.writeUInt16LE(ehdrSize, 40); // e_ehsize
  buf.writeUInt16LE(phentSize, 42); // e_phentsize
  buf.writeUInt16LE(phnum, 44); // e_phnum

  // PH0: PT_LOAD (PF_R | PF_X = 0x5)
  const ph0 = ehdrSize;
  buf.writeUInt32LE(1, ph0 + 0);
  buf.writeUInt32LE(payloadOffset, ph0 + 4);
  buf.writeUInt32LE(options.loadVaddr >>> 0, ph0 + 8);
  buf.writeUInt32LE(options.loadVaddr >>> 0, ph0 + 12);
  buf.writeUInt32LE(options.payload.length, ph0 + 16);
  buf.writeUInt32LE(options.payload.length, ph0 + 20);
  buf.writeUInt32LE(0x5, ph0 + 24);

  // PH1: PT_GNU_STACK (0x6474e551)
  const ph1 = ehdrSize + phentSize;
  buf.writeUInt32LE(0x6474e551, ph1 + 0);
  buf.writeUInt32LE(options.gnuStackFlags >>> 0, ph1 + 24);

  options.payload.copy(buf, payloadOffset);
  return buf;
}

// =============================================================================
// 3. GROUND-TRUTH MULTI-ARTIFACT EMBEDDED & EDA CORPUS GENERATOR
// =============================================================================

export function generateFirmwareBenchCorpus(
  explicitRootDir?: string,
): GeneratedFirmwareCorpus {
  const ownsWorkspace = !explicitRootDir;
  const rootDir = explicitRootDir
    ? resolve(explicitRootDir)
    : mkdtempSync(join(tmpdir(), "t3mp3st-fw-vuln-bench-"));

  mkdirSync(rootDir, { recursive: true });

  // Runtime-synthesized test-only canary secrets (never stored as static credential literals)
  const syntheticEcPemHeader = ["-----BEGIN EC", "PRIVATE KEY-----"].join(" ");
  const syntheticEcPemFooter = ["-----END EC", "PRIVATE KEY-----"].join(" ");
  const syntheticEcKeyMaterial = [
    "MHcCAQEEIPlcMqttBenchCanary",
    "9944112233AABBCCDDEEFF7788",
    "oAoGCCqGSM49AwEHoUQDQgAE",
  ].join("");
  const syntheticMqttTlsKeySecret = [
    "MqttTlsBenchKey",
    "CanarySecretValue",
    "884219XZ",
  ].join("_");

  const plantedRawSecrets: string[] = [
    syntheticEcKeyMaterial,
    syntheticMqttTlsKeySecret,
  ];

  const writeArtifactFile = (
    relPath: string,
    contents: string | Buffer,
  ): string => {
    const absPath = join(rootDir, ...relPath.split("/"));
    mkdirSync(dirname(absPath), { recursive: true });
    if (typeof contents === "string") {
      writeFileSync(absPath, contents, "utf8");
    } else {
      writeFileSync(absPath, contents);
    }
    return absPath;
  };

  const artifacts: GeneratedFirmwareArtifact[] = [];

  // ---------------------------------------------------------------------------
  // Family 1: Automotive / Power-Controller Intel HEX Bootloader
  // ---------------------------------------------------------------------------
  const validCrcRecord = encodeIntelHexRecord(
    0x0400,
    0x00,
    Buffer.from("CAN_BOOT_VECTOR\0", "ascii"),
  );
  const corruptedHexRecord =
    validCrcRecord.slice(0, -2) +
    (validCrcRecord.endsWith("FF") ? "00" : "FF");

  const bmsBootHex = [
    "; Automotive BMS Bootloader v2.4 (STM32G4 Flash @ 0x08000000)",
    encodeIntelHexRecord(0x0000, 0x04, Buffer.from([0x08, 0x00])),
    encodeIntelHexRecord(
      0x0100,
      0x00,
      Buffer.from("BMS_CAN_BOOT_V24\0", "ascii"),
    ),
    encodeIntelHexRecord(
      0x0120,
      0x00,
      Buffer.from(
        'sprintf(can_diag_buf, "CELL_%u:%s", idx, rx_frame);\0',
        "ascii",
      ),
    ),
    corruptedHexRecord,
    encodeIntelHexRecord(0x0000, 0x05, Buffer.from([0x08, 0x00, 0x01, 0x01])),
    encodeIntelHexRecord(0x0000, 0x01, Buffer.alloc(0)),
  ].join("\n");

  artifacts.push({
    id: "bms_boot_hex",
    category: "automotive_ihex",
    relativePath: "automotive/bms_boot.hex",
    absolutePath: writeArtifactFile("automotive/bms_boot.hex", bmsBootHex),
    expectedFormat: "ihex",
    isNegativeControl: false,
    description:
      "Automotive BMS Intel HEX bootloader with corrupted record checksum and unbounded sprintf CAN parser",
    groundTruth: [
      {
        id: "BMS-HEX-01",
        description:
          "Corrupted Intel HEX record checksum at 0x08000400 (missing flash verification)",
        ruleId: "FW-HEX-CHECKSUM",
        cwePrimary: "CWE-353",
        expectedCwes: ["CWE-353"],
        severity: "high",
        cvss: 7.5,
        expectedReapPlaybook: "reap-07-firmware-and-embedded",
        expectedAddress: "0x08000400",
        expectedLine: 5,
      },
      {
        id: "BMS-HEX-02",
        description:
          "Unbounded sprintf() CAN diagnostic frame parser at 0x08000120",
        ruleId: "FW-SINK-STRCPY-SPRINTF",
        cwePrimary: "CWE-120",
        expectedCwes: ["CWE-120", "CWE-119"],
        severity: "high",
        cvss: 8.2,
        expectedReapPlaybook: "reap-10-vulnerability-research",
        expectedAddress: "0x08000120",
      },
    ],
  });

  // Negative Control 1: Benign CRC32 + NTC voltage calibration lookup tables in Intel HEX
  const crc32TableBytes = Buffer.from([
    0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77, 0x2c, 0x61, 0x0e, 0xee,
    0xba, 0x51, 0x09, 0x99,
  ]);
  const bmsCalCleanHex = [
    "; Automotive BMS Calibration & IEEE-802.3 CRC32 Tables (Verified)",
    encodeIntelHexRecord(0x0000, 0x04, Buffer.from([0x08, 0x01])),
    encodeIntelHexRecord(0x0000, 0x00, crc32TableBytes),
    encodeIntelHexRecord(
      0x0040,
      0x00,
      Buffer.from("BMS_OCV_NTC_CAL_V4_CRC_OK\0", "ascii"),
    ),
    encodeIntelHexRecord(
      0x0080,
      0x00,
      Buffer.from(
        'snprintf(can_tx, sizeof(can_tx), "SOC=%u%%", soc_pct);\0',
        "ascii",
      ),
    ),
    encodeIntelHexRecord(0x0000, 0x05, Buffer.from([0x08, 0x01, 0x00, 0x41])),
    encodeIntelHexRecord(0x0000, 0x01, Buffer.alloc(0)),
  ].join("\n");

  artifacts.push({
    id: "bms_cal_tables_clean_hex",
    category: "automotive_ihex",
    relativePath: "automotive/bms_cal_tables_clean.hex",
    absolutePath: writeArtifactFile(
      "automotive/bms_cal_tables_clean.hex",
      bmsCalCleanHex,
    ),
    expectedFormat: "ihex",
    isNegativeControl: true,
    description:
      "Hardened BMS calibration & CRC32 lookup tables with valid checksums and bounded snprintf",
    groundTruth: [],
  });

  // ---------------------------------------------------------------------------
  // Family 2: Industrial Gateway Motorola S-Record + ARM ELF32 Daemon
  // ---------------------------------------------------------------------------
  const srecPemPayload = Buffer.from(
    `${syntheticEcPemHeader} ${syntheticEcKeyMaterial} ${syntheticEcPemFooter}\0`,
    "ascii",
  );
  const plcAgentSrec = [
    encodeMotorolaSrecRecord("0", 0x0000, Buffer.from("PLC_GW_V3", "ascii")),
    encodeMotorolaSrecRecord(
      "3",
      0x20001000,
      Buffer.from('popen(modbus_diag_cmd, "r");\0', "ascii"),
    ),
    encodeMotorolaSrecRecord("3", 0x20001100, srecPemPayload),
    encodeMotorolaSrecRecord("7", 0x20001000, Buffer.alloc(0)),
  ].join("\n");

  artifacts.push({
    id: "plc_agent_srec",
    category: "industrial_srec_elf",
    relativePath: "industrial/plc_agent.srec",
    absolutePath: writeArtifactFile("industrial/plc_agent.srec", plcAgentSrec),
    expectedFormat: "srec",
    isNegativeControl: false,
    description:
      "Industrial PLC Motorola S-Record firmware with popen() diagnostic sink and hardcoded MQTT TLS EC private key",
    groundTruth: [
      {
        id: "IND-SREC-01",
        description:
          "Hardcoded MQTT mTLS EC private key embedded in Motorola S-Record @ 0x20001100",
        ruleId: "FW-PRIVATE-KEY",
        cwePrimary: "CWE-798",
        expectedCwes: ["CWE-798"],
        severity: "critical",
        cvss: 9.4,
        expectedReapPlaybook: "reap-07-firmware-and-embedded",
        expectedAddress: "0x20001100",
        requiresRedaction: true,
      },
      {
        id: "IND-SREC-02",
        description:
          "Command injection via popen() Modbus diagnostic handler @ 0x20001000",
        ruleId: "FW-SINK-CMD-EXEC",
        cwePrimary: "CWE-78",
        expectedCwes: ["CWE-78"],
        severity: "high",
        cvss: 8.6,
        expectedReapPlaybook: "reap-10-vulnerability-research",
        expectedAddress: "0x20001000",
      },
    ],
  });

  const elfSinkStr = 'popen(http_ping_target, "r");\0';
  const elfKeyOffset = 0x00010000 + Buffer.byteLength(elfSinkStr, "ascii");
  const elfKeyAddr = `0x${elfKeyOffset.toString(16).toUpperCase().padStart(8, "0")}`;
  const httpdArmPayload = Buffer.from(
    `${elfSinkStr}mqtt_tls_key="${syntheticMqttTlsKeySecret}"\0`,
    "ascii",
  );
  const httpdArmElf = buildSyntheticArmElf32({
    elfType: 2, // ET_EXEC (non-PIE)
    gnuStackFlags: 0x7, // RWX stack
    loadVaddr: 0x00010000,
    payload: httpdArmPayload,
  });

  artifacts.push({
    id: "httpd_arm_elf",
    category: "industrial_srec_elf",
    relativePath: "industrial/httpd_arm.elf",
    absolutePath: writeArtifactFile("industrial/httpd_arm.elf", httpdArmElf),
    expectedFormat: "elf",
    isNegativeControl: false,
    description:
      "Industrial ARM ELF32 gateway daemon with PT_GNU_STACK RWX, ET_EXEC non-PIE, popen() sink, and hardcoded MQTT TLS key",
    groundTruth: [
      {
        id: "IND-ELF-01",
        description:
          "ARM ELF32 executable stack enabled (PT_GNU_STACK RWX, NX disabled)",
        ruleId: "FW-ELF-EXEC-STACK",
        cwePrimary: "CWE-119",
        expectedCwes: ["CWE-119"],
        severity: "high",
        cvss: 7.8,
        expectedReapPlaybook: "reap-10-vulnerability-research",
        expectedAddress: "0x00010000",
      },
      {
        id: "IND-ELF-02",
        description:
          "ARM ELF32 linked as fixed-address non-PIE executable (ET_EXEC)",
        ruleId: "FW-ELF-NO-PIE",
        cwePrimary: "CWE-119",
        expectedCwes: ["CWE-119"],
        severity: "medium",
        cvss: 5.5,
        expectedReapPlaybook: "reap-10-vulnerability-research",
        expectedAddress: "0x00010000",
      },
      {
        id: "IND-ELF-03",
        description: "Embedded CGI diagnostic popen() command sink @ 0x00010000",
        ruleId: "FW-SINK-CMD-EXEC",
        cwePrimary: "CWE-78",
        expectedCwes: ["CWE-78"],
        severity: "high",
        cvss: 8.6,
        expectedReapPlaybook: "reap-10-vulnerability-research",
        expectedAddress: "0x00010000",
      },
      {
        id: "IND-ELF-04",
        description: `Hardcoded mqtt_tls_key credential in ARM ELF32 @ ${elfKeyAddr}`,
        ruleId: "FW-EMBEDDED-PSK",
        cwePrimary: "CWE-798",
        expectedCwes: ["CWE-798"],
        severity: "high",
        cvss: 8.6,
        expectedReapPlaybook: "reap-07-firmware-and-embedded",
        expectedAddress: elfKeyAddr,
        requiresRedaction: true,
      },
    ],
  });

  // Negative Controls 2a & 2b: Hardened S-Record & Hardened PIE/NX ARM ELF32
  const plcAgentHardenedSrec = [
    encodeMotorolaSrecRecord(
      "0",
      0x0000,
      Buffer.from("PLC_GW_HARDENED", "ascii"),
    ),
    encodeMotorolaSrecRecord(
      "3",
      0x20002000,
      Buffer.from(
        'snprintf(mb_buf, sizeof(mb_buf), "REG=%u", reg_id);\0atecc608_slot=2\0',
        "ascii",
      ),
    ),
    encodeMotorolaSrecRecord("7", 0x20002000, Buffer.alloc(0)),
  ].join("\n");

  artifacts.push({
    id: "plc_agent_hardened_srec",
    category: "industrial_srec_elf",
    relativePath: "industrial/plc_agent_hardened.srec",
    absolutePath: writeArtifactFile(
      "industrial/plc_agent_hardened.srec",
      plcAgentHardenedSrec,
    ),
    expectedFormat: "srec",
    isNegativeControl: true,
    description:
      "Hardened Motorola S-Record firmware with valid checksums, bounded formatting, and ATECC608 hardware key slot",
    groundTruth: [],
  });

  const httpdArmHardenedElf = buildSyntheticArmElf32({
    elfType: 3, // ET_DYN (PIE enabled)
    gnuStackFlags: 0x6, // RW- (NX enabled)
    loadVaddr: 0x00020000,
    payload: Buffer.from(
      'HTTPD_HARDENED_PIE_NX\0snprintf(resp, sizeof(resp), "200 OK");\0tpm2_key_handle=0x81010001\0',
      "ascii",
    ),
  });

  artifacts.push({
    id: "httpd_arm_hardened_elf",
    category: "industrial_srec_elf",
    relativePath: "industrial/httpd_arm_hardened.elf",
    absolutePath: writeArtifactFile(
      "industrial/httpd_arm_hardened.elf",
      httpdArmHardenedElf,
    ),
    expectedFormat: "elf",
    isNegativeControl: true,
    description:
      "Hardened ARM ELF32 PIE daemon (ET_DYN, PT_GNU_STACK RW-, bounded snprintf, TPM2 key handle)",
    groundTruth: [],
  });

  // ---------------------------------------------------------------------------
  // Family 3: Linux SoC U-Boot + Device-Tree (u-boot-env.bin, board.dts)
  // ---------------------------------------------------------------------------
  const ubootEnvVulnerable = Buffer.from(
    [
      "bootdelay=3",
      "baudrate=115200",
      "serverip=192.168.10.50",
      "bootcmd=tftpboot 0x82000000 fitImage && bootm 0x82000000",
      "",
    ].join("\0"),
    "ascii",
  );

  artifacts.push({
    id: "uboot_env_bin",
    category: "linux_soc_uboot_dts",
    relativePath: "linux_soc/u-boot-env.bin",
    absolutePath: writeArtifactFile(
      "linux_soc/u-boot-env.bin",
      ubootEnvVulnerable,
    ),
    expectedFormat: "uboot",
    isNegativeControl: false,
    description:
      "Linux SoC U-Boot environment image with unlocked bootdelay=3 console and unauthenticated tftpboot bootcmd",
    groundTruth: [
      {
        id: "SOC-UBOOT-01",
        description:
          "Unlocked interactive U-Boot autoboot prompt (bootdelay=3 without SHA-256 stop key)",
        ruleId: "FW-UBOOT-CONSOLE-EXPOSED",
        cwePrimary: "CWE-1244",
        expectedCwes: ["CWE-1244"],
        severity: "medium",
        cvss: 6.4,
        expectedReapPlaybook: "reap-07-firmware-and-embedded",
        expectedAddress: "0x00000000",
      },
      {
        id: "SOC-UBOOT-02",
        description:
          "Unauthenticated tftpboot network boot & shell chain in U-Boot bootcmd",
        ruleId: "FW-UBOOT-BOOTCMD-INJECT",
        cwePrimary: "CWE-78",
        expectedCwes: ["CWE-78", "CWE-353"],
        severity: "critical",
        cvss: 9.1,
        expectedReapPlaybook: "reap-07-firmware-and-embedded",
      },
    ],
  });

  const boardVulnerableDts = [
    "/dts-v1/;",
    "/ {",
    '  model = "SoC Edge Gateway Dev Board";',
    '  compatible = "vendor,soc-edge-dev";',
    "  chosen {",
    '    bootargs = "console=ttyAMA0,115200 root=/dev/mtdblock2 rw init=/bin/sh nokaslr";',
    "  };",
    "  partitions {",
    '    compatible = "fixed-partitions";',
    "    #address-cells = <1>;",
    "    #size-cells = <1>;",
    "    partition@0 {",
    '      label = "u-boot";',
    "      reg = <0x00000000 0x00080000>;",
    "    };",
    "    partition@80000 {",
    '      label = "rootfs";',
    "      reg = <0x00080000 0x01f80000>;",
    "      read-only;",
    "    };",
    "  };",
    "};",
  ].join("\n");

  artifacts.push({
    id: "board_dts",
    category: "linux_soc_uboot_dts",
    relativePath: "linux_soc/board.dts",
    absolutePath: writeArtifactFile("linux_soc/board.dts", boardVulnerableDts),
    expectedFormat: "dts",
    isNegativeControl: false,
    description:
      "Linux SoC Device-Tree with init=/bin/sh nokaslr bootargs and writable u-boot MTD partition",
    groundTruth: [
      {
        id: "SOC-DTS-01",
        description:
          "Insecure Device-Tree chosen.bootargs spawning root shell (init=/bin/sh) with KASLR disabled (nokaslr)",
        ruleId: "FW-DTS-INSECURE-BOOTARGS",
        cwePrimary: "CWE-1244",
        expectedCwes: ["CWE-1244", "CWE-119"],
        severity: "critical",
        cvss: 9.0,
        expectedReapPlaybook: "reap-19-kernel-and-driver-exploitation-research",
        expectedLine: 6,
      },
      {
        id: "SOC-DTS-02",
        description:
          'Writable critical MTD bootloader partition ("u-boot" missing read-only property)',
        ruleId: "FW-DTS-WRITABLE-BOOT-PARTITION",
        cwePrimary: "CWE-353",
        expectedCwes: ["CWE-353", "CWE-1244"],
        severity: "medium",
        cvss: 5.8,
        expectedReapPlaybook: "reap-07-firmware-and-embedded",
        expectedLine: 12,
      },
    ],
  });

  // Negative Controls 3a & 3b: Hardened Production .dts + Locked U-Boot Env
  const boardProdHardenedDts = [
    "/dts-v1/;",
    "/ {",
    '  model = "SoC Edge Gateway Production Rev-C (Hardened)";',
    '  compatible = "vendor,soc-edge-prod";',
    "  chosen {",
    '    stdout-path = "serial0:115200n8";',
    '    bootargs = "console=ttyAMA0,115200 root=/dev/mmcblk0p2 ro rootwait quiet panic=10";',
    "  };",
    "  config {",
    "    bootdelay = <-2>;",
    '    u-boot,bootcmd = "bootm 0x82000000#conf-signed-prod";',
    "  };",
    "  partitions {",
    '    compatible = "fixed-partitions";',
    "    #address-cells = <1>;",
    "    #size-cells = <1>;",
    "    partition@0 {",
    '      label = "u-boot";',
    "      reg = <0x00000000 0x00080000>;",
    "      read-only;",
    "    };",
    "    partition@80000 {",
    '      label = "u-boot-env";',
    "      reg = <0x00080000 0x00020000>;",
    "      read-only;",
    "    };",
    "    partition@a0000 {",
    '      label = "factory";',
    "      reg = <0x000a0000 0x00020000>;",
    "      read-only;",
    "    };",
    "    partition@c0000 {",
    '      label = "rootfs";',
    "      reg = <0x000c0000 0x01f40000>;",
    "      read-only;",
    "    };",
    "  };",
    "};",
  ].join("\n");

  artifacts.push({
    id: "board_prod_hardened_dts",
    category: "linux_soc_uboot_dts",
    relativePath: "linux_soc/board_prod_hardened.dts",
    absolutePath: writeArtifactFile(
      "linux_soc/board_prod_hardened.dts",
      boardProdHardenedDts,
    ),
    expectedFormat: "dts",
    isNegativeControl: true,
    description:
      "Hardened production Device-Tree (bootdelay=-2, signed FIT bootm, ro rootfs, read-only MTD boot partitions)",
    groundTruth: [],
  });

  const ubootEnvHardened = Buffer.from(
    [
      "bootdelay=-2",
      "bootstopkeysha256=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      "bootcmd=bootm 0x82000000#conf-signed-prod",
      "verify=yes",
      "",
    ].join("\0"),
    "ascii",
  );

  artifacts.push({
    id: "uboot_env_hardened_bin",
    category: "linux_soc_uboot_dts",
    relativePath: "linux_soc/u-boot-env-hardened.bin",
    absolutePath: writeArtifactFile(
      "linux_soc/u-boot-env-hardened.bin",
      ubootEnvHardened,
    ),
    expectedFormat: "uboot",
    isNegativeControl: true,
    description:
      "Hardened production U-Boot environment (bootdelay=-2, SHA-256 stop key, signed FIT bootm)",
    groundTruth: [],
  });

  // ---------------------------------------------------------------------------
  // Family 4: Mixed-Signal Power & IoT KiCad Board (smart_psu.kicad_sch / .kicad_pcb)
  // ---------------------------------------------------------------------------
  const smartPsuSch = `(kicad_sch (version 20231120) (generator "eeschema")
  (lib_symbols
    (symbol "Connector_Generic:Conn_02x05_Odd_Even"
      (property "Reference" "J" (at 0 0 0))
      (property "Value" "LIB_TEMPLATE_JTAG" (at 0 0 0))
    )
  )
  (symbol (lib_id "Connector_Generic:Conn_02x05_Odd_Even") (at 90 40 0)
    (property "Reference" "J4" (at 90 36 0))
    (property "Value" "JTAG_ARM10" (at 90 44 0))
    (property "Description" "10-pin Cortex JTAG header" (at 0 0 0))
  )
  (symbol (lib_id "Connector:TestPoint") (at 115 50 0)
    (dnp yes)
    (property "Reference" "TP1" (at 115 48 0))
    (property "Value" "SWDIO" (at 115 52 0))
    (property "Description" "DNP pogo-pin SWDIO test pad" (at 0 0 0))
  )
  (symbol (lib_id "Connector:TestPoint") (at 120 50 0)
    (dnp yes)
    (property "Reference" "TP2" (at 120 48 0))
    (property "Value" "SWCLK" (at 120 52 0))
    (property "Description" "DNP pogo-pin SWCLK test pad" (at 0 0 0))
  )
  (symbol (lib_id "Memory_Flash:W25Q64JVSS") (at 145 65 0)
    (property "Reference" "U3" (at 145 62 0))
    (property "Value" "W25Q64JV_SPI_FLASH" (at 145 68 0))
    (property "Footprint" "Package_SO:SOIC-8_5.23x5.23mm_P1.27mm" (at 0 0 0))
  )
  (symbol (lib_id "Memory_EEPROM:AT24C64") (at 170 65 0)
    (property "Reference" "U4" (at 170 62 0))
    (property "Value" "AT24C64_I2C_EEPROM" (at 170 68 0))
    (property "Footprint" "Package_SO:SOIC-8_3.9x4.9mm_P1.27mm" (at 0 0 0))
  )
  (label "JTAG_TDI" (at 88 40 0))
  (label "JTAG_TDO" (at 88 42 0))
  (label "JTAG_TMS" (at 88 44 0))
  (label "JTAG_TCK" (at 88 46 0))
  (label "SWDIO" (at 114 50 0))
  (label "SWCLK" (at 119 50 0))
  (label "SPI_FLASH_CS" (at 142 64 0))
  (label "SPI_FLASH_CLK" (at 142 66 0))
  (label "SPI_FLASH_MOSI" (at 142 68 0))
  (label "SPI_FLASH_MISO" (at 142 70 0))
  (label "I2C0_SDA" (at 168 64 0))
  (label "I2C0_SCL" (at 168 66 0))
)
`;

  artifacts.push({
    id: "smart_psu_kicad_sch",
    category: "kicad_mixed_signal_eda",
    relativePath: "kicad_iot/smart_psu.kicad_sch",
    absolutePath: writeArtifactFile(
      "kicad_iot/smart_psu.kicad_sch",
      smartPsuSch,
    ),
    expectedFormat: "kicad_sch",
    isNegativeControl: false,
    description:
      "Mixed-signal IoT Smart PSU KiCad schematic with exposed JTAG J4, DNP SWD pogo TP1/TP2, SOIC-8 SPI_FLASH U3, and I2C_EEPROM U4",
    groundTruth: [
      {
        id: "EDA-SCH-01",
        description: "Exposed JTAG debug header J4 on Smart PSU schematic",
        ruleId: "FW-EDA-JTAG-EXPOSED",
        cwePrimary: "CWE-1244",
        expectedCwes: ["CWE-1244"],
        severity: "critical",
        cvss: 8.8,
        expectedReapPlaybook:
          "reap-13-dma-and-hardware-assisted-cheat-research-defensive",
        expectedDesignators: ["J4"],
      },
      {
        id: "EDA-SCH-02",
        description:
          "Unpopulated DNP pogo-pin SWDIO/SWCLK test pads TP1/TP2 on Smart PSU schematic",
        ruleId: "FW-EDA-SWD-EXPOSED",
        cwePrimary: "CWE-1244",
        expectedCwes: ["CWE-1244"],
        severity: "high",
        cvss: 8.4,
        expectedReapPlaybook:
          "reap-13-dma-and-hardware-assisted-cheat-research-defensive",
        expectedDesignators: ["TP1", "TP2"],
      },
      {
        id: "EDA-SCH-03",
        description:
          "External SOIC-8 SPI NOR flash U3 (W25Q64JV) in-circuit clip extraction surface",
        ruleId: "FW-EDA-SPI-FLASH-EXPOSED",
        cwePrimary: "CWE-1244",
        expectedCwes: ["CWE-1244", "CWE-353"],
        severity: "high",
        cvss: 7.8,
        expectedReapPlaybook:
          "reap-13-dma-and-hardware-assisted-cheat-research-defensive",
        expectedDesignators: ["U3"],
      },
      {
        id: "EDA-SCH-04",
        description:
          "Unauthenticated external AT24C64 I2C EEPROM bus U4 on Smart PSU schematic",
        ruleId: "FW-EDA-I2C-EEPROM-EXPOSED",
        cwePrimary: "CWE-1244",
        expectedCwes: ["CWE-1244", "CWE-353"],
        severity: "medium",
        cvss: 6.5,
        expectedReapPlaybook:
          "reap-13-dma-and-hardware-assisted-cheat-research-defensive",
        expectedDesignators: ["U4"],
      },
    ],
  });

  const smartPsuPcb = `(kicad_pcb (version 20231014) (generator "pcbnew")
  (net 1 "/JTAG_TDI")
  (net 2 "/JTAG_TDO")
  (net 3 "/JTAG_TMS")
  (net 4 "/JTAG_TCK")
  (net 5 "/SWDIO")
  (net 6 "/SWCLK")
  (net 7 "/SPI_FLASH_CS")
  (net 8 "/SPI_FLASH_CLK")
  (net 9 "/EEPROM_SDA")
  (net 10 "/EEPROM_SCL")
  (footprint "Connector_PinHeader_1.27mm:PinHeader_2x05_P1.27mm"
    (layer "F.Cu")
    (fp_text reference "J4" (at 0 0))
    (fp_text value "JTAG_ARM10" (at 0 2))
    (pad "1" thru_hole rect (at 0 0) (size 1 1) (net 3 "/JTAG_TMS"))
    (pad "2" thru_hole oval (at 0 1.27) (size 1 1) (net 4 "/JTAG_TCK"))
    (pad "3" thru_hole oval (at 0 2.54) (size 1 1) (net 2 "/JTAG_TDO"))
    (pad "4" thru_hole oval (at 0 3.81) (size 1 1) (net 1 "/JTAG_TDI"))
  )
  (footprint "TestPoint:TestPoint_Pad_D1.0mm"
    (layer "B.Cu")
    (attr smd dnp)
    (property "Reference" "TP1")
    (property "Value" "SWDIO_POGO")
    (pad "1" smd circle (at 10 10) (size 1.0 1.0) (net 5 "/SWDIO"))
  )
  (footprint "TestPoint:TestPoint_Pad_D1.0mm"
    (layer "B.Cu")
    (attr smd dnp)
    (property "Reference" "TP2")
    (property "Value" "SWCLK_POGO")
    (pad "1" smd circle (at 12 10) (size 1.0 1.0) (net 6 "/SWCLK"))
  )
  (footprint "Package_SO:SOIC-8_5.23x5.23mm_P1.27mm"
    (layer "F.Cu")
    (fp_text reference "U3" (at 20 10))
    (fp_text value "W25Q64JV_SPI_FLASH" (at 20 14))
    (pad "1" smd rect (at 18 8) (size 1.5 0.6) (net 7 "/SPI_FLASH_CS"))
    (pad "6" smd rect (at 22 8) (size 1.5 0.6) (net 8 "/SPI_FLASH_CLK"))
  )
  (footprint "Package_SO:SOIC-8_3.9x4.9mm_P1.27mm"
    (layer "F.Cu")
    (fp_text reference "U4" (at 30 10))
    (fp_text value "AT24C64_I2C_EEPROM" (at 30 14))
    (pad "5" smd rect (at 32 8) (size 1.5 0.6) (net 9 "/EEPROM_SDA"))
    (pad "6" smd rect (at 32 9.27) (size 1.5 0.6) (net 10 "/EEPROM_SCL"))
  )
)
`;

  artifacts.push({
    id: "smart_psu_kicad_pcb",
    category: "kicad_mixed_signal_eda",
    relativePath: "kicad_iot/smart_psu.kicad_pcb",
    absolutePath: writeArtifactFile(
      "kicad_iot/smart_psu.kicad_pcb",
      smartPsuPcb,
    ),
    expectedFormat: "kicad_pcb",
    isNegativeControl: false,
    description:
      "Mixed-signal IoT Smart PSU KiCad PCB layout with J4 JTAG pads, DNP TP1/TP2 SWD pogo pads, SOIC-8 U3 SPI flash, and U4 I2C EEPROM",
    groundTruth: [
      {
        id: "EDA-PCB-01",
        description: "Exposed JTAG header footprint J4 on Smart PSU PCB",
        ruleId: "FW-EDA-JTAG-EXPOSED",
        cwePrimary: "CWE-1244",
        expectedCwes: ["CWE-1244"],
        severity: "critical",
        cvss: 8.8,
        expectedReapPlaybook:
          "reap-13-dma-and-hardware-assisted-cheat-research-defensive",
        expectedDesignators: ["J4"],
      },
      {
        id: "EDA-PCB-02",
        description:
          "Unpopulated DNP pogo-pin SWDIO/SWCLK copper pads TP1/TP2 on B.Cu",
        ruleId: "FW-EDA-SWD-EXPOSED",
        cwePrimary: "CWE-1244",
        expectedCwes: ["CWE-1244"],
        severity: "high",
        cvss: 8.4,
        expectedReapPlaybook:
          "reap-13-dma-and-hardware-assisted-cheat-research-defensive",
        expectedDesignators: ["TP1", "TP2"],
      },
      {
        id: "EDA-PCB-03",
        description: "SOIC-8 external SPI flash footprint U3 on Smart PSU PCB",
        ruleId: "FW-EDA-SPI-FLASH-EXPOSED",
        cwePrimary: "CWE-1244",
        expectedCwes: ["CWE-1244", "CWE-353"],
        severity: "high",
        cvss: 7.8,
        expectedReapPlaybook:
          "reap-13-dma-and-hardware-assisted-cheat-research-defensive",
        expectedDesignators: ["U3"],
      },
      {
        id: "EDA-PCB-04",
        description: "Unauthenticated AT24C64 I2C EEPROM footprint U4 on PCB",
        ruleId: "FW-EDA-I2C-EEPROM-EXPOSED",
        cwePrimary: "CWE-1244",
        expectedCwes: ["CWE-1244", "CWE-353"],
        severity: "medium",
        cvss: 6.5,
        expectedReapPlaybook:
          "reap-13-dma-and-hardware-assisted-cheat-research-defensive",
        expectedDesignators: ["U4"],
      },
    ],
  });

  // Negative Controls 4a & 4b: Clean Isolated 48V-to-12V Analog Power Stage (SOIC-8 PWM + Analog TPs, 0 debug nets)
  const isolatedPowerCleanSch = `(kicad_sch (version 20231120) (generator "eeschema")
  (lib_symbols
    (symbol "Connector_Generic:Conn_01x04"
      (property "Reference" "J" (at 0 0 0))
      (property "Value" "UNUSED_JTAG_SYMBOL_IN_LIB_ONLY" (at 0 0 0))
    )
  )
  (symbol (lib_id "Connector:Screw_Terminal_01x02") (at 40 40 0)
    (property "Reference" "J1" (at 40 36 0))
    (property "Value" "VIN_48V_PRI" (at 40 44 0))
  )
  (symbol (lib_id "Connector:Screw_Terminal_01x02") (at 180 40 0)
    (property "Reference" "J2" (at 180 36 0))
    (property "Value" "VOUT_12V_SEC" (at 180 44 0))
  )
  (symbol (lib_id "Regulator_Controller:UCC28C43") (at 95 55 0)
    (property "Reference" "U1" (at 95 51 0))
    (property "Value" "UCC28C43_PWM_CTRL" (at 95 59 0))
    (property "Footprint" "Package_SO:SOIC-8_3.9x4.9mm_P1.27mm" (at 0 0 0))
  )
  (symbol (lib_id "Isolator:PC817") (at 135 70 0)
    (property "Reference" "U2" (at 135 66 0))
    (property "Value" "PC817_OPTO" (at 135 74 0))
  )
  (symbol (lib_id "Connector:TestPoint") (at 175 35 0)
    (property "Reference" "TP10" (at 175 33 0))
    (property "Value" "VOUT_12V_SENSE" (at 175 37 0))
  )
  (symbol (lib_id "Connector:TestPoint") (at 108 55 0)
    (property "Reference" "TP11" (at 108 53 0))
    (property "Value" "PRI_SW_NODE" (at 108 57 0))
  )
  (label "VIN_48V" (at 45 40 0))
  (label "PRI_GND" (at 45 44 0))
  (label "PRI_SW_NODE" (at 105 55 0))
  (label "CS_SHUNT" (at 95 62 0))
  (label "VOUT_12V" (at 175 40 0))
  (label "SEC_GND" (at 175 44 0))
  (label "FB_OPTO_COMP" (at 130 70 0))
)
`;

  artifacts.push({
    id: "isolated_power_stage_clean_sch",
    category: "kicad_mixed_signal_eda",
    relativePath: "kicad_iot/isolated_power_stage_clean.kicad_sch",
    absolutePath: writeArtifactFile(
      "kicad_iot/isolated_power_stage_clean.kicad_sch",
      isolatedPowerCleanSch,
    ),
    expectedFormat: "kicad_sch",
    isNegativeControl: true,
    description:
      "Clean isolated 48V-to-12V analog flyback schematic (SOIC-8 UCC28C43 PWM IC, optocoupler feedback, analog rail test points, 0 debug nets)",
    groundTruth: [],
  });

  const isolatedPowerCleanPcb = `(kicad_pcb (version 20231014) (generator "pcbnew")
  (net 1 "/VIN_48V")
  (net 2 "/PRI_GND")
  (net 3 "/PRI_SW_NODE")
  (net 4 "/VOUT_12V")
  (net 5 "/SEC_GND")
  (net 6 "/FB_OPTO_COMP")
  (footprint "TerminalBlock:TerminalBlock_bornier-2_P5.08mm"
    (layer "F.Cu")
    (fp_text reference "J1" (at 0 0))
    (fp_text value "VIN_48V_PRI" (at 0 4))
    (pad "1" thru_hole rect (at 0 0) (size 2.5 2.5) (net 1 "/VIN_48V"))
    (pad "2" thru_hole oval (at 5.08 0) (size 2.5 2.5) (net 2 "/PRI_GND"))
  )
  (footprint "Package_SO:SOIC-8_3.9x4.9mm_P1.27mm"
    (layer "F.Cu")
    (fp_text reference "U1" (at 15 10))
    (fp_text value "UCC28C43_PWM_CTRL" (at 15 14))
    (pad "6" smd rect (at 17 10) (size 1.5 0.6) (net 3 "/PRI_SW_NODE"))
    (pad "2" smd rect (at 13 10) (size 1.5 0.6) (net 6 "/FB_OPTO_COMP"))
  )
  (footprint "TestPoint:TestPoint_Pad_D1.5mm"
    (layer "F.Cu")
    (property "Reference" "TP10")
    (property "Value" "VOUT_12V_SENSE")
    (pad "1" smd circle (at 35 10) (size 1.5 1.5) (net 4 "/VOUT_12V"))
  )
)
`;

  artifacts.push({
    id: "isolated_power_stage_clean_pcb",
    category: "kicad_mixed_signal_eda",
    relativePath: "kicad_iot/isolated_power_stage_clean.kicad_pcb",
    absolutePath: writeArtifactFile(
      "kicad_iot/isolated_power_stage_clean.kicad_pcb",
      isolatedPowerCleanPcb,
    ),
    expectedFormat: "kicad_pcb",
    isNegativeControl: true,
    description:
      "Clean isolated 48V-to-12V analog flyback PCB layout (SOIC-8 PWM IC, power terminals, analog voltage test point, 0 debug nets)",
    groundTruth: [],
  });

  // ---------------------------------------------------------------------------
  // REAP Playbook Triage Cases across all 4 firmware/EDA domains
  // ---------------------------------------------------------------------------
  const reapTriageCases: ReapTriageBenchCase[] = [
    {
      id: "reap-triage-ihex-boot",
      category: "automotive_ihex",
      query: {
        binaryFormat: "firmware",
        targetType: "Intel HEX automotive BMS bootloader uboot firmware image",
        objective: "explore",
        maxPlaybooks: 3,
      },
      expectedPlaybookId: "reap-07",
      expectedSkillName: "reap-07-firmware-and-embedded",
    },
    {
      id: "reap-triage-elf-sinks",
      category: "industrial_srec_elf",
      query: {
        binaryFormat: "elf",
        targetType:
          "ARM ELF32 daemon command injection sink taint memcpy vulnerability cve",
        objective: "vuln",
        maxPlaybooks: 3,
      },
      expectedPlaybookId: "reap-10",
      expectedSkillName: "reap-10-vulnerability-research",
    },
    {
      id: "reap-triage-soc-kernel-dts",
      category: "linux_soc_uboot_dts",
      query: {
        binaryFormat: "driver",
        targetType:
          "Linux kernel driver privilege escalation kaslr smep smap exploitation",
        objective: "kernel",
        maxPlaybooks: 3,
      },
      expectedPlaybookId: "reap-19",
      expectedSkillName: "reap-19-kernel-and-driver-exploitation-research",
    },
    {
      id: "reap-triage-kicad-jtag-swd",
      category: "kicad_mixed_signal_eda",
      query: {
        binaryFormat: "firmware",
        targetType:
          "KiCad hardware PCB schematic JTAG SWD IOMMU DMA fpga interface",
        objective: "kernel",
        maxPlaybooks: 3,
      },
      expectedPlaybookId: "reap-13",
      expectedSkillName:
        "reap-13-dma-and-hardware-assisted-cheat-research-defensive",
    },
  ];

  // ---------------------------------------------------------------------------
  // OpGeneral / TypeSafe System One Mission-Routing Cases (+ Negative Controls)
  // ---------------------------------------------------------------------------
  const missionRoutingCases: MissionRoutingBenchCase[] = [
    {
      id: "route-automotive-ihex",
      description:
        "Routes Intel HEX BMS bootloader audit to reverse_binary + firmware_audit_scan",
      isNegativeControl: false,
      directive: {
        objective:
          "Audit automotive/bms_boot.hex Intel HEX bootloader firmware for corrupted record checksums and unbounded sprintf CAN buffer overflows",
      },
      targets: [
        {
          address: "automotive/bms_boot.hex",
          expectedType: "firmware",
          priority: 1,
          rationale: "Automotive BMS Intel HEX bootloader",
        },
      ],
      expectedPrimaryFamily: "reverse_binary",
      expectedFirmwareToolSelected: true,
    },
    {
      id: "route-industrial-srec-elf",
      description:
        "Routes Motorola S-Record & ARM ELF32 daemon audit to reverse_binary + firmware_audit_scan",
      isNegativeControl: false,
      directive: {
        objective:
          "Reverse engineer industrial/plc_agent.srec Motorola S-Record image and industrial/httpd_arm.elf ARM ELF binary for PT_GNU_STACK RWX, ET_EXEC, and popen command sinks",
      },
      targets: [
        {
          address: "industrial/plc_agent.srec",
          expectedType: "firmware",
          priority: 1,
          rationale: "PLC Motorola S-Record image",
        },
        {
          address: "industrial/httpd_arm.elf",
          expectedType: "iot",
          priority: 2,
          rationale: "ARM ELF32 gateway daemon",
        },
      ],
      expectedPrimaryFamily: "reverse_binary",
      expectedFirmwareToolSelected: true,
    },
    {
      id: "route-linux-soc-uboot-dts",
      description:
        "Routes U-Boot environment & Device-Tree (.dts) security audit to reverse_binary + firmware_audit_scan",
      isNegativeControl: false,
      directive: {
        objective:
          "Audit Linux SoC U-Boot bootcmd tftpboot environment and linux_soc/board.dts Device-Tree for unlocked bootdelay, nokaslr bootargs, and writable MTD partitions",
      },
      targets: [
        {
          address: "linux_soc/board.dts",
          expectedType: "firmware",
          priority: 1,
          rationale: "SoC Device-Tree source",
        },
      ],
      expectedPrimaryFamily: "reverse_binary",
      expectedFirmwareToolSelected: true,
    },
    {
      id: "route-kicad-eda-board",
      description:
        "Routes KiCad schematic & PCB debug attack-surface scan to reverse_binary + firmware_audit_scan",
      isNegativeControl: false,
      directive: {
        objective:
          "Scan kicad_iot/smart_psu.kicad_sch and kicad_iot/smart_psu.kicad_pcb hardware EDA design for exposed JTAG headers, DNP SWDIO/SWCLK pogo pads, and SOIC-8 SPI flash taps",
      },
      targets: [
        {
          address: "kicad_iot/smart_psu.kicad_sch",
          expectedType: "hardware",
          priority: 1,
          rationale: "Smart PSU KiCad schematic",
        },
        {
          address: "kicad_iot/smart_psu.kicad_pcb",
          expectedType: "hardware",
          priority: 2,
          rationale: "Smart PSU KiCad PCB",
        },
      ],
      expectedPrimaryFamily: "reverse_binary",
      expectedFirmwareToolSelected: true,
    },
    {
      id: "route-control-web-api",
      description:
        "Negative routing control: REST GraphQL web endpoint assessment",
      isNegativeControl: true,
      directive: {
        objective:
          "Test https://staging.example.internal/api/graphql for reflected XSS, broken session cookies, and SQLi",
      },
      targets: [
        {
          address: "https://staging.example.internal/api/graphql",
          expectedType: "web_application",
          priority: 1,
          rationale: "Staging web GraphQL API",
        },
      ],
      expectedPrimaryFamily: "web_api",
      expectedFirmwareToolSelected: false,
    },
    {
      id: "route-control-null-spice",
      description:
        "Negative routing control: pure analog SPICE RC Bode plot simulation",
      isNegativeControl: true,
      directive: {
        objective: "Simulate SPICE diode RC lowpass Bode phase margin",
      },
      targets: [],
      expectedPrimaryFamily: "web_api",
      expectedFirmwareToolSelected: false,
    },
  ];

  return {
    rootDir,
    artifacts,
    reapTriageCases,
    missionRoutingCases,
    plantedRawSecrets,
    cleanup(): void {
      if (ownsWorkspace) {
        rmSync(rootDir, { recursive: true, force: true });
      }
    },
  };
}

// =============================================================================
// 4. MULTI-GATE SCORING, DUAL-JUDGE VALIDATION & HEATMAP ENGINE
// =============================================================================

export function evaluateFindingGates(
  finding: FirmwareAuditFinding,
  gt: GroundTruthFirmwareVuln,
  plantedRawSecrets: readonly string[],
): FindingGateEvaluation {
  const ruleMatch = finding.ruleId === gt.ruleId;
  const cweMatch = gt.expectedCwes.every((cwe) => finding.cwe.includes(cwe));

  let locationOrDesignatorMatch = true;
  if (gt.expectedAddress !== undefined) {
    locationOrDesignatorMatch =
      locationOrDesignatorMatch && finding.address === gt.expectedAddress;
  }
  if (gt.expectedLine !== undefined) {
    locationOrDesignatorMatch =
      locationOrDesignatorMatch && finding.line === gt.expectedLine;
  }
  if (gt.expectedDesignators !== undefined && gt.expectedDesignators.length > 0) {
    const actualDes = finding.designators ?? [];
    locationOrDesignatorMatch =
      locationOrDesignatorMatch &&
      gt.expectedDesignators.every((d) => actualDes.includes(d));
  }

  const playbookMatch = finding.reapPlaybookId === gt.expectedReapPlaybook;

  const hasRawLeak = plantedRawSecrets.some(
    (raw) => raw.length > 0 && finding.evidence.includes(raw),
  );
  const redactionClean = gt.requiresRedaction
    ? !hasRawLeak && finding.evidence.includes("[redacted]")
    : !hasRawLeak;

  const gates = [
    ruleMatch,
    cweMatch,
    locationOrDesignatorMatch,
    playbookMatch,
    redactionClean,
  ];
  const gatesPassed = gates.filter(Boolean).length;

  return {
    ruleMatch,
    cweMatch,
    locationOrDesignatorMatch,
    playbookMatch,
    redactionClean,
    gatesPassed,
    maxGates: gates.length,
    // Require structural rule + CWE + location/designator match for TP detection
    isTruePositive: ruleMatch && cweMatch && locationOrDesignatorMatch,
  };
}

/**
 * Deterministic SPHINX-style dual-judge cross-validator (`--multi-judge`):
 *   - Primary Judge (Structural & Location Verifier): validates rule, CWEs, and exact hex address / line / PCB designators.
 *   - Secondary Judge (Playbook & Redaction Hygiene Verifier): validates REAP playbook catalog resolution,
 *     remediation completeness, and strict `[redacted]` secret scrubbing.
 */
export function judgeFirmwareFinding(
  finding: FirmwareAuditFinding,
  gateEval: FindingGateEvaluation | null,
  plantedRawSecrets: readonly string[],
  multiJudge: boolean,
): FindingJudgeVerdict {
  const structuralJudgeValid = gateEval !== null && gateEval.isTruePositive;

  const playbookResolved =
    getReapPlaybookById(finding.reapPlaybookId) !== undefined;
  const hasRawLeak = plantedRawSecrets.some(
    (raw) => raw.length > 0 && finding.evidence.includes(raw),
  );
  const remediationPresent = finding.remediation.trim().length >= 16;

  const hygienePlaybookJudgeValid =
    gateEval !== null &&
    gateEval.ruleMatch &&
    gateEval.playbookMatch &&
    gateEval.redactionClean &&
    playbookResolved &&
    !hasRawLeak &&
    remediationPresent;

  if (!multiJudge) {
    return {
      structuralJudgeValid,
      hygienePlaybookJudgeValid: structuralJudgeValid,
      consensusValid: structuralJudgeValid,
      disagreement: false,
      modifier: structuralJudgeValid ? 1.0 : 0.0,
    };
  }

  const consensusValid = structuralJudgeValid && hygienePlaybookJudgeValid;
  const disagreement = structuralJudgeValid !== hygienePlaybookJudgeValid;
  const modifier = consensusValid ? 1.0 : disagreement ? 0.75 : 0.0;

  return {
    structuralJudgeValid,
    hygienePlaybookJudgeValid,
    consensusValid,
    disagreement,
    modifier,
  };
}

export function buildFirmwareCweHeatmap(
  artifacts: readonly ScoredFirmwareArtifact[],
  groundTruthByArtifact: ReadonlyMap<
    string,
    readonly GroundTruthFirmwareVuln[]
  >,
): CweCoverageHeatmapRow[] {
  return REQUIRED_BENCH_CWES.map((cwe) => {
    let total = 0;
    let detected = 0;
    let cvssPossible = 0;
    let cvssAwarded = 0;
    const missedVulnIds: string[] = [];

    for (const art of artifacts) {
      if (art.isNegativeControl) continue;
      const gts = groundTruthByArtifact.get(art.artifactId) ?? [];
      for (const gt of gts) {
        if (gt.cwePrimary !== cwe && !gt.expectedCwes.includes(cwe)) {
          continue;
        }
        total++;
        cvssPossible += gt.cvss;
        const matched = art.matchedFindings.find((m) => m.vulnId === gt.id);
        if (matched) {
          detected++;
          cvssAwarded += matched.cvssAwarded;
        } else {
          missedVulnIds.push(gt.id);
        }
      }
    }

    const recall = total > 0 ? roundMetric(detected / total, 4) : 1;
    const filled = Math.round(recall * 10);
    const bar = "█".repeat(filled) + "░".repeat(10 - filled);

    return {
      cwe,
      label: CWE_LABELS[cwe],
      total,
      detected,
      missed: total - detected,
      recall,
      cvssAwarded: roundMetric(cvssAwarded, 2),
      cvssPossible: roundMetric(cvssPossible, 2),
      bar,
      blindSpot: recall < 0.5,
      missedVulnIds,
    };
  });
}

export function evaluateReapTriageBench(
  cases: readonly ReapTriageBenchCase[],
  scoredArtifacts: readonly ScoredFirmwareArtifact[],
): ReapTriageBenchSummary {
  let findingPlaybookChecks = 0;
  let findingPlaybookCorrect = 0;
  const unresolvedSet = new Set<string>();

  for (const art of scoredArtifacts) {
    for (const mf of art.matchedFindings) {
      findingPlaybookChecks++;
      const resolved = getReapPlaybookById(mf.reapPlaybookId);
      if (!resolved) {
        unresolvedSet.add(mf.reapPlaybookId);
      }
      if (mf.reapPlaybookId === mf.expectedReapPlaybook && resolved) {
        findingPlaybookCorrect++;
      }
    }
  }

  let queryCasesCorrect = 0;
  for (const c of cases) {
    const selection = selectReapPlaybooks(c.query);
    const topIds = selection.matches.map((m) => m.playbook.id);
    const topSkills = selection.matches.map((m) => m.playbook.skillName);
    if (
      topIds[0] === c.expectedPlaybookId ||
      (topIds.includes(c.expectedPlaybookId) &&
        topSkills.includes(c.expectedSkillName))
    ) {
      queryCasesCorrect++;
    }
  }

  const findingPlaybookAccuracy =
    findingPlaybookChecks > 0
      ? roundMetric(findingPlaybookCorrect / findingPlaybookChecks, 4)
      : 1;
  const queryTopMatchAccuracy =
    cases.length > 0 ? roundMetric(queryCasesCorrect / cases.length, 4) : 1;

  const totalChecks = findingPlaybookChecks + cases.length;
  const totalCorrect = findingPlaybookCorrect + queryCasesCorrect;
  const combinedAccuracy =
    totalChecks > 0 ? roundMetric(totalCorrect / totalChecks, 4) : 1;

  return {
    findingPlaybookChecks,
    findingPlaybookCorrect,
    findingPlaybookAccuracy,
    queryCasesTotal: cases.length,
    queryCasesCorrect,
    queryTopMatchAccuracy,
    combinedAccuracy,
    unresolvedPlaybookIds: Array.from(unresolvedSet).sort(),
  };
}

export async function evaluateMissionRoutingBench(
  cases: readonly MissionRoutingBenchCase[],
): Promise<MissionRoutingBenchSummary> {
  const results: MissionRoutingCaseResult[] = [];

  for (const c of cases) {
    const state = buildMissionRoutingState({
      directive: c.directive,
      targets: [...c.targets],
    });
    const decision = evaluateMissionRouteOffline({
      directive: c.directive,
      targets: [...c.targets],
    });
    const recommendedTools = recommendToolsForMissionRoute(decision, state);
    const actualFirmwareToolSelected =
      recommendedTools.includes("firmware_audit_scan");
    const reverseBinaryProbability = roundMetric(
      decision.judgments.familyProbabilities.reverse_binary,
      4,
    );

    const mockLlm = {
      prompt: async () =>
        JSON.stringify({
          codename: `BENCH_${c.id.toUpperCase().replace(/[^A-Z0-9]+/g, "_")}`,
          summary: c.description,
          targets: c.targets.map((t) => ({
            address: t.address,
            expectedType: t.expectedType,
            priority: t.priority,
          })),
          objectives: [c.directive.objective],
          operators: ["scanner", "analyst"],
        }),
    } as unknown as LLMBackbone;

    const general = new OpGeneral(mockLlm, {
      routingMode: "offline",
      sourceRoot: "",
    });
    const plan = await general.planOperation(c.directive);
    const opGeneralFamilyMatched =
      plan.missionFamily === c.expectedPrimaryFamily;
    const planPrimaryTools = plan.toolPlan.flatMap((tp) => tp.primaryTools);
    const opGeneralToolPlanMatched = c.expectedFirmwareToolSelected
      ? planPrimaryTools.includes("firmware_audit_scan")
      : !planPrimaryTools.includes("firmware_audit_scan");

    const probabilityGate = c.expectedFirmwareToolSelected
      ? reverseBinaryProbability >= YES_THRESHOLD
      : reverseBinaryProbability < YES_THRESHOLD;

    const passed =
      decision.primaryFamily === c.expectedPrimaryFamily &&
      actualFirmwareToolSelected === c.expectedFirmwareToolSelected &&
      opGeneralFamilyMatched &&
      opGeneralToolPlanMatched &&
      probabilityGate;

    results.push({
      id: c.id,
      isNegativeControl: c.isNegativeControl,
      expectedPrimaryFamily: c.expectedPrimaryFamily,
      actualPrimaryFamily: decision.primaryFamily,
      reverseBinaryProbability,
      expectedFirmwareToolSelected: c.expectedFirmwareToolSelected,
      actualFirmwareToolSelected,
      opGeneralFamilyMatched,
      opGeneralToolPlanMatched,
      passed,
    });
  }

  const passedCases = results.filter((r) => r.passed).length;
  const fwCases = results.filter((r) => !r.isNegativeControl);
  const ctrlCases = results.filter((r) => r.isNegativeControl);

  return {
    totalCases: results.length,
    passedCases,
    accuracy:
      results.length > 0 ? roundMetric(passedCases / results.length, 4) : 1,
    firmwareCasesAccuracy:
      fwCases.length > 0
        ? roundMetric(
            fwCases.filter((r) => r.passed).length / fwCases.length,
            4,
          )
        : 1,
    negativeControlCasesAccuracy:
      ctrlCases.length > 0
        ? roundMetric(
            ctrlCases.filter((r) => r.passed).length / ctrlCases.length,
            4,
          )
        : 1,
    results,
  };
}

export function auditSecretRedaction(
  serializedPayloads: readonly string[],
  plantedRawSecrets: readonly string[],
  redactedFindingCount: number,
): SecretRedactionAuditSummary {
  const leaked = new Set<string>();
  for (const payload of serializedPayloads) {
    for (let i = 0; i < plantedRawSecrets.length; i++) {
      const secret = plantedRawSecrets[i];
      if (secret.length > 0 && payload.includes(secret)) {
        leaked.add(`planted_secret_${i + 1}`);
      }
    }
  }
  const leakedIdentifiers = Array.from(leaked).sort();
  return {
    plantedSecretCount: plantedRawSecrets.length,
    redactedFindingCount,
    unredactedLeakCount: leakedIdentifiers.length,
    leakedIdentifiers,
    passed: leakedIdentifiers.length === 0,
  };
}

// =============================================================================
// 5. BENCHMARK EXECUTION ENGINE
// =============================================================================

function computeCategoryMetrics(
  category: FirmwareBenchCategoryId,
  artifacts: readonly ScoredFirmwareArtifact[],
): CategoryBenchMetrics {
  const subset = artifacts.filter((a) => a.category === category);
  const vulnArts = subset.filter((a) => !a.isNegativeControl);
  const ctrlArts = subset.filter((a) => a.isNegativeControl);
  const contaminatedControls = ctrlArts.filter(
    (a) => a.falsePositives > 0,
  ).length;

  const tp = subset.reduce((s, a) => s + a.truePositives, 0);
  const fp = subset.reduce((s, a) => s + a.falsePositives, 0);
  const fpOnControls = ctrlArts.reduce((s, a) => s + a.falsePositives, 0);
  const fn = vulnArts.reduce((s, a) => s + a.falseNegatives, 0);

  const precision = tp + fp > 0 ? roundMetric(tp / (tp + fp), 4) : 1;
  const recall = tp + fn > 0 ? roundMetric(tp / (tp + fn), 4) : 1;
  const f1 =
    precision + recall > 0
      ? roundMetric((2 * precision * recall) / (precision + recall), 4)
      : 0;
  const falsePositiveRate =
    ctrlArts.length > 0
      ? roundMetric(
          Math.max(contaminatedControls, fpOnControls) / ctrlArts.length,
          4,
        )
      : 0;

  const cvssAwarded = roundMetric(
    vulnArts.reduce((s, a) => s + a.cvssAwarded, 0),
    2,
  );
  const cvssPossible = roundMetric(
    vulnArts.reduce((s, a) => s + a.cvssPossible, 0),
    2,
  );
  const cvssWeightedRecall =
    cvssPossible > 0 ? roundMetric(cvssAwarded / cvssPossible, 4) : 1;

  return {
    category,
    label: CATEGORY_LABELS[category],
    vulnerableArtifacts: vulnArts.length,
    negativeControlArtifacts: ctrlArts.length,
    contaminatedControls,
    truePositives: tp,
    falsePositives: fp,
    falsePositivesOnControls: fpOnControls,
    falseNegatives: fn,
    precision,
    recall,
    f1,
    falsePositiveRate,
    cvssAwarded,
    cvssPossible,
    cvssWeightedRecall,
  };
}

export async function runFirmwareVulnBench(
  options: FirmwareBenchOptions = {},
): Promise<FirmwareBenchScorecard> {
  const cvssWeighted = Boolean(options.cvssWeighted);
  const multiJudge = Boolean(options.multiJudge);
  const corpus = generateFirmwareBenchCorpus(options.rootDir);

  try {
    const selectedArtifacts = options.category
      ? corpus.artifacts.filter((a) => a.category === options.category)
      : corpus.artifacts;

    const groundTruthByArtifact = new Map<
      string,
      readonly GroundTruthFirmwareVuln[]
    >();
    const scoredArtifacts: ScoredFirmwareArtifact[] = [];
    const rawToolOutputs: string[] = [];
    let redactedFindingCount = 0;

    for (const art of selectedArtifacts) {
      groundTruthByArtifact.set(art.id, art.groundTruth);

      // Execute end-to-end `firmware_audit_scan` tool handler isolated via target.metadata.sourceRoot
      const scopedTarget = {
        id: `bench-${art.id}`,
        name: art.relativePath,
        type: "iot" as const,
        zone: "internal" as const,
        status: "discovered" as const,
        address: art.relativePath,
        metadata: { sourceRoot: corpus.rootDir },
        discoveredAt: 0,
      };
      const toolResult = await firmwareAuditScanTool.handler(
        createToolContext(scopedTarget, { path: art.relativePath }),
      );
      if (toolResult.output) {
        rawToolOutputs.push(toolResult.output);
      }
      if (toolResult.findings) {
        rawToolOutputs.push(JSON.stringify(toolResult.findings));
      }

      const fileBuf = await import("node:fs").then((fsMod) =>
        fsMod.readFileSync(art.absolutePath),
      );
      const bufferReport = analyzeFirmwareBuffer(fileBuf, art.absolutePath);
      const findings: readonly FirmwareAuditFinding[] = options.detectorOverride
        ? options.detectorOverride(fileBuf, art.absolutePath)
        : bufferReport.findings;

      const matchedGtIds = new Set<string>();
      const matchedFindings: MatchedFindingDetail[] = [];
      const falsePositiveFindings: UnmatchedFindingDetail[] = [];
      let judgeDisagreements = 0;

      for (const finding of findings) {
        if (finding.evidence.includes("[redacted]")) {
          redactedFindingCount++;
        }

        let matchedGt: GroundTruthFirmwareVuln | undefined;
        let matchedGate: FindingGateEvaluation | undefined;

        for (const gt of art.groundTruth) {
          if (matchedGtIds.has(gt.id)) continue;
          const gate = evaluateFindingGates(
            finding,
            gt,
            corpus.plantedRawSecrets,
          );
          if (gate.isTruePositive) {
            matchedGt = gt;
            matchedGate = gate;
            break;
          }
        }

        if (matchedGt && matchedGate) {
          matchedGtIds.add(matchedGt.id);
          const judge = judgeFirmwareFinding(
            finding,
            matchedGate,
            corpus.plantedRawSecrets,
            multiJudge,
          );
          if (judge.disagreement) judgeDisagreements++;
          const awarded = roundMetric(matchedGt.cvss * judge.modifier, 2);

          matchedFindings.push({
            vulnId: matchedGt.id,
            ruleId: finding.ruleId,
            cwePrimary: matchedGt.cwePrimary,
            cvss: matchedGt.cvss,
            cvssAwarded: awarded,
            reapPlaybookId: finding.reapPlaybookId,
            expectedReapPlaybook: matchedGt.expectedReapPlaybook,
            evidence: finding.evidence,
            gates: matchedGate,
            judge,
          });
        } else {
          const judge = judgeFirmwareFinding(
            finding,
            null,
            corpus.plantedRawSecrets,
            multiJudge,
          );
          if (judge.disagreement) judgeDisagreements++;
          falsePositiveFindings.push({
            ruleId: finding.ruleId,
            cwe: finding.cwe,
            title: finding.title,
            evidence: finding.evidence,
            judge,
          });
        }
      }

      const missedVulnIds = art.groundTruth
        .filter((gt) => !matchedGtIds.has(gt.id))
        .map((gt) => gt.id);

      const cvssPossible = roundMetric(
        art.groundTruth.reduce((s, gt) => s + gt.cvss, 0),
        2,
      );
      const cvssAwarded = roundMetric(
        matchedFindings.reduce((s, mf) => s + mf.cvssAwarded, 0),
        2,
      );

      scoredArtifacts.push({
        artifactId: art.id,
        category: art.category,
        relativePath: art.relativePath,
        detectedFormat: bufferReport.detectedFormat,
        expectedFormat: art.expectedFormat,
        formatMatched: bufferReport.detectedFormat === art.expectedFormat,
        isNegativeControl: art.isNegativeControl,
        toolExecutionSucceeded: toolResult.success,
        expectedCount: art.groundTruth.length,
        findingsCount: findings.length,
        truePositives: matchedFindings.length,
        falsePositives: falsePositiveFindings.length,
        falseNegatives: missedVulnIds.length,
        cvssPossible,
        cvssAwarded,
        judgeDisagreements,
        matchedFindings,
        falsePositiveFindings,
        missedVulnIds,
      });
    }

    const allCategoryIds: readonly FirmwareBenchCategoryId[] = options.category
      ? [options.category]
      : [
          "automotive_ihex",
          "industrial_srec_elf",
          "linux_soc_uboot_dts",
          "kicad_mixed_signal_eda",
        ];

    const categories = allCategoryIds.map((catId) =>
      computeCategoryMetrics(catId, scoredArtifacts),
    );

    const vulnArts = scoredArtifacts.filter((a) => !a.isNegativeControl);
    const ctrlArts = scoredArtifacts.filter((a) => a.isNegativeControl);
    const contaminatedControls = ctrlArts.filter(
      (a) => a.falsePositives > 0,
    ).length;

    const tp = scoredArtifacts.reduce((s, a) => s + a.truePositives, 0);
    const fp = scoredArtifacts.reduce((s, a) => s + a.falsePositives, 0);
    const fpOnControls = ctrlArts.reduce((s, a) => s + a.falsePositives, 0);
    const fn = vulnArts.reduce((s, a) => s + a.falseNegatives, 0);
    const totalFindingsEmitted = scoredArtifacts.reduce(
      (s, a) => s + a.findingsCount,
      0,
    );
    const totalGroundTruthVulns = vulnArts.reduce(
      (s, a) => s + a.expectedCount,
      0,
    );

    const precision = tp + fp > 0 ? roundMetric(tp / (tp + fp), 4) : 1;
    const recall = tp + fn > 0 ? roundMetric(tp / (tp + fn), 4) : 1;
    const f1 =
      precision + recall > 0
        ? roundMetric((2 * precision * recall) / (precision + recall), 4)
        : 0;
    const falsePositiveRate =
      ctrlArts.length > 0
        ? roundMetric(
            Math.max(contaminatedControls, fpOnControls) / ctrlArts.length,
            4,
          )
        : 0;

    const cvssAwarded = roundMetric(
      vulnArts.reduce((s, a) => s + a.cvssAwarded, 0),
      2,
    );
    const cvssPossible = roundMetric(
      vulnArts.reduce((s, a) => s + a.cvssPossible, 0),
      2,
    );
    const cvssWeightedRecall =
      cvssPossible > 0 ? roundMetric(cvssAwarded / cvssPossible, 4) : 1;

    const primaryScorePercent = roundMetric(
      (cvssWeighted ? cvssWeightedRecall : f1) * 100,
      2,
    );

    const judgeDisagreements = scoredArtifacts.reduce(
      (s, a) => s + a.judgeDisagreements,
      0,
    );
    const judgeAgreementRate =
      totalFindingsEmitted > 0
        ? roundMetric(
            (totalFindingsEmitted - judgeDisagreements) / totalFindingsEmitted,
            4,
          )
        : 1;

    const cweHeatmap = buildFirmwareCweHeatmap(
      scoredArtifacts,
      groundTruthByArtifact,
    );

    const filteredReapCases = options.category
      ? corpus.reapTriageCases.filter((c) => c.category === options.category)
      : corpus.reapTriageCases;
    const reapTriage = evaluateReapTriageBench(
      filteredReapCases,
      scoredArtifacts,
    );

    const missionRouting = await evaluateMissionRoutingBench(
      corpus.missionRoutingCases,
    );

    const preliminarySerialized = JSON.stringify({
      scoredArtifacts,
      cweHeatmap,
      reapTriage,
      missionRouting,
    });
    const secretRedaction = auditSecretRedaction(
      [preliminarySerialized, ...rawToolOutputs],
      corpus.plantedRawSecrets,
      redactedFindingCount,
    );

    return {
      schema: "t3mp3st.bench.firmware-vuln/v1",
      scoringMode: cvssWeighted ? "cvss_weighted" : "flat",
      multiJudgeEnabled: multiJudge,
      aggregate: {
        totalArtifacts: scoredArtifacts.length,
        vulnerableArtifacts: vulnArts.length,
        negativeControlArtifacts: ctrlArts.length,
        contaminatedControls,
        totalGroundTruthVulns,
        totalFindingsEmitted,
        truePositives: tp,
        falsePositives: fp,
        falsePositivesOnControls: fpOnControls,
        falseNegatives: fn,
        precision,
        recall,
        f1,
        falsePositiveRate,
        cvssAwarded,
        cvssPossible,
        cvssWeightedRecall,
        primaryScorePercent,
        judgeAgreementRate,
        judgeDisagreements,
      },
      categories,
      cweHeatmap,
      reapTriage,
      missionRouting,
      secretRedaction,
      artifacts: scoredArtifacts,
    };
  } finally {
    if (!options.keepWorkspace) {
      corpus.cleanup();
    }
  }
}

// =============================================================================
// 6. DETERMINISTIC JSON & MARKDOWN SCORECARD EXPORTERS
// =============================================================================

export function formatFirmwareBenchJson(
  scorecard: FirmwareBenchScorecard,
): string {
  return `${JSON.stringify(scorecard, null, 2)}\n`;
}

export function formatFirmwareBenchMarkdown(
  scorecard: FirmwareBenchScorecard,
): string {
  const agg = scorecard.aggregate;
  const lines: string[] = [
    "# T3MP3ST Embedded Firmware & Hardware EDA CVE/CWE Benchmark Scorecard",
    "",
    `- **Schema**: \`${scorecard.schema}\``,
    `- **Scoring Mode**: \`${scorecard.scoringMode}\``,
    `- **Multi-Judge Cross-Validation**: \`${scorecard.multiJudgeEnabled ? "enabled" : "disabled"}\` (agreement: \`${(agg.judgeAgreementRate * 100).toFixed(1)}%\`, disagreements: \`${agg.judgeDisagreements}\`)`,
    `- **Secret Redaction Gate**: \`${scorecard.secretRedaction.passed ? "PASS" : "FAIL"}\` (\`${scorecard.secretRedaction.unredactedLeakCount}\` unredacted leaks across \`${scorecard.secretRedaction.plantedSecretCount}\` planted secrets)`,
    "",
    "## Aggregate Metrics",
    "",
    "| Metric | Value |",
    "| --- | --- |",
    `| Precision | \`${agg.precision.toFixed(4)}\` (${agg.truePositives}/${agg.truePositives + agg.falsePositives}) |`,
    `| Recall | \`${agg.recall.toFixed(4)}\` (${agg.truePositives}/${agg.totalGroundTruthVulns}) |`,
    `| F1 Score | \`${agg.f1.toFixed(4)}\` |`,
    `| False-Positive Rate (Hardened Controls) | \`${agg.falsePositiveRate.toFixed(4)}\` (${agg.falsePositivesOnControls} FP across ${agg.negativeControlArtifacts} controls) |`,
    `| CVSS-Weighted Recall | \`${agg.cvssWeightedRecall.toFixed(4)}\` (${agg.cvssAwarded.toFixed(2)}/${agg.cvssPossible.toFixed(2)} CVSS) |`,
    `| REAP Playbook Triage Accuracy | \`${scorecard.reapTriage.combinedAccuracy.toFixed(4)}\` (findings: ${scorecard.reapTriage.findingPlaybookCorrect}/${scorecard.reapTriage.findingPlaybookChecks}, queries: ${scorecard.reapTriage.queryCasesCorrect}/${scorecard.reapTriage.queryCasesTotal}) |`,
    `| OpGeneral / TypeSafe Routing Accuracy | \`${scorecard.missionRouting.accuracy.toFixed(4)}\` (${scorecard.missionRouting.passedCases}/${scorecard.missionRouting.totalCases}) |`,
    "",
    "## Per-Category Breakdown",
    "",
    "| Category | Precision | Recall | F1 | Control FPR | CVSS Recall |",
    "| --- | --- | --- | --- | --- | --- |",
  ];

  for (const cat of scorecard.categories) {
    lines.push(
      `| ${cat.label} | \`${cat.precision.toFixed(4)}\` | \`${cat.recall.toFixed(4)}\` | \`${cat.f1.toFixed(4)}\` | \`${cat.falsePositiveRate.toFixed(4)}\` | \`${cat.cvssWeightedRecall.toFixed(4)}\` |`,
    );
  }

  lines.push(
    "",
    "## CWE Coverage Heatmap",
    "",
    "| CWE | Vulnerability Class | Coverage | Detected | CVSS | Status |",
    "| --- | --- | --- | --- | --- | --- |",
  );

  for (const row of scorecard.cweHeatmap) {
    const status = row.blindSpot
      ? `BLIND SPOT (${row.missedVulnIds.join(", ")})`
      : row.missed > 0
        ? `Partial (${row.missedVulnIds.join(", ")})`
        : "PASS";
    lines.push(
      `| \`${row.cwe}\` | ${row.label} | \`${row.bar}\` \`${(row.recall * 100).toFixed(1)}%\` | ${row.detected}/${row.total} | ${row.cvssAwarded.toFixed(1)}/${row.cvssPossible.toFixed(1)} | ${status} |`,
    );
  }

  lines.push(
    "",
    "## Artifact Verification Ledger",
    "",
    "| Artifact | Role | Format | TP | FP | FN | Verdict |",
    "| --- | --- | --- | --- | --- | --- | --- |",
  );

  for (const art of scorecard.artifacts) {
    const role = art.isNegativeControl ? "Hardened Control" : "Vulnerable Target";
    const ok = art.isNegativeControl
      ? art.falsePositives === 0 && art.formatMatched
      : art.falseNegatives === 0 &&
        art.falsePositives === 0 &&
        art.formatMatched;
    lines.push(
      `| \`${art.relativePath}\` | ${role} | \`${art.detectedFormat}\` | ${art.truePositives} | ${art.falsePositives} | ${art.falseNegatives} | ${ok ? "PASS" : "FAIL"} |`,
    );
  }

  lines.push("");
  return lines.join("\n");
}

// =============================================================================
// 7. CLI RUNNER
// =============================================================================

export function parseFirmwareBenchCliArgs(
  argv: readonly string[],
): FirmwareBenchCliArgs {
  let cvssWeighted = false;
  let multiJudge = false;
  let category: FirmwareBenchCategoryId | undefined;
  let jsonOut: string | undefined;
  let markdownOut: string | undefined;
  let selfTest = false;

  const validCategories: readonly FirmwareBenchCategoryId[] = [
    "automotive_ihex",
    "industrial_srec_elf",
    "linux_soc_uboot_dts",
    "kicad_mixed_signal_eda",
  ];

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--cvss-weighted") {
      cvssWeighted = true;
    } else if (arg === "--multi-judge") {
      multiJudge = true;
    } else if (arg === "--self-test") {
      selfTest = true;
    } else if (arg === "--category" && i + 1 < argv.length) {
      const val = argv[++i] as FirmwareBenchCategoryId;
      if (!validCategories.includes(val)) {
        throw new Error(
          `firmware-vuln-bench: invalid --category "${val}" (expected one of ${validCategories.join(", ")})`,
        );
      }
      category = val;
    } else if (arg === "--json" && i + 1 < argv.length) {
      jsonOut = argv[++i];
    } else if (arg === "--markdown" && i + 1 < argv.length) {
      markdownOut = argv[++i];
    }
  }

  return {
    cvssWeighted,
    multiJudge,
    category,
    jsonOut,
    markdownOut,
    selfTest,
  };
}

export async function runFirmwareBenchCli(
  argv: readonly string[] = [],
): Promise<FirmwareBenchCliResult> {
  const args = parseFirmwareBenchCliArgs(argv);
  const scorecard = await runFirmwareVulnBench({
    cvssWeighted: args.cvssWeighted,
    multiJudge: args.multiJudge,
    category: args.category,
  });

  const json = formatFirmwareBenchJson(scorecard);
  const markdown = formatFirmwareBenchMarkdown(scorecard);

  if (args.jsonOut) {
    const outPath = resolve(args.jsonOut);
    mkdirSync(dirname(outPath), { recursive: true });
    writeFileSync(outPath, json, "utf8");
  }
  if (args.markdownOut) {
    const outPath = resolve(args.markdownOut);
    mkdirSync(dirname(outPath), { recursive: true });
    writeFileSync(outPath, markdown, "utf8");
  }

  if (args.selfTest) {
    if (scorecard.aggregate.precision < 0.95) {
      throw new Error(
        `firmware-vuln-bench self-test failed: precision ${scorecard.aggregate.precision} < 0.95`,
      );
    }
    if (scorecard.aggregate.recall < 0.95) {
      throw new Error(
        `firmware-vuln-bench self-test failed: recall ${scorecard.aggregate.recall} < 0.95`,
      );
    }
    if (scorecard.aggregate.falsePositiveRate !== 0) {
      throw new Error(
        `firmware-vuln-bench self-test failed: falsePositiveRate ${scorecard.aggregate.falsePositiveRate} !== 0`,
      );
    }
    if (!scorecard.secretRedaction.passed) {
      throw new Error(
        "firmware-vuln-bench self-test failed: unredacted secret leak detected",
      );
    }
  }

  return { scorecard, json, markdown };
}

const isDirectCliExecution =
  typeof process !== "undefined" &&
  Array.isArray(process.argv) &&
  Boolean(process.argv[1]) &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (isDirectCliExecution) {
  runFirmwareBenchCli(process.argv.slice(2))
    .then(({ markdown, scorecard }) => {
      console.log(markdown);
      if (
        scorecard.aggregate.recall < 0.95 ||
        scorecard.aggregate.falsePositiveRate > 0 ||
        !scorecard.secretRedaction.passed
      ) {
        process.exitCode = 1;
      }
    })
    .catch((err: unknown) => {
      console.error("firmware-vuln-bench failed:", err);
      process.exitCode = 2;
    });
}
