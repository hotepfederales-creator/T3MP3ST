/**
 * T3MP3ST REAP Playbooks — Reverse Engineering with AI Agent Prompts.
 *
 * Distilled from JoasASantos/REA-Prompts (MIT License, Copyright (c) 2025 Joas Antonio dos Santos,
 * https://github.com/JoasASantos/REA-Prompts) for REA (https://rea.tools/) workflows.
 *
 * Provides:
 *   1. REAP_PLAYBOOKS — structured, typed catalog covering native binaries, feature tracing,
 *      clean-room cloning, games & WASM portability, firmware, Android, kernel/drivers,
 *      vulnerability research, Electron/JS, protectors/deobfuscation, version diffs & crashes,
 *      long-running evidence ledgers, malware analysis, Go/Rust recovery, and prompt craft.
 *   2. selectReapPlaybooks() — deterministic multi-factor matcher that ranks playbooks and
 *      synthesizes REA MCP tool pipelines, evidence/unknown-tracking checklists, and prompts.
 *   3. reapPlaybookTool (`reap_playbook`) — T3MP3ST Arsenal CustomTool for reverse_binary,
 *      analyst, and coordinator operators.
 */

import type { CustomTool } from "../types/index.js";

export type ReapTargetFormat =
  | "pe"
  | "elf"
  | "macho"
  | "firmware"
  | "apk"
  | "electron"
  | "js"
  | "wasm"
  | "driver"
  | "go_rust"
  | "crash"
  | "diff";

export type ReapObjective =
  | "clone"
  | "trace"
  | "vuln"
  | "diff"
  | "deobfuscate"
  | "malware"
  | "reconstruct"
  | "kernel"
  | "explore";

export interface ReapPromptTemplate {
  name: string;
  template: string;
}

export interface ReapPlaybook {
  id: string;
  skillName: string;
  title: string;
  category: string;
  summary: string;
  targetFormats: readonly ReapTargetFormat[];
  objectives: readonly ReapObjective[];
  keywords: readonly string[];
  reaToolPipeline: readonly string[];
  evidenceChecklist: readonly string[];
  promptTemplates: readonly ReapPromptTemplate[];
  staticFirst: boolean;
}

export interface ReapSelectionQuery {
  targetType?: string;
  objective?: string;
  binaryFormat?: string;
  maxPlaybooks?: number;
}

export interface ReapPlaybookMatch {
  playbook: ReapPlaybook;
  score: number;
  matchedFactors: string[];
}

export interface ReapSelectionResult {
  normalizedFormat?: ReapTargetFormat;
  normalizedObjective?: ReapObjective;
  matches: ReapPlaybookMatch[];
  recommendedPipeline: string[];
  evidenceChecklist: string[];
  renderedPrompts: Array<{
    playbookId: string;
    name: string;
    prompt: string;
  }>;
}

const CORE_EVIDENCE_RULES: readonly string[] = [
  "Cite concrete evidence for every claim: file path, function name, virtual address, or disassembly/decompiled slice.",
  "Separate confirmed facts, inferences/hypotheses, and residual unknowns explicitly.",
  "Start with static analysis only; do not execute untrusted binaries without an isolated lab/approval.",
];

export const REAP_PLAYBOOKS: readonly ReapPlaybook[] = [
  {
    id: "reap-02",
    skillName: "reap-02-feature-tracing-any-program",
    title: "Feature Tracing (Any Program)",
    category: "tracing",
    summary:
      "Trace a single user-visible feature or UI action from entry point through call chain, data flow, and observable side effects.",
    targetFormats: ["pe", "elf", "macho", "electron", "js", "apk", "go_rust"],
    objectives: ["trace", "explore"],
    keywords: [
      "feature",
      "trace",
      "button",
      "workflow",
      "dataflow",
      "rule",
      "entry point",
      "call chain",
    ],
    reaToolPipeline: [
      "rea.open_target",
      "rea.search_strings",
      "rea.find_xrefs",
      "rea.decompile_function",
      "rea.trace_call_graph",
    ],
    evidenceChecklist: [
      ...CORE_EVIDENCE_RULES,
      "Map entry trigger -> intermediate handlers -> final file/network/UI side effect.",
      "Document every unverified branch or dynamic dispatch target as UNKNOWN.",
    ],
    promptTemplates: [
      {
        name: "Explain one feature",
        template:
          "Use REA to investigate how <FEATURE> works in <PATH TO APPLICATION>. Identify the entry point, functions involved, data flow, dependencies, and observable effects. Cite file, function, address, or snippet for every conclusion. Separate confirmed facts, inferences, and unknowns. Do not execute the application in this step.",
      },
      {
        name: "Recover a rule and rebuild it",
        template:
          "Use REA to find the rule that controls <BEHAVIOR> in <PROGRAM>. Write the rule in plain words, cite proving addresses, build a minimal standalone version, and provide one input proving parity.",
      },
    ],
    staticFirst: true,
  },
  {
    id: "reap-03",
    skillName: "reap-03-native-binary-exploration",
    title: "Native Binary Exploration",
    category: "native",
    summary:
      "Static triage of PE/ELF/Mach-O binaries: architecture, sections, imports by capability, strings, file formats, and wire protocols.",
    targetFormats: ["pe", "elf", "macho"],
    objectives: ["explore", "trace"],
    keywords: [
      "native",
      "pe",
      "elf",
      "macho",
      "exe",
      "dll",
      "so",
      "dylib",
      "imports",
      "sections",
      "protocol",
      "file format",
      "triage",
    ],
    reaToolPipeline: [
      "rea.open_target",
      "rea.triage_binary",
      "rea.list_imports",
      "rea.search_strings",
      "rea.list_functions",
      "rea.decompile_function",
    ],
    evidenceChecklist: [
      ...CORE_EVIDENCE_RULES,
      "Record binary format, architecture, endianness, section layout, and hardening flags.",
      "Group imports by capability (network, filesystem, crypto, process, IPC) and flag packing/entropy anomalies.",
    ],
    promptTemplates: [
      {
        name: "Imports, strings and triage map",
        template:
          "Use REA on <BINARY>. Produce a triage map: file format and architecture, section layout, linked libraries and imports grouped by capability (network, filesystem, crypto, process/thread, registry/IPC), interesting strings with addresses, and top candidate entry points for <FEATURE>. Flag signs of packing or obfuscation.",
      },
      {
        name: "Protocol / serialization extraction",
        template:
          "Use REA on <BINARY> to recover the wire format for <FEATURE>. Show marshal/unmarshal functions with addresses, list every field (size, endianness, encoding), and emit a struct/proto definition plus one sample message.",
      },
    ],
    staticFirst: true,
  },
  {
    id: "reap-04",
    skillName: "reap-04-software-and-feature-cloning",
    title: "Software & Feature Cloning",
    category: "cloning",
    summary:
      "Clean-room behavioral specification and feature reimplementation from recovered rules, validated with differential tests.",
    targetFormats: ["pe", "elf", "macho", "electron", "js", "wasm"],
    objectives: ["clone", "reconstruct"],
    keywords: [
      "clone",
      "clean-room",
      "spec",
      "behavior",
      "reimplement",
      "parity",
      "verify_reconstruction",
    ],
    reaToolPipeline: [
      "rea.open_target",
      "rea.trace_call_graph",
      "rea.decompile_function",
      "rea.extract_constants",
      "rea.verify_reconstruction",
    ],
    evidenceChecklist: [
      ...CORE_EVIDENCE_RULES,
      "Extract observable behavior, edge cases, and error modes — never copy proprietary code or assets.",
      "Track passing cases, divergences, and untested behaviors in CLONE_SPEC.md.",
    ],
    promptTemplates: [
      {
        name: "Full application behavioral spec",
        template:
          "Use REA to study <APPLICATION> for a clean-room clone. Produce CLONE_SPEC.md covering user-visible features, state machines, inputs/outputs, file formats, protocols, persistence, and error modes. Cite proving functions/addresses and mark unconfirmed behavior as UNKNOWN.",
      },
      {
        name: "Validate clone against original",
        template:
          "Compare <MY IMPLEMENTATION> with <ORIGINAL APPLICATION> using verify_reconstruction if available. Check results, errors, limits, and state transitions. Report passing cases, divergences, and untested behaviors.",
      },
    ],
    staticFirst: true,
  },
  {
    id: "reap-05",
    skillName: "reap-05-games",
    title: "Games & Simulation Logic",
    category: "games",
    summary:
      "Recover game engine architecture, tick/render loops, physics/scoring constants, and asset serialization pipelines.",
    targetFormats: ["pe", "elf", "macho", "wasm"],
    objectives: ["explore", "trace", "reconstruct"],
    keywords: [
      "game",
      "engine",
      "physics",
      "tick",
      "render loop",
      "scoring",
      "assets",
      "constants",
      "mod",
    ],
    reaToolPipeline: [
      "rea.open_target",
      "rea.triage_binary",
      "rea.search_strings",
      "rea.find_xrefs",
      "rea.decompile_function",
    ],
    evidenceChecklist: [
      ...CORE_EVIDENCE_RULES,
      "Document update/tick order, fixed-timestep constants, and data table offsets.",
      "Keep scope restricted to offline/owned titles and behavioral research.",
    ],
    promptTemplates: [
      {
        name: "Engine & asset pipeline map",
        template:
          "Use REA on <GAME EXECUTABLE>. Identify the engine/framework, render loop, update/tick order, asset serialization/loading, and gameplay data tables. Map each component to functions and addresses.",
      },
    ],
    staticFirst: true,
  },
  {
    id: "reap-06",
    skillName: "reap-06-game-portability-to-wasm",
    title: "Game & Native Portability to WASM",
    category: "portability",
    summary:
      "Assess native binaries for WebAssembly portability: classify rendering, threading, filesystem, and audio APIs into portable, shim, or rewrite.",
    targetFormats: ["wasm", "pe", "elf", "macho"],
    objectives: ["reconstruct", "clone", "explore"],
    keywords: [
      "wasm",
      "webassembly",
      "emscripten",
      "port",
      "webgl",
      "sdl",
      "indexeddb",
      "headless",
    ],
    reaToolPipeline: [
      "rea.open_target",
      "rea.list_imports",
      "rea.trace_call_graph",
      "rea.decompile_function",
      "rea.verify_reconstruction",
    ],
    evidenceChecklist: [
      ...CORE_EVIDENCE_RULES,
      "Classify every OS/graphics/audio/thread dependency as portable as-is, needs shim, or must rewrite.",
      "Isolate pure simulation core first and validate via deterministic state-hash replay.",
    ],
    promptTemplates: [
      {
        name: "Port native game to WASM",
        template:
          "Use REA to analyze <GAME> as a WASM portability target. Map main loop, rendering backend, filesystem/save paths, threading, audio, input, and platform APIs. Classify each as portable / needs shim / must rewrite with call-site evidence.",
      },
    ],
    staticFirst: true,
  },
  {
    id: "reap-07",
    skillName: "reap-07-firmware-and-embedded",
    title: "Firmware & Embedded Systems",
    category: "firmware",
    summary:
      "Triage firmware images, unpack SquashFS/JFFS2/UBI partitions, map load addresses and MMIO, and audit init scripts and services.",
    targetFormats: ["firmware", "elf"],
    objectives: ["explore", "vuln", "trace"],
    keywords: [
      "firmware",
      "embedded",
      "binwalk",
      "squashfs",
      "jffs2",
      "ubi",
      "bootloader",
      "uboot",
      "rtos",
      "mmio",
      "arm",
      "mips",
      "iot",
    ],
    reaToolPipeline: [
      "rea.open_target",
      "rea.scan_firmware_partitions",
      "rea.extract_filesystem",
      "rea.triage_binary",
      "rea.search_strings",
      "rea.decompile_function",
    ],
    evidenceChecklist: [
      ...CORE_EVIDENCE_RULES,
      "Record partition offsets, compression types, entropy profile, architecture, and base load address.",
      "Enumerate init scripts, network daemons, hardcoded credentials, and update-verification routines.",
    ],
    promptTemplates: [
      {
        name: "Firmware image triage",
        template:
          "Use REA to analyze <FIRMWARE IMAGE>. Identify container format, extract partitions/filesystems (JFFS2, SquashFS, UBI, cramfs), map architecture and load addresses, locate kernel and rootfs, and list boot entries, init scripts, and services with offsets and evidence.",
      },
    ],
    staticFirst: true,
  },
  {
    id: "reap-08",
    skillName: "reap-08-android",
    title: "Android APK & Native JNI Analysis",
    category: "mobile",
    summary:
      "Inspect Android manifests, exported components, DEX/Java logic, JNI native bridges, certificate pinning, and local data storage.",
    targetFormats: ["apk", "elf"],
    objectives: ["explore", "vuln", "trace"],
    keywords: [
      "android",
      "apk",
      "dex",
      "smali",
      "jadx",
      "jni",
      "manifest",
      "intent",
      "webview",
      "mobile",
    ],
    reaToolPipeline: [
      "rea.open_target",
      "rea.inspect_android_manifest",
      "rea.decompile_dex",
      "rea.find_jni_bridges",
      "rea.decompile_function",
    ],
    evidenceChecklist: [
      ...CORE_EVIDENCE_RULES,
      "List exported activities, services, broadcast receivers, content providers, and deep-link schemes.",
      "Trace Java/Kotlin -> JNI -> native .so boundaries with method signatures and native offsets.",
    ],
    promptTemplates: [
      {
        name: "APK attack-surface & JNI trace",
        template:
          "Use REA on <APK>. Inspect AndroidManifest.xml for exported components and permissions, trace <FEATURE> through DEX classes into any native JNI libraries, and cite class/method names and native addresses.",
      },
    ],
    staticFirst: true,
  },
  {
    id: "reap-09",
    skillName: "reap-09-kernel-analysis",
    title: "Kernel Analysis",
    category: "kernel",
    summary:
      "Map kernel modules, IOCTL dispatch tables, syscall handlers, minifilter callbacks, and privilege boundaries statically.",
    targetFormats: ["driver", "elf", "pe", "macho"],
    objectives: ["kernel", "explore", "trace"],
    keywords: [
      "kernel",
      "driver",
      "sys",
      "ko",
      "ioctl",
      "irp",
      "syscall",
      "minifilter",
      "ntoskrnl",
      "lkm",
    ],
    reaToolPipeline: [
      "rea.open_target",
      "rea.triage_binary",
      "rea.list_imports",
      "rea.find_ioctl_handlers",
      "rea.decompile_function",
    ],
    evidenceChecklist: [
      ...CORE_EVIDENCE_RULES,
      "Enumerate DriverEntry/module_init, device symbolic links, ACLs, and dispatch tables.",
      "Verify user-pointer probing (ProbeForRead/Write, copy_from_user) and input buffer length validation.",
    ],
    promptTemplates: [
      {
        name: "Driver dispatch & IOCTL map",
        template:
          "Use REA on <DRIVER>. Locate DriverEntry/module_init, device creation/ACL setup, and the IOCTL/syscall dispatch table. List every control code, handler address, expected struct layout, and privilege check.",
      },
    ],
    staticFirst: true,
  },
  {
    id: "reap-10",
    skillName: "reap-10-vulnerability-research",
    title: "Vulnerability Research & Sink Hunting",
    category: "vuln",
    summary:
      "Trust-boundary audits, untrusted source-to-sink tracing, 1-day patch diffing for incomplete fixes, and root-cause crash triage.",
    targetFormats: [
      "pe",
      "elf",
      "macho",
      "firmware",
      "apk",
      "electron",
      "driver",
      "go_rust",
    ],
    objectives: ["vuln", "diff", "trace"],
    keywords: [
      "vulnerability",
      "cve",
      "sink",
      "taint",
      "trust boundary",
      "patch diff",
      "1-day",
      "memcpy",
      "deserialization",
      "command injection",
      "path traversal",
      "crash",
    ],
    reaToolPipeline: [
      "rea.open_target",
      "rea.list_imports",
      "rea.find_xrefs",
      "rea.trace_call_graph",
      "rea.decompile_function",
      "rea.compare_application_versions",
    ],
    evidenceChecklist: [
      ...CORE_EVIDENCE_RULES,
      "For every candidate vulnerability record: input origin, sensitive sink, call chain with addresses, existing checks, preconditions, and controlled validation plan.",
      "Never promote a hypothesis to a confirmed vulnerability without verifying guards on every reaching path.",
    ],
    promptTemplates: [
      {
        name: "Trust-boundary audit",
        template:
          "Use REA to review the security of <AUTHORIZED TARGET>. Prioritize trust boundaries, untrusted input, privileged operations, credential storage, IPC, file handling, and command execution. Present input origin, sink, code path, existing checks, preconditions, evidence, uncertainties, and controlled validation proposal.",
      },
      {
        name: "Sink hunt from untrusted input",
        template:
          "Use REA on <BINARY>. List every untrusted input entry (sockets, files, IPC, CLI, URL handlers) and trace each source to dangerous sinks (memcpy/strcpy, system/exec, dynamic load, deserialization, path join). Cite function chains, addresses, and intermediate validation.",
      },
      {
        name: "Patch diffing for incomplete fixes",
        template:
          "Use REA to compare <VULNERABLE VERSION> and <PATCHED VERSION>. Diff security-relevant functions, identify the added check, and search all callers and sibling routines for missing checks. Label candidate incomplete fixes as hypotheses until validated.",
      },
    ],
    staticFirst: true,
  },
  {
    id: "reap-11",
    skillName: "reap-11-electron-and-javascript",
    title: "Electron & JavaScript Applications",
    category: "electron",
    summary:
      "Unpack ASAR archives, audit Electron main/preload/renderer IPC bridges, contextIsolation/nodeIntegration flags, and bundled JS.",
    targetFormats: ["electron", "js"],
    objectives: ["explore", "vuln", "trace", "deobfuscate"],
    keywords: [
      "electron",
      "asar",
      "javascript",
      "preload",
      "ipc",
      "contextBridge",
      "nodeIntegration",
      "webpack",
      "bundle",
      "sourcemap",
    ],
    reaToolPipeline: [
      "rea.open_target",
      "rea.unpack_asar",
      "rea.search_strings",
      "rea.inspect_ipc_channels",
      "rea.deobfuscate_js",
    ],
    evidenceChecklist: [
      ...CORE_EVIDENCE_RULES,
      "Inventory BrowserWindow webPreferences (nodeIntegration, contextIsolation, sandbox, webSecurity).",
      "Map every ipcMain.handle/on channel and contextBridge.exposeInMainWorld surface to its handler.",
    ],
    promptTemplates: [
      {
        name: "Electron IPC & preload security map",
        template:
          "Use REA on <ELECTRON APP>. Unpack app.asar, enumerate BrowserWindow security flags, map every preload contextBridge exposure and ipcMain handler, and trace untrusted renderer inputs to privileged Node/OS sinks with file:line evidence.",
      },
    ],
    staticFirst: true,
  },
  {
    id: "reap-12",
    skillName: "reap-12-anti-cheat-and-protection-research",
    title: "Anti-Cheat & Protection Research",
    category: "protection",
    summary:
      "Document integrity checks, telemetry pipelines, anti-debug hooks, and kernel/user protection architectures defensively.",
    targetFormats: ["pe", "driver", "elf"],
    objectives: ["deobfuscate", "kernel", "explore"],
    keywords: [
      "anti-cheat",
      "protection",
      "integrity",
      "anti-debug",
      "attestation",
      "telemetry",
      "tamper",
    ],
    reaToolPipeline: [
      "rea.open_target",
      "rea.triage_binary",
      "rea.list_imports",
      "rea.find_xrefs",
      "rea.decompile_function",
    ],
    evidenceChecklist: [
      ...CORE_EVIDENCE_RULES,
      "Document detection signals, integrity hash loops, and user-kernel communication channels with addresses.",
      "Restrict to authorized defensive evaluation and hardening assessment.",
    ],
    promptTemplates: [
      {
        name: "Protection architecture map",
        template:
          "Use REA on <AUTHORIZED BINARY>. Document the integrity verification, anti-debug checks, and telemetry reporting architecture. Cite proving functions and addresses; document structure without bypassing third-party protections.",
      },
    ],
    staticFirst: true,
  },
  {
    id: "reap-13",
    skillName: "reap-13-dma-and-hardware-assisted-cheat-research-defensive",
    title: "DMA & Hardware-Assisted Interface Research (Defensive)",
    category: "hardware",
    summary:
      "Defensive analysis of PCIe/DMA memory-access protections (IOMMU/VT-d, BAR mappings), FPGA/MCU bus firmware, and exposed hardware debug/bus attack surfaces (JTAG, SWD, UART, SPI flash).",
    targetFormats: ["firmware", "driver", "pe", "elf"],
    objectives: ["kernel", "explore", "vuln"],
    keywords: [
      "dma",
      "pcie",
      "iommu",
      "vt-d",
      "thunderbolt",
      "bar",
      "fpga",
      "jtag",
      "swd",
      "kicad",
      "hardware-assisted",
    ],
    reaToolPipeline: [
      "rea.open_target",
      "rea.triage_binary",
      "rea.scan_firmware_partitions",
      "rea.find_xrefs",
      "rea.decompile_function",
    ],
    evidenceChecklist: [
      ...CORE_EVIDENCE_RULES,
      "Document IOMMU/VT-d protection checks, PCIe BAR mappings, and physical debug/bus interfaces with concrete offsets or net designators.",
      "Restrict strictly to owned lab hardware, defensive posture assessment, and authorized firmware dumps.",
    ],
    promptTemplates: [
      {
        name: "Platform DMA & IOMMU protection audit",
        template:
          "Use REA on <AUTHORIZED DRIVER OR FIRMWARE> in my lab. Explain with function/address evidence how external PCIe/DMA memory access is restricted (IOMMU/VT-d mappings, BAR regions, root-port checks) and which checks are load-bearing vs cosmetic.",
      },
      {
        name: "FPGA/MCU device firmware & hardware bus study",
        template:
          "Use REA on <OWNED DEVICE FIRMWARE / HARDWARE ARTIFACT>. Identify the MCU/FPGA architecture, exposed debug/bus interfaces (JTAG, SWD, UART, SPI, I2C, PCIe), host protocol handlers, and memory-read primitives with proving addresses.",
      },
    ],
    staticFirst: true,
  },
  {
    id: "reap-15",
    skillName: "reap-15-version-comparison-and-crash-work",
    title: "Version Comparison & Crash Analysis",
    category: "diff",
    summary:
      "Diff two application versions to separate build noise from behavioral/security changes, and triage crash dumps/stack traces to root cause.",
    targetFormats: ["diff", "crash", "pe", "elf", "macho", "electron", "apk"],
    objectives: ["diff", "vuln", "trace"],
    keywords: [
      "version",
      "compare",
      "diff",
      "patch",
      "crash",
      "stack trace",
      "minidump",
      "coredump",
      "regression",
      "compare_application_versions",
    ],
    reaToolPipeline: [
      "rea.compare_application_versions",
      "rea.diff_functions",
      "rea.decompile_function",
      "rea.find_xrefs",
      "rea.audit_residual_unknowns",
    ],
    evidenceChecklist: [
      ...CORE_EVIDENCE_RULES,
      "Differentiate compiler/build-noise diffs from genuine behavior, API, permission, or security-check changes.",
      "For crashes, correlate faulting address/register state to candidate root-cause hypotheses and smallest distinguishing test.",
    ],
    promptTemplates: [
      {
        name: "Compare two versions",
        template:
          "Use compare_application_versions (if available) to compare <OLD VERSION> and <NEW VERSION> of <APPLICATION>. Identify functional, API, dependency, permission, and security-fix changes. Map each change to functions/files with addresses and separate build noise from behavior changes.",
      },
      {
        name: "Crash triage to root cause",
        template:
          "Use REA to investigate this crash in <APPLICATION> using <STACK TRACE / DUMP / LOGS>. Map faulting frames to decompiled functions, rank hypotheses with supporting evidence, and propose the smallest experiment to confirm root cause.",
      },
    ],
    staticFirst: true,
  },
  {
    id: "reap-16",
    skillName: "reap-16-long-running-investigations",
    title: "Long-Running Evidence-Ledger Investigations",
    category: "methodology",
    summary:
      "Maintain persistent INVESTIGATION.md ledgers, audit residual unknowns, prune discarded hypotheses, and prioritize uncertainty-reducing next steps.",
    targetFormats: [
      "pe",
      "elf",
      "macho",
      "firmware",
      "apk",
      "electron",
      "driver",
      "go_rust",
      "diff",
    ],
    objectives: ["explore", "trace", "vuln", "reconstruct"],
    keywords: [
      "investigation",
      "ledger",
      "unknowns",
      "audit_residual_unknowns",
      "resume",
      "continuity",
      "evidence",
      "hypothesis",
    ],
    reaToolPipeline: [
      "rea.audit_residual_unknowns",
      "rea.list_evidence",
      "rea.decompile_function",
      "rea.find_xrefs",
    ],
    evidenceChecklist: [
      ...CORE_EVIDENCE_RULES,
      "Run audit_residual_unknowns before declaring an investigation complete.",
      "Maintain INVESTIGATION.md with four explicit sections: Confirmed Findings, Discarded Hypotheses, Residual Unknowns, and Highest-Leverage Next Steps.",
    ],
    promptTemplates: [
      {
        name: "Continue where you left off",
        template:
          "Review the evidence and notes of this investigation. Use audit_residual_unknowns (if available) to list what has not been demonstrated yet. Prioritize the next analyses by uncertainty reduction and update INVESTIGATION.md with findings, evidence, discarded hypotheses, and next steps.",
      },
    ],
    staticFirst: true,
  },
  {
    id: "reap-17",
    skillName: "reap-17-malware-analysis",
    title: "Malware Analysis & Threat Intelligence",
    category: "malware",
    summary:
      "Static-first malware triage, C2 config/protocol extraction, persistence/injection/evasion inventory, stage-chain mapping, and YARA/IOC generation.",
    targetFormats: ["pe", "elf", "macho", "js", "apk", "go_rust"],
    objectives: ["malware", "deobfuscate", "explore"],
    keywords: [
      "malware",
      "c2",
      "beacon",
      "yara",
      "ioc",
      "ransomware",
      "loader",
      "dropper",
      "persistence",
      "injection",
      "evasion",
      "sandbox",
    ],
    reaToolPipeline: [
      "rea.open_target",
      "rea.triage_binary",
      "rea.list_imports",
      "rea.search_strings",
      "rea.extract_config",
      "rea.decompile_function",
    ],
    evidenceChecklist: [
      ...CORE_EVIDENCE_RULES,
      "Never execute malware outside an isolated detonation sandbox.",
      "Separate family-stable code patterns (for YARA rules) from sample-specific obfuscated IOCs.",
      "Map capability claims (persistence, injection, C2, evasion) to exact API calls and addresses.",
    ],
    promptTemplates: [
      {
        name: "Static triage and capability map",
        template:
          "Use REA on malware sample <PATH> (authorized IR/threat-intel). Produce a static triage report: file type, compiler/packer indicators, imports grouped by capability (persistence, credential theft, C2, injection, evasion), suspicious strings with addresses, and embedded configs. Do not execute the sample.",
      },
      {
        name: "C2 protocol and config extraction",
        template:
          "Use REA on <MALWARE SAMPLE> to recover C2 endpoint construction, decode routines/keys, beacon fields, tasking commands, and fallback infra. Emit a protocol spec and parser with proving addresses.",
      },
    ],
    staticFirst: true,
  },
  {
    id: "reap-18",
    skillName: "reap-18-advanced-binary-exploration-and-deobfuscation",
    title: "Advanced Binary Exploration & Deobfuscation",
    category: "deobfuscation",
    summary:
      "Recover control-flow flattened dispatchers, string/constant decryptors, opaque predicates, VM handler tables, structs, and custom calling conventions.",
    targetFormats: ["pe", "elf", "macho", "driver"],
    objectives: ["deobfuscate", "explore", "reconstruct"],
    keywords: [
      "deobfuscation",
      "cff",
      "control-flow flattening",
      "opaque predicate",
      "string decryption",
      "vm",
      "virtualized",
      "struct recovery",
      "calling convention",
      "cfg",
    ],
    reaToolPipeline: [
      "rea.open_target",
      "rea.inspect_cfg",
      "rea.decompile_function",
      "rea.disassemble_range",
      "rea.find_xrefs",
      "rea.apply_types",
    ],
    evidenceChecklist: [
      ...CORE_EVIDENCE_RULES,
      "Document dispatcher state variables, state-to-block mappings, and provably constant opaque predicates with address ranges.",
      "For recovered structs, cite the exact load/store instruction address proving each field offset and width.",
    ],
    promptTemplates: [
      {
        name: "Control-flow flattening recovery",
        template:
          "Use REA on <BINARY>. Identify the dispatcher state variable for <FEATURE>, map each state to its real basic block, reconstruct original logical flow as pseudocode/graph with address ranges, and note any ambiguous states.",
      },
      {
        name: "String and constant decryption pass",
        template:
          "Use REA on <BINARY>. Locate string-decryption routine(s), recover algorithm and keys with addresses, produce a decrypted string table with referencing functions, and emit an offline decoder script if uniform.",
      },
      {
        name: "Struct & type recovery from access patterns",
        template:
          "Use REA on <BINARY>. Reconstruct the struct operated on by <FUNCTION> field by field from access offsets and widths. Emit a C header with per-field proving address comments.",
      },
    ],
    staticFirst: true,
  },
  {
    id: "reap-19",
    skillName: "reap-19-kernel-and-driver-exploitation-research",
    title: "Kernel & Driver Vulnerability Research",
    category: "kernel",
    summary:
      "Rank kernel attack surfaces, audit IOCTL R/W primitives, hunt TOCTOU/race and refcount UAF bugs, and validate CVE patch completeness.",
    targetFormats: ["driver", "pe", "elf"],
    objectives: ["kernel", "vuln", "diff"],
    keywords: [
      "driver",
      "byovd",
      "ioctl",
      "toctou",
      "race",
      "uaf",
      "refcount",
      "ssdt",
      "ntoskrnl",
      "kernel exploit",
      "primitive",
    ],
    reaToolPipeline: [
      "rea.open_target",
      "rea.find_ioctl_handlers",
      "rea.decompile_function",
      "rea.trace_call_graph",
      "rea.compare_application_versions",
    ],
    evidenceChecklist: [
      ...CORE_EVIDENCE_RULES,
      "Document alloc/free/use address triples for UAF candidates and racing IRQL/lock contexts for TOCTOU candidates.",
      "Restrict to authorized lab drivers, CVE validation, and defensive hardening.",
    ],
    promptTemplates: [
      {
        name: "Kernel attack-surface ranking",
        template:
          "Use REA on <KERNEL MODULE / DRIVER>. Enumerate all user-reachable entry points (IOCTLs, syscalls, netlink, minifilter callbacks), assess input validation depth and privilege context, and rank top 3 targets with evidence.",
      },
      {
        name: "Reference-count / lifetime bug hunt",
        template:
          "Use REA on <DRIVER>. Trace alloc/free and refcount pairs for stale-pointer or decrement-then-use windows. Cite alloc/free/use address triples and label every finding as hypothesis until validated.",
      },
    ],
    staticFirst: true,
  },
  {
    id: "reap-20",
    skillName: "reap-20-advanced-software-cloning-and-feature-reconstruction",
    title: "Advanced Cloning, Reconstruction & Obligation Ledgers",
    category: "reconstruction",
    summary:
      "Full protocol/ABI/state-machine reconstruction with behavioral equivalence harnesses and obligation ledgers (PASS / FAIL / NOT-TESTED per spec item).",
    targetFormats: ["pe", "elf", "macho", "electron", "js", "wasm", "go_rust"],
    objectives: ["reconstruct", "clone"],
    keywords: [
      "reconstruction",
      "obligation ledger",
      "protocol",
      "abi",
      "plugin",
      "state machine",
      "differential test",
      "equivalence harness",
      "algorithm",
    ],
    reaToolPipeline: [
      "rea.open_target",
      "rea.trace_call_graph",
      "rea.decompile_function",
      "rea.extract_constants",
      "rea.verify_reconstruction",
      "rea.audit_residual_unknowns",
    ],
    evidenceChecklist: [
      ...CORE_EVIDENCE_RULES,
      "Maintain an obligation ledger mapping every spec requirement to PASS / FAIL / NOT-TESTED with differential test corpus results.",
      "Cite marshal/unmarshal addresses for protocol fields and host callback table offsets for plugin ABIs.",
    ],
    promptTemplates: [
      {
        name: "Behavioral equivalence harness",
        template:
          "Build a differential-testing harness between <MY CLONE> and <ORIGINAL APPLICATION> derived from CLONE_SPEC.md. Run both sides on normal, boundary, and malformed inputs and emit an obligation ledger marking every spec item PASS / FAIL / NOT-TESTED.",
      },
      {
        name: "State machine / business-logic reconstruction",
        template:
          "Use REA on <APPLICATION> to enumerate states, transitions, guards, and side effects for <WORKFLOW> with proving addresses. Implement the state machine and replay tests covering every documented transition.",
      },
    ],
    staticFirst: true,
  },
  {
    id: "reap-21",
    skillName: "reap-21-protector-and-obfuscator-research",
    title: "Protector & Obfuscator Research",
    category: "deobfuscation",
    summary:
      "Fingerprint packers, VM protectors, import-table obfuscation, anti-tamper layers, and runtime unpacking stubs.",
    targetFormats: ["pe", "elf", "macho", "apk", "js"],
    objectives: ["deobfuscate", "malware", "explore"],
    keywords: [
      "protector",
      "obfuscator",
      "packer",
      "upx",
      "vmprotect",
      "themida",
      "iat",
      "oep",
      "entropy",
      "unpack",
    ],
    reaToolPipeline: [
      "rea.open_target",
      "rea.triage_binary",
      "rea.inspect_sections",
      "rea.disassemble_range",
      "rea.inspect_cfg",
    ],
    evidenceChecklist: [
      ...CORE_EVIDENCE_RULES,
      "Record section entropy, RWX segments, TLS callbacks, stub entry point, and import resolution patterns.",
      "Document protector mechanics and boundaries before proposing any controlled unpacking experiment.",
    ],
    promptTemplates: [
      {
        name: "Packer & protector fingerprint",
        template:
          "Use REA on <BINARY>. Analyze section entropy, entry stub, TLS callbacks, import reconstruction, and VM/obfuscation signatures to classify the protector/packer layer with address evidence.",
      },
    ],
    staticFirst: true,
  },
  {
    id: "reap-22",
    skillName: "reap-22-go-and-rust-binary-source-recovery",
    title: "Go & Rust Binary Source Recovery",
    category: "go_rust",
    summary:
      "Metadata-first recovery for Go (pclntab, moduledata, itabs, ABIInternal) and Rust (panic strings, crate paths, vtables, Result/Option idioms) with fidelity grading.",
    targetFormats: ["go_rust", "pe", "elf", "macho"],
    objectives: ["reconstruct", "explore", "trace", "vuln"],
    keywords: [
      "go",
      "golang",
      "rust",
      "pclntab",
      "moduledata",
      "itab",
      "goroutine",
      "crate",
      "panic",
      "vtable",
      "monomorphized",
      "stripped",
    ],
    reaToolPipeline: [
      "rea.open_target",
      "rea.recover_go_pclntab",
      "rea.recover_rust_metadata",
      "rea.search_strings",
      "rea.decompile_function",
      "rea.audit_residual_unknowns",
    ],
    evidenceChecklist: [
      ...CORE_EVIDENCE_RULES,
      "Extract surviving metadata first (Go pclntab/moduledata/runtime.types; Rust panic strings/#[track_caller] paths/vtable layouts) even on stripped binaries.",
      "Grade every recovered module honestly in RECOVERY_REPORT.md: symbol-exact, structure-exact, or behavior-only.",
    ],
    promptTemplates: [
      {
        name: "Go binary symbol & package map",
        template:
          "Use REA on <GO BINARY>. Recover package layout from pclntab/moduledata, Go version, build ID, embedded dependencies, and main.main/main.init call graph. Deliver a package tree with proving addresses.",
      },
      {
        name: "Rust binary logic recovery with trait-dispatch awareness",
        template:
          "Use REA on <RUST BINARY>. Recover crate/module tree from panic strings and symbol paths, then produce pseudocode for <FEATURE> accounting for Result/Option discriminants, drop glue, vtable trait dispatch, and inlined iterators. Cite addresses and mark inferred names as hypotheses.",
      },
      {
        name: "Stripped Go/Rust metadata-first triage",
        template:
          "Use REA on <STRIPPED GO/RUST BINARY>. Reconstruct function-name -> address map from surviving pclntab or panic/file-path metadata before analyzing <FEATURE>, and report what metadata survived vs what is irrecoverably gone.",
      },
    ],
    staticFirst: true,
  },
  {
    id: "reap-wildcard",
    skillName: "reap-wildcard",
    title: "REAP Wildcard Investigation Starter",
    category: "general",
    summary:
      "Universal static-first starter prompt for any unfamiliar target: verify available tools, trace one feature, separate facts from hypotheses, and emit a spec + test plan.",
    targetFormats: [
      "pe",
      "elf",
      "macho",
      "firmware",
      "apk",
      "electron",
      "js",
      "wasm",
      "driver",
      "go_rust",
      "crash",
      "diff",
    ],
    objectives: ["explore", "trace", "vuln", "clone", "reconstruct"],
    keywords: ["wildcard", "start", "general", "unknown", "any", "unfamiliar"],
    reaToolPipeline: [
      "rea.list_capabilities",
      "rea.open_target",
      "rea.triage_binary",
      "rea.search_strings",
      "rea.decompile_function",
    ],
    evidenceChecklist: [
      ...CORE_EVIDENCE_RULES,
      "Verify which analysis engines/tools are actually available before committing to a workflow.",
      "End with a concrete behavioral specification and verification test proposal.",
    ],
    promptTemplates: [
      {
        name: "Wildcard starter prompt",
        template:
          "Use REA to understand how <FEATURE> works in <PATH TO APPLICATION>. Check first which tools are actually available. Start with static analysis and trace the feature down to the responsible functions. Present evidence for each conclusion, separate facts from hypotheses, record limitations, and end with a behavioral spec and test plan.",
      },
    ],
    staticFirst: true,
  },
  {
    id: "reap-prompt-writing-tips",
    skillName: "reap-prompt-writing-tips",
    title: "REAP Prompt-Writing Discipline",
    category: "methodology",
    summary:
      "Six rules that make RE agent prompts reliable: one feature per prompt, mandatory address evidence, fact/inference/unknown buckets, static-first, concrete deliverables, and explicit scope.",
    targetFormats: [
      "pe",
      "elf",
      "macho",
      "firmware",
      "apk",
      "electron",
      "js",
      "wasm",
      "driver",
      "go_rust",
      "crash",
      "diff",
    ],
    objectives: ["explore", "trace", "reconstruct"],
    keywords: [
      "prompt",
      "tips",
      "craft",
      "methodology",
      "discipline",
      "evidence",
    ],
    reaToolPipeline: ["rea.list_capabilities", "rea.audit_residual_unknowns"],
    evidenceChecklist: [
      "Scope each request to one feature rather than asking to explain the entire application.",
      "Require file/function/address evidence for every claim to prevent confabulation.",
      "Enforce the three-bucket output format: Confirmed Facts / Inferences / Residual Unknowns.",
      "Require a concrete deliverable (SPEC.md, reader script, port plan, or test harness).",
    ],
    promptTemplates: [
      {
        name: "REAP prompt quality checklist",
        template:
          "Refine this RE task into a narrow single-feature REAP prompt with: (1) explicit authorized scope, (2) static-first constraint, (3) mandatory file/function/address citations, (4) Fact/Inference/Unknown separation, and (5) a concrete verifiable deliverable.",
      },
    ],
    staticFirst: true,
  },
];

const FORMAT_ALIASES: ReadonlyArray<readonly [RegExp, ReapTargetFormat]> = [
  [/\b(go_rust|golang|go\b|rust|pclntab|cargo)\b/i, "go_rust"],
  [
    /\b(firmware|embedded|squashfs|jffs2|ubi|uboot|u-boot|rtos|iot|binwalk|ihex|srec|s-record|kicad|jtag|swd|eda|\.img|\.bin|\.hex|\.ihex|\.srec|\.s19|\.mot|\.dts|\.dtsi|\.kicad_sch|\.kicad_pcb)\b/i,
    "firmware",
  ],
  [/\b(apk|android|dex|smali|jadx|jni|aab)\b/i, "apk"],
  [/\b(electron|asar|ipcmain|contextbridge)\b/i, "electron"],
  [/\b(wasm|webassembly|emscripten)\b/i, "wasm"],
  [/\b(driver|kernel|ntoskrnl|ioctl|byovd|lkm|\.sys|\.ko)\b/i, "driver"],
  [/\b(crash|minidump|coredump|stack\s*trace|segfault|dump)\b/i, "crash"],
  [
    /\b(diff|patch\s*diff|version\s*compar|compare\s*version|v1.*v2|upgrade)\b/i,
    "diff",
  ],
  [/\b(js|javascript|typescript|node|webpack|bundle)\b/i, "js"],
  [/\b(macho|mach-o|dylib|macos|ios)\b/i, "macho"],
  [/\b(elf|\.so\b|linux)\b/i, "elf"],
  [/\b(pe|pe32|pe64|win32|win64|windows|\.exe|\.dll)\b/i, "pe"],
];

const OBJECTIVE_ALIASES: ReadonlyArray<readonly [RegExp, ReapObjective]> = [
  [
    /\b(malware|ransomware|c2|beacon|dropper|loader|ioc|yara|trojan|wiper)\b/i,
    "malware",
  ],
  [
    /\b(deobfuscat\w*|obfuscat\w*|unpack\w*|packer|protector|cff|flattening|vmprotect|themida|anti-cheat|opaque)\b/i,
    "deobfuscate",
  ],
  [/\b(kernel|driver|ioctl|byovd|ssdt|uaf|toctou|minifilter)\b/i, "kernel"],
  [
    /\b(vuln\w*|cve|sink|taint|audit|trust[- ]boundary|exploit\w*|security|1-day)\b/i,
    "vuln",
  ],
  [/\b(diff|compar\w*|patch|regression|crash|root[- ]cause)\b/i, "diff"],
  [
    /\b(reconstruct\w*|obligation|abi|protocol|state[- ]machine|port|wasm|recovery|source[- ]recovery)\b/i,
    "reconstruct",
  ],
  [/\b(clone|clean[- ]room|reimplement\w*|parity|spec)\b/i, "clone"],
  [/\b(trace|feature|button|workflow|flow|rule)\b/i, "trace"],
  [/\b(explore|triage|map|understand|imports|strings|overview)\b/i, "explore"],
];

function normalizeFormat(input?: string): ReapTargetFormat | undefined {
  if (!input || !input.trim()) return undefined;
  const trimmed = input.trim().toLowerCase();
  const direct: readonly ReapTargetFormat[] = [
    "pe",
    "elf",
    "macho",
    "firmware",
    "apk",
    "electron",
    "js",
    "wasm",
    "driver",
    "go_rust",
    "crash",
    "diff",
  ];
  if ((direct as readonly string[]).includes(trimmed)) {
    return trimmed as ReapTargetFormat;
  }
  for (const [re, fmt] of FORMAT_ALIASES) {
    if (re.test(input)) return fmt;
  }
  return undefined;
}

function normalizeObjective(input?: string): ReapObjective | undefined {
  if (!input || !input.trim()) return undefined;
  const trimmed = input.trim().toLowerCase();
  const direct: readonly ReapObjective[] = [
    "clone",
    "trace",
    "vuln",
    "diff",
    "deobfuscate",
    "malware",
    "reconstruct",
    "kernel",
    "explore",
  ];
  if ((direct as readonly string[]).includes(trimmed)) {
    return trimmed as ReapObjective;
  }
  for (const [re, obj] of OBJECTIVE_ALIASES) {
    if (re.test(input)) return obj;
  }
  return undefined;
}

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .split(/[^a-z0-9_+-]+/)
    .filter((t) => t.length >= 2);
}

/**
 * Deterministically match target format, target type, and objective to ranked REAP playbooks,
 * synthesizing a deduplicated REA MCP tool pipeline, evidence checklist, and prompt templates.
 */
export function selectReapPlaybooks(
  query: ReapSelectionQuery = {},
): ReapSelectionResult {
  const maxRaw = query.maxPlaybooks ?? 3;
  const maxPlaybooks = Math.max(
    1,
    Math.min(10, Number.isFinite(maxRaw) ? Math.floor(maxRaw) : 3),
  );

  const combinedText = [
    query.binaryFormat ?? "",
    query.targetType ?? "",
    query.objective ?? "",
  ]
    .join(" ")
    .trim();

  const normalizedFormat =
    normalizeFormat(query.binaryFormat) ??
    normalizeFormat(query.targetType) ??
    normalizeFormat(query.objective);

  const normalizedObjective =
    normalizeObjective(query.objective) ?? normalizeObjective(query.targetType);

  const tokens = tokenize(combinedText);

  const scored: ReapPlaybookMatch[] = [];

  for (const playbook of REAP_PLAYBOOKS) {
    let score = 0;
    const matchedFactors: string[] = [];

    if (normalizedFormat && playbook.targetFormats.includes(normalizedFormat)) {
      // Reward specialist playbooks that tightly target this format over catch-alls.
      const specificityBonus = Math.max(0, 12 - playbook.targetFormats.length);
      score += 30 + specificityBonus;
      matchedFactors.push(`format:${normalizedFormat}`);
    }

    if (
      normalizedObjective &&
      playbook.objectives.includes(normalizedObjective)
    ) {
      const specificityBonus = Math.max(0, 8 - playbook.objectives.length);
      score += 28 + specificityBonus;
      matchedFactors.push(`objective:${normalizedObjective}`);
    }

    // Penalize meta/catch-all packs slightly when a specialist pack matches.
    if (
      (playbook.id === "reap-wildcard" ||
        playbook.id === "reap-prompt-writing-tips") &&
      (normalizedFormat || normalizedObjective)
    ) {
      score = Math.max(0, score - 25);
    }

    const haystack =
      `${playbook.title} ${playbook.summary} ${playbook.category}`.toLowerCase();
    const matchedKeywords = new Set<string>();
    for (const token of tokens) {
      if (playbook.keywords.some((kw) => kw.toLowerCase().includes(token))) {
        if (!matchedKeywords.has(token)) {
          matchedKeywords.add(token);
          score += 8;
        }
      } else if (haystack.includes(token)) {
        if (!matchedKeywords.has(token)) {
          matchedKeywords.add(token);
          score += 4;
        }
      }
    }
    if (matchedKeywords.size > 0) {
      matchedFactors.push(
        `keywords:${Array.from(matchedKeywords).sort().join(",")}`,
      );
    }

    if (score > 0) {
      scored.push({ playbook, score, matchedFactors });
    }
  }

  let matches: ReapPlaybookMatch[];
  if (scored.length === 0) {
    const fallbackIds = ["reap-wildcard", "reap-02", "reap-03"];
    matches = fallbackIds
      .map((id) => REAP_PLAYBOOKS.find((p) => p.id === id))
      .filter((p): p is ReapPlaybook => p !== undefined)
      .slice(0, maxPlaybooks)
      .map((playbook, idx) => ({
        playbook,
        score: 10 - idx,
        matchedFactors: ["fallback:general"],
      }));
  } else {
    scored.sort((a, b) => {
      if (b.score !== a.score) return b.score - a.score;
      if (a.playbook.targetFormats.length !== b.playbook.targetFormats.length) {
        return (
          a.playbook.targetFormats.length - b.playbook.targetFormats.length
        );
      }
      return a.playbook.id.localeCompare(b.playbook.id);
    });
    matches = scored.slice(0, maxPlaybooks);
  }

  const pipelineSet = new Set<string>();
  const checklistSet = new Set<string>();
  const renderedPrompts: ReapSelectionResult["renderedPrompts"] = [];

  for (const { playbook } of matches) {
    for (const step of playbook.reaToolPipeline) pipelineSet.add(step);
    for (const item of playbook.evidenceChecklist) checklistSet.add(item);
    for (const tmpl of playbook.promptTemplates) {
      renderedPrompts.push({
        playbookId: playbook.id,
        name: tmpl.name,
        prompt: tmpl.template,
      });
    }
  }

  return {
    normalizedFormat,
    normalizedObjective,
    matches,
    recommendedPipeline: Array.from(pipelineSet),
    evidenceChecklist: Array.from(checklistSet),
    renderedPrompts,
  };
}

export function getReapPlaybookById(id: string): ReapPlaybook | undefined {
  const normalized = id.trim().toLowerCase();
  return REAP_PLAYBOOKS.find(
    (p) =>
      p.id.toLowerCase() === normalized ||
      p.skillName.toLowerCase() === normalized,
  );
}

function formatSelectionOutput(result: ReapSelectionResult): string {
  const lines: string[] = [
    `REAP Playbook Selection (format=${result.normalizedFormat ?? "any"}, objective=${result.normalizedObjective ?? "any"}):`,
    "",
    "Matched Playbooks:",
  ];
  for (const m of result.matches) {
    lines.push(
      `  - [${m.playbook.id}] ${m.playbook.title} (skill=${m.playbook.skillName}, score=${m.score}, factors=${m.matchedFactors.join("; ")})`,
      `      ${m.playbook.summary}`,
    );
  }
  lines.push(
    "",
    `Recommended REA MCP Pipeline (${result.recommendedPipeline.length} steps):`,
    `  ${result.recommendedPipeline.join(" -> ")}`,
    "",
    "Evidence & Unknown-Tracking Checklist:",
    ...result.evidenceChecklist.map((item) => `  - ${item}`),
    "",
    "Prompt Templates:",
    ...result.renderedPrompts.map(
      (p) => `  [${p.playbookId} :: ${p.name}]\n    ${p.prompt}`,
    ),
  );
  return lines.join("\n");
}

export const reapPlaybookTool: CustomTool = {
  name: "reap_playbook",
  description:
    "Select ranked REAP (REA-Prompts) reverse-engineering playbooks, REA MCP tool pipelines, evidence/unknown-tracking checklists, and prompt templates for a target binary/format and objective",
  category: "re",
  parameters: [
    {
      name: "target_type",
      type: "string",
      description:
        "Target description or artifact type (e.g. 'Windows PE executable', 'SquashFS firmware', 'Android APK', 'Electron app', 'stripped Go binary', 'kernel driver')",
      required: false,
    },
    {
      name: "objective",
      type: "string",
      description:
        "Investigation objective: explore | trace | vuln | clone | reconstruct | diff | deobfuscate | malware | kernel (or free-text description)",
      required: false,
    },
    {
      name: "binary_format",
      type: "string",
      description:
        "Target format: pe | elf | macho | firmware | apk | electron | js | wasm | driver | go_rust | crash | diff",
      required: false,
    },
    {
      name: "playbook_id",
      type: "string",
      description:
        "Optional direct REAP playbook ID or skill name (e.g. 'reap-10', 'reap-18', 'reap-22')",
      required: false,
    },
    {
      name: "max_playbooks",
      type: "number",
      description: "Maximum playbooks to return (1-10, default 3)",
      required: false,
    },
  ],
  handler: async (context) => {
    const playbookId =
      typeof context.parameters.playbook_id === "string"
        ? context.parameters.playbook_id.trim()
        : "";

    if (playbookId) {
      const direct = getReapPlaybookById(playbookId);
      if (!direct) {
        return {
          success: false,
          error: `reap_playbook: unknown playbook_id "${playbookId}". Available IDs: ${REAP_PLAYBOOKS.map((p) => p.id).join(", ")}`,
        };
      }
      const singleResult: ReapSelectionResult = {
        normalizedFormat: direct.targetFormats[0],
        normalizedObjective: direct.objectives[0],
        matches: [
          {
            playbook: direct,
            score: 100,
            matchedFactors: [`direct:${direct.id}`],
          },
        ],
        recommendedPipeline: [...direct.reaToolPipeline],
        evidenceChecklist: [...direct.evidenceChecklist],
        renderedPrompts: direct.promptTemplates.map((t) => ({
          playbookId: direct.id,
          name: t.name,
          prompt: t.template,
        })),
      };
      return {
        success: true,
        output: formatSelectionOutput(singleResult),
      };
    }

    const targetType =
      typeof context.parameters.target_type === "string"
        ? context.parameters.target_type
        : context.target?.address;
    const objective =
      typeof context.parameters.objective === "string"
        ? context.parameters.objective
        : undefined;
    const binaryFormat =
      typeof context.parameters.binary_format === "string"
        ? context.parameters.binary_format
        : undefined;
    const maxRaw = Number(context.parameters.max_playbooks);
    const maxPlaybooks =
      Number.isFinite(maxRaw) && maxRaw > 0 ? maxRaw : undefined;

    const result = selectReapPlaybooks({
      targetType,
      objective,
      binaryFormat,
      maxPlaybooks,
    });

    return {
      success: true,
      output: formatSelectionOutput(result),
    };
  },
};
