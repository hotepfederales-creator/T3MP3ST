/**
 * T3MP3ST firmware_audit_scan — Hardware EDA & Embedded Firmware Security Scanner.
 *
 * Pure Node.js built-ins only (zero external dependencies), confined strictly to
 * T3MP3ST_SOURCE_ROOT via canonical lstatSync + realpathSync containment so
 * out-of-root paths, escaping symlinks, FIFOs/devices, and oversized blobs fail closed.
 *
 * Capabilities:
 *   1. Intel HEX (.hex / .ihex) & Motorola S-Record (.srec / .s19 / .s28 / .s37 / .mot)
 *      decoders with per-record byte-checksum verification (corrupted_checksum CWE-353),
 *      contiguous memory-segment coalescing, and address-attributed ASCII + UTF-16LE
 *      string extraction.
 *   2. ELF32/ELF64, raw firmware blob, U-Boot uImage/FIT/environment, and Device-Tree
 *      (.dts / .dtsi) security analyzer: architecture/endianness/bitness triage,
 *      PT_GNU_STACK RWX & PIE vs ET_EXEC hardening checks, uImage (0x27051956) &
 *      FDT/FIT (0xd00dfeed) header parsing, bootdelay/bootcmd/tftpboot injection
 *      vectors, redacted hardcoded credential/PSK/JWT/private-key detection, and
 *      unsafe C/RTOS memory & command sinks (strcpy, sprintf, vsprintf, gets,
 *      scanf("%s"), system, popen).
 *   3. KiCad S-expression Hardware EDA schematic & PCB attack-surface scanner
 *      (.kicad_sch, .kicad_pcb): identifies exposed JTAG, SWD, UART, SPI_FLASH/SOIC8,
 *      BOOT0/BOOT_SEL straps, and unauthenticated I2C EEPROM buses on connectors and
 *      test points (J*, TP*, P*), including unpopulated/DNP pogo-pin headers.
 */

import {
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync,
  statSync,
  type Stats,
} from "fs";
import {
  basename,
  extname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "path";
import { SECRET_PATTERNS, redactString } from "../redact.js";
import type {
  CustomTool,
  Severity,
  ToolContext,
  ToolFinding,
} from "../types/index.js";
import { getReapPlaybookById } from "./reap-playbooks.js";

export const DEFAULT_MAX_FIRMWARE_BYTES = 16 * 1024 * 1024;

export type FirmwareArtifactFormat =
  | "ihex"
  | "srec"
  | "elf"
  | "dts"
  | "kicad_sch"
  | "kicad_pcb"
  | "uboot"
  | "raw_firmware";

export type ReapFirmwarePlaybookSkill =
  | "reap-07-firmware-and-embedded"
  | "reap-10-vulnerability-research"
  | "reap-13-dma-and-hardware-assisted-cheat-research-defensive"
  | "reap-19-kernel-and-driver-exploitation-research";

export interface MemorySegment {
  baseAddress: number;
  endAddress: number;
  length: number;
  data: Buffer;
}

export interface PositionedString {
  value: string;
  address: number;
  formattedAddress: string;
  encoding: "ascii" | "utf16le";
  nullTerminated: boolean;
}

export interface FirmwareAuditFinding {
  ruleId: string;
  vulnClass: string;
  title: string;
  category:
    | "integrity"
    | "elf_hardening"
    | "bootloader"
    | "secret"
    | "memory_sink"
    | "hardware_debug";
  severity: Severity;
  cvssWeight: number;
  cwe: string[];
  reapPlaybookId: ReapFirmwarePlaybookSkill;
  address?: string;
  line?: number;
  designators?: string[];
  nets?: string[];
  unpopulatedOrTestPoint?: boolean;
  evidence: string;
  remediation: string;
}

export interface HexDecodeResult {
  format: "ihex" | "srec";
  recordCount: number;
  validRecordCount: number;
  corruptedChecksumCount: number;
  entryPoint?: number;
  headerComment?: string;
  segments: MemorySegment[];
  strings: PositionedString[];
  findings: FirmwareAuditFinding[];
}

export interface ElfLoadSegmentInfo {
  offset: number;
  vaddr: bigint;
  filesz: number;
  memsz: number;
  flags: string;
}

export interface ElfMetadata {
  bitness: 32 | 64;
  endianness: "little" | "big";
  elfType: "ET_REL" | "ET_EXEC" | "ET_DYN" | "ET_CORE" | "ET_UNKNOWN";
  machineCode: number;
  architecture: string;
  entryPoint: string;
  pieEnabled: boolean;
  nxEnabled: boolean;
  gnuStackPresent: boolean;
  gnuStackFlags?: string;
  loadSegments: ElfLoadSegmentInfo[];
}

export interface UBootContainerHit {
  kind: "uimage" | "fdt_or_fit";
  offset: number;
  formattedOffset: string;
  totalSize?: number;
  loadAddress?: string;
  entryPoint?: string;
  imageName?: string;
}

export interface KicadDebugInterfaceHit {
  interfaceType: "JTAG" | "SWD" | "UART" | "SPI_FLASH" | "BOOT_PIN" | "I2C_EEPROM";
  designators: string[];
  nets: string[];
  unpopulated: boolean;
  testPointExposed: boolean;
  line: number;
}

export interface FirmwareAuditReport {
  filePath: string;
  fileName: string;
  sizeBytes: number;
  detectedFormat: FirmwareArtifactFormat;
  hexDecode?: HexDecodeResult;
  elf?: ElfMetadata;
  ubootContainers: UBootContainerHit[];
  kicadHits?: KicadDebugInterfaceHit[];
  extractedStringCount: number;
  findings: FirmwareAuditFinding[];
}

const FIRMWARE_CANDIDATE_EXTENSIONS = new Set([
  ".hex",
  ".ihex",
  ".srec",
  ".s19",
  ".s28",
  ".s37",
  ".mot",
  ".elf",
  ".axf",
  ".out",
  ".ko",
  ".so",
  ".bin",
  ".fw",
  ".img",
  ".rom",
  ".uimage",
  ".itb",
  ".dtb",
  ".dts",
  ".dtsi",
  ".env",
  ".cfg",
  ".kicad_sch",
  ".kicad_pcb",
]);

export function formatHexAddress(addr: number | bigint, minDigits = 8): string {
  const positive =
    typeof addr === "bigint"
      ? addr < 0n
        ? 0n
        : addr
      : BigInt(Math.max(0, Math.floor(addr)));
  const hex = positive.toString(16).toUpperCase();
  return `0x${hex.padStart(minDigits, "0")}`;
}

/**
 * Redact raw credentials, PSKs, tokens, JWTs, shadow hashes, and PEM bodies
 * before emitting any finding snippet or report preview.
 */
export function redactFirmwareEvidence(raw: string, maxLen = 180): string {
  let scrubbed = redactString(raw);
  scrubbed = scrubbed
    .replace(
      /(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)[\s\S]*/gi,
      "$1 [redacted]",
    )
    .replace(
      /\b(wpa[_-]?psk|wifi[_-]?pass(?:word)?|mqtt[_-]?(?:tls[_-]?)?(?:pass(?:word)?|key|secret)|tls[_-]?(?:private[_-]?)?key|root[_-]?pass(?:word)?|admin[_-]?pass(?:word)?|passphrase|psk|passwd|pwd|password|api[_-]?key|auth[_-]?token|access[_-]?token|secret[_-]?key|client[_-]?secret|private[_-]?key|jwt[_-]?secret)\s*([:=])\s*(?:"[^"]*"|'[^']*'|[^\s,;#}"']+)/gi,
      "$1$2[redacted]",
    )
    .replace(
      /(^|[\s"'])([a-z_][a-z0-9_-]{0,31}):(\$[1256yab]\$[A-Za-z0-9./$]{8,})/gi,
      "$1$2:[redacted]",
    );
  const singleLine = scrubbed.replace(/\s+/g, " ").trim();
  if (singleLine.length <= maxLen) return singleLine;
  return `${singleLine.slice(0, maxLen)}...`;
}

// =============================================================================
// 1. CANONICAL CONTAINMENT & FAIL-CLOSED FILE RESOLUTION
// =============================================================================

export function isWithinFirmwareRoot(
  realRoot: string,
  realCandidate: string,
): boolean {
  const rel = relative(realRoot, realCandidate);
  if (rel === "") return true;
  if (rel === ".." || rel.startsWith(`..${sep}`) || rel.startsWith("../")) {
    return false;
  }
  if (isAbsolute(rel)) return false;
  return true;
}

function formatFsError(err: unknown): string {
  if (err && typeof err === "object") {
    const code = "code" in err && typeof err.code === "string" ? err.code : "";
    const msg =
      "message" in err && typeof err.message === "string" ? err.message : "";
    if (code && msg) return `${code}: ${msg}`;
    if (msg) return msg;
    if (code) return code;
  }
  return String(err);
}

function resolveConfiguredSourceRoot(context: ToolContext): string | null {
  const metaRoot = context.target?.metadata?.sourceRoot;
  if (typeof metaRoot === "string" && metaRoot.trim().length > 0) {
    return metaRoot.trim();
  }
  const envRoot = process.env.T3MP3ST_SOURCE_ROOT?.trim();
  return envRoot && envRoot.length > 0 ? envRoot : null;
}

type ApprovedFirmwarePathResult =
  | { ok: true; root: string; path: string; stat: Stats }
  | { ok: false; error: string };

export function resolveApprovedFirmwarePath(
  tool: string,
  configuredRoot: string,
  requested: string,
  allowDirectory: boolean,
): ApprovedFirmwarePathResult {
  let realRoot: string;
  try {
    realRoot = realpathSync(resolve(configuredRoot));
  } catch (err) {
    return {
      ok: false,
      error: `${tool}: T3MP3ST_SOURCE_ROOT cannot be resolved (${formatFsError(err)})`,
    };
  }

  const rawCandidate = isAbsolute(requested)
    ? resolve(requested)
    : resolve(realRoot, requested);

  let rawLstat: Stats;
  try {
    rawLstat = lstatSync(rawCandidate);
  } catch (err) {
    return {
      ok: false,
      error: `${tool}: path cannot be resolved inside T3MP3ST_SOURCE_ROOT (${formatFsError(err)})`,
    };
  }

  // Reject special device/FIFO/socket nodes immediately before opening or resolving further
  if (
    !rawLstat.isSymbolicLink() &&
    !rawLstat.isFile() &&
    !(allowDirectory && rawLstat.isDirectory())
  ) {
    return {
      ok: false,
      error: `${tool}: path must be ${allowDirectory ? "a regular file or directory" : "a regular file"} (special files/FIFOs/devices are rejected)`,
    };
  }

  let realCandidate: string;
  try {
    realCandidate = realpathSync(rawCandidate);
  } catch (err) {
    return {
      ok: false,
      error: `${tool}: path cannot be resolved inside T3MP3ST_SOURCE_ROOT (${formatFsError(err)})`,
    };
  }

  if (!isWithinFirmwareRoot(realRoot, realCandidate)) {
    return {
      ok: false,
      error: `${tool}: path is outside T3MP3ST_SOURCE_ROOT`,
    };
  }

  let stat: Stats;
  try {
    stat = statSync(realCandidate);
  } catch (err) {
    return {
      ok: false,
      error: `${tool}: path cannot be inspected inside T3MP3ST_SOURCE_ROOT (${formatFsError(err)})`,
    };
  }

  if (!stat.isFile() && !(allowDirectory && stat.isDirectory())) {
    return {
      ok: false,
      error: `${tool}: path must be ${allowDirectory ? "a regular file or directory" : "a regular file"} (special files/FIFOs/devices are rejected)`,
    };
  }

  return { ok: true, root: realRoot, path: realCandidate, stat };
}

// =============================================================================
// 2. SEGMENT COALESCING & ADDRESS-ATTRIBUTED STRING EXTRACTION
// =============================================================================

interface RawMemoryChunk {
  address: number;
  data: Buffer;
  order: number;
}

export function coalesceMemorySegments(
  chunks: readonly RawMemoryChunk[],
): MemorySegment[] {
  const nonEmpty = chunks.filter((c) => c.data.length > 0);
  if (nonEmpty.length === 0) return [];

  const sorted = [...nonEmpty].sort((a, b) => {
    if (a.address !== b.address) return a.address - b.address;
    return a.order - b.order;
  });

  const segments: MemorySegment[] = [];
  let curBase = sorted[0].address;
  let curBuf = Buffer.from(sorted[0].data);

  for (let i = 1; i < sorted.length; i++) {
    const chunk = sorted[i];
    const curEnd = curBase + curBuf.length;

    if (chunk.address === curEnd) {
      curBuf = Buffer.concat([curBuf, chunk.data]);
    } else if (chunk.address >= curBase && chunk.address < curEnd) {
      // Overlapping write (later record overwrites overlapping range)
      const relOffset = chunk.address - curBase;
      const neededLen = Math.max(curBuf.length, relOffset + chunk.data.length);
      if (neededLen > curBuf.length) {
        const grown = Buffer.alloc(neededLen);
        curBuf.copy(grown, 0);
        curBuf = grown;
      }
      chunk.data.copy(curBuf, relOffset);
    } else {
      segments.push({
        baseAddress: curBase,
        endAddress: curBase + curBuf.length,
        length: curBuf.length,
        data: curBuf,
      });
      curBase = chunk.address;
      curBuf = Buffer.from(chunk.data);
    }
  }

  segments.push({
    baseAddress: curBase,
    endAddress: curBase + curBuf.length,
    length: curBuf.length,
    data: curBuf,
  });

  return segments;
}

export function extractPositionedStrings(
  segments: ReadonlyArray<{ baseAddress: number; data: Buffer }>,
  minLength = 4,
): PositionedString[] {
  const out: PositionedString[] = [];

  for (const seg of segments) {
    const buf = seg.data;
    // 1. Printable ASCII runs
    let runStart = -1;
    let asciiChars = "";
    for (let i = 0; i < buf.length; i++) {
      const b = buf[i];
      if ((b >= 0x20 && b <= 0x7e) || b === 0x09) {
        if (runStart === -1) runStart = i;
        asciiChars += String.fromCharCode(b);
      } else {
        if (asciiChars.length >= minLength && runStart >= 0) {
          const addr = seg.baseAddress + runStart;
          out.push({
            value: asciiChars,
            address: addr,
            formattedAddress: formatHexAddress(addr),
            encoding: "ascii",
            nullTerminated: b === 0x00,
          });
        }
        runStart = -1;
        asciiChars = "";
      }
    }
    if (asciiChars.length >= minLength && runStart >= 0) {
      const addr = seg.baseAddress + runStart;
      out.push({
        value: asciiChars,
        address: addr,
        formattedAddress: formatHexAddress(addr),
        encoding: "ascii",
        nullTerminated: false,
      });
    }

    // 2. Printable UTF-16LE runs (both even and odd alignments)
    for (const parity of [0, 1]) {
      let uStart = -1;
      let uChars = "";
      let idx = parity;
      while (idx + 1 < buf.length) {
        const lo = buf[idx];
        const hi = buf[idx + 1];
        if (((lo >= 0x20 && lo <= 0x7e) || lo === 0x09) && hi === 0x00) {
          if (uStart === -1) uStart = idx;
          uChars += String.fromCharCode(lo);
        } else {
          if (uChars.length >= minLength && uStart >= 0) {
            const addr = seg.baseAddress + uStart;
            out.push({
              value: uChars,
              address: addr,
              formattedAddress: formatHexAddress(addr),
              encoding: "utf16le",
              nullTerminated: lo === 0x00 && hi === 0x00,
            });
          }
          uStart = -1;
          uChars = "";
        }
        idx += 2;
      }
      if (uChars.length >= minLength && uStart >= 0) {
        const addr = seg.baseAddress + uStart;
        out.push({
          value: uChars,
          address: addr,
          formattedAddress: formatHexAddress(addr),
          encoding: "utf16le",
          nullTerminated: false,
        });
      }
    }
  }

  return out;
}

// =============================================================================
// 3. INTEL HEX & MOTOROLA S-RECORD DECODERS WITH CHECKSUM VERIFICATION
// =============================================================================

function parseHexBytes(hexStr: string): Uint8Array | null {
  if (hexStr.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hexStr)) {
    return null;
  }
  const bytes = new Uint8Array(hexStr.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hexStr.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function decodeIntelHex(text: string): HexDecodeResult {
  const lines = text.split(/\r?\n/);
  const chunks: RawMemoryChunk[] = [];
  const findings: FirmwareAuditFinding[] = [];
  let upperBase = 0;
  let recordCount = 0;
  let validRecordCount = 0;
  let corruptedChecksumCount = 0;
  let entryPoint: number | undefined;

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (!trimmed || trimmed.startsWith(";") || trimmed.startsWith("#")) {
      continue;
    }
    const lineNo = i + 1;
    recordCount++;

    if (!trimmed.startsWith(":")) {
      corruptedChecksumCount++;
      findings.push({
        ruleId: "FW-HEX-MALFORMED",
        vulnClass: "corrupted_checksum",
        title: `Malformed Intel HEX record at line ${lineNo}`,
        category: "integrity",
        severity: "high",
        cvssWeight: 7.2,
        cwe: ["CWE-353"],
        reapPlaybookId: "reap-07-firmware-and-embedded",
        line: lineNo,
        evidence: `Missing ':' start code on Intel HEX record line ${lineNo}`,
        remediation:
          "Regenerate firmware HEX image from verified build output and enforce cryptographic image signing before flashing.",
      });
      continue;
    }

    const hexPayload = trimmed.slice(1);
    const bytes = parseHexBytes(hexPayload);
    if (!bytes || bytes.length < 5) {
      corruptedChecksumCount++;
      findings.push({
        ruleId: "FW-HEX-MALFORMED",
        vulnClass: "corrupted_checksum",
        title: `Truncated or non-hex Intel HEX record at line ${lineNo}`,
        category: "integrity",
        severity: "high",
        cvssWeight: 7.2,
        cwe: ["CWE-353"],
        reapPlaybookId: "reap-07-firmware-and-embedded",
        line: lineNo,
        evidence: `Invalid Intel HEX byte encoding at line ${lineNo}`,
        remediation:
          "Verify transport/storage integrity of the firmware HEX image and require signed firmware containers.",
      });
      continue;
    }

    const byteCount = bytes[0];
    const offset16 = (bytes[1] << 8) | bytes[2];
    const recordType = bytes[3];
    const effectiveAddress = upperBase + offset16;

    if (bytes.length !== byteCount + 5) {
      corruptedChecksumCount++;
      findings.push({
        ruleId: "FW-HEX-LENGTH-MISMATCH",
        vulnClass: "corrupted_checksum",
        title: `Intel HEX record byte-count mismatch at line ${lineNo}`,
        category: "integrity",
        severity: "high",
        cvssWeight: 7.5,
        cwe: ["CWE-353"],
        reapPlaybookId: "reap-07-firmware-and-embedded",
        line: lineNo,
        address: formatHexAddress(effectiveAddress),
        evidence: `Declared byte count 0x${byteCount.toString(16).toUpperCase().padStart(2, "0")} does not match payload length (${bytes.length - 5} bytes) at ${formatHexAddress(effectiveAddress)}`,
        remediation:
          "Reject corrupted Intel HEX images in bootloader/programmer pipelines and verify image SHA-256/signature.",
      });
      continue;
    }

    let sum = 0;
    for (let bIdx = 0; bIdx < bytes.length - 1; bIdx++) {
      sum = (sum + bytes[bIdx]) & 0xff;
    }
    const expectedChecksum = (0x100 - sum) & 0xff;
    const actualChecksum = bytes[bytes.length - 1];

    if (actualChecksum !== expectedChecksum) {
      corruptedChecksumCount++;
      findings.push({
        ruleId: "FW-HEX-CHECKSUM",
        vulnClass: "corrupted_checksum",
        title: `Corrupted Intel HEX checksum at line ${lineNo} (${formatHexAddress(effectiveAddress)})`,
        category: "integrity",
        severity: "high",
        cvssWeight: 7.5,
        cwe: ["CWE-353"],
        reapPlaybookId: "reap-07-firmware-and-embedded",
        line: lineNo,
        address: formatHexAddress(effectiveAddress),
        evidence: `corrupted_checksum on Intel HEX type 0x${recordType.toString(16).toUpperCase().padStart(2, "0")} record at ${formatHexAddress(effectiveAddress)}: expected 0x${expectedChecksum.toString(16).toUpperCase().padStart(2, "0")}, got 0x${actualChecksum.toString(16).toUpperCase().padStart(2, "0")}`,
        remediation:
          "Enforce strict record checksum rejection and cryptographic firmware image verification (e.g., MCUboot / FIT signed images) prior to flash programming.",
      });
      continue;
    }

    validRecordCount++;
    const dataSlice = bytes.subarray(4, 4 + byteCount);

    switch (recordType) {
      case 0x00: {
        chunks.push({
          address: effectiveAddress,
          data: Buffer.from(dataSlice),
          order: i,
        });
        break;
      }
      case 0x01: {
        // EOF record
        break;
      }
      case 0x02: {
        // Extended Segment Address (bits 4..19)
        if (dataSlice.length === 2) {
          upperBase = ((dataSlice[0] << 8) | dataSlice[1]) * 16;
        }
        break;
      }
      case 0x03: {
        // Start Segment Address (CS:IP)
        if (dataSlice.length === 4) {
          const cs = (dataSlice[0] << 8) | dataSlice[1];
          const ip = (dataSlice[2] << 8) | dataSlice[3];
          entryPoint = cs * 16 + ip;
        }
        break;
      }
      case 0x04: {
        // Extended Linear Address (upper 16 bits of 32-bit linear address)
        if (dataSlice.length === 2) {
          upperBase = ((dataSlice[0] << 8) | dataSlice[1]) * 0x10000;
        }
        break;
      }
      case 0x05: {
        // Start Linear Address (32-bit EIP / ARM Reset Handler)
        if (dataSlice.length === 4) {
          entryPoint =
            dataSlice[0] * 0x1000000 +
            (dataSlice[1] << 16) +
            (dataSlice[2] << 8) +
            dataSlice[3];
        }
        break;
      }
      default:
        break;
    }
  }

  const segments = coalesceMemorySegments(chunks);
  const strings = extractPositionedStrings(segments);

  return {
    format: "ihex",
    recordCount,
    validRecordCount,
    corruptedChecksumCount,
    entryPoint,
    segments,
    strings,
    findings,
  };
}

export function decodeMotorolaSrec(text: string): HexDecodeResult {
  const lines = text.split(/\r?\n/);
  const chunks: RawMemoryChunk[] = [];
  const findings: FirmwareAuditFinding[] = [];
  let recordCount = 0;
  let validRecordCount = 0;
  let corruptedChecksumCount = 0;
  let entryPoint: number | undefined;
  let headerComment: string | undefined;

  const addrBytesByType: Readonly<Record<string, number>> = {
    "0": 2,
    "1": 2,
    "2": 3,
    "3": 4,
    "5": 2,
    "6": 3,
    "7": 4,
    "8": 3,
    "9": 2,
  };

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (!trimmed || trimmed.startsWith(";") || trimmed.startsWith("#")) {
      continue;
    }
    const lineNo = i + 1;
    recordCount++;

    if (!/^S[0-9]/i.test(trimmed)) {
      corruptedChecksumCount++;
      findings.push({
        ruleId: "FW-SREC-MALFORMED",
        vulnClass: "corrupted_checksum",
        title: `Malformed Motorola S-Record at line ${lineNo}`,
        category: "integrity",
        severity: "high",
        cvssWeight: 7.2,
        cwe: ["CWE-353"],
        reapPlaybookId: "reap-07-firmware-and-embedded",
        line: lineNo,
        evidence: `Invalid Motorola S-Record header at line ${lineNo}`,
        remediation:
          "Validate S-Record syntax and require signed firmware update manifests.",
      });
      continue;
    }

    const recType = trimmed[1];
    const addrLen = addrBytesByType[recType];
    if (!addrLen) {
      continue;
    }

    const bytes = parseHexBytes(trimmed.slice(2));
    if (!bytes || bytes.length < 1 + addrLen + 1) {
      corruptedChecksumCount++;
      findings.push({
        ruleId: "FW-SREC-MALFORMED",
        vulnClass: "corrupted_checksum",
        title: `Truncated or invalid hex in Motorola S${recType} record at line ${lineNo}`,
        category: "integrity",
        severity: "high",
        cvssWeight: 7.2,
        cwe: ["CWE-353"],
        reapPlaybookId: "reap-07-firmware-and-embedded",
        line: lineNo,
        evidence: `Truncated S${recType} record payload at line ${lineNo}`,
        remediation:
          "Reject malformed S-Record images and enforce cryptographic image integrity checks.",
      });
      continue;
    }

    const declaredCount = bytes[0];
    if (bytes.length !== declaredCount + 1) {
      corruptedChecksumCount++;
      findings.push({
        ruleId: "FW-SREC-LENGTH-MISMATCH",
        vulnClass: "corrupted_checksum",
        title: `Motorola S${recType} byte-count mismatch at line ${lineNo}`,
        category: "integrity",
        severity: "high",
        cvssWeight: 7.5,
        cwe: ["CWE-353"],
        reapPlaybookId: "reap-07-firmware-and-embedded",
        line: lineNo,
        evidence: `Declared S${recType} count 0x${declaredCount.toString(16).toUpperCase().padStart(2, "0")} does not match ${bytes.length - 1} remaining bytes at line ${lineNo}`,
        remediation:
          "Reject corrupted S-Record transfers and verify cryptographic firmware digests.",
      });
      continue;
    }

    let address = 0;
    for (let aIdx = 0; aIdx < addrLen; aIdx++) {
      address = address * 256 + bytes[1 + aIdx];
    }

    let sum = 0;
    for (let bIdx = 0; bIdx < bytes.length - 1; bIdx++) {
      sum = (sum + bytes[bIdx]) & 0xff;
    }
    const expectedChecksum = (~sum) & 0xff;
    const actualChecksum = bytes[bytes.length - 1];

    if (actualChecksum !== expectedChecksum) {
      corruptedChecksumCount++;
      findings.push({
        ruleId: "FW-SREC-CHECKSUM",
        vulnClass: "corrupted_checksum",
        title: `Corrupted Motorola S${recType} checksum at line ${lineNo} (${formatHexAddress(address)})`,
        category: "integrity",
        severity: "high",
        cvssWeight: 7.5,
        cwe: ["CWE-353"],
        reapPlaybookId: "reap-07-firmware-and-embedded",
        line: lineNo,
        address: formatHexAddress(address),
        evidence: `corrupted_checksum on Motorola S${recType} record at ${formatHexAddress(address)}: expected 0x${expectedChecksum.toString(16).toUpperCase().padStart(2, "0")}, got 0x${actualChecksum.toString(16).toUpperCase().padStart(2, "0")}`,
        remediation:
          "Reject S-Record payloads failing one's-complement checksum verification and enforce signed firmware verification.",
      });
      continue;
    }

    validRecordCount++;
    const dataSlice = bytes.subarray(1 + addrLen, bytes.length - 1);

    if (recType === "0") {
      headerComment = Buffer.from(dataSlice)
        .toString("utf8")
        .replace(/[^\x20-\x7e]+/g, "")
        .trim();
    } else if (recType === "1" || recType === "2" || recType === "3") {
      chunks.push({
        address,
        data: Buffer.from(dataSlice),
        order: i,
      });
    } else if (recType === "7" || recType === "8" || recType === "9") {
      entryPoint = address;
    }
  }

  const segments = coalesceMemorySegments(chunks);
  const strings = extractPositionedStrings(segments);

  return {
    format: "srec",
    recordCount,
    validRecordCount,
    corruptedChecksumCount,
    entryPoint,
    headerComment,
    segments,
    strings,
    findings,
  };
}

// =============================================================================
// 4. ELF32 / ELF64 HEADER & HARDENING ANALYZER
// =============================================================================

const ELF_MACHINE_NAMES: Readonly<Record<number, string>> = {
  0x03: "x86",
  0x08: "MIPS",
  0x14: "PowerPC",
  0x28: "ARM",
  0x3e: "x86_64",
  0x53: "AVR",
  0x5e: "Xtensa",
  0xb7: "AArch64",
  0xf3: "RISC-V",
};

function formatSegmentFlags(pFlags: number): string {
  const r = (pFlags & 0x4) !== 0 ? "R" : "-";
  const w = (pFlags & 0x2) !== 0 ? "W" : "-";
  const x = (pFlags & 0x1) !== 0 ? "X" : "-";
  return `${r}${w}${x}`;
}

export function parseElfMetadata(buf: Buffer): {
  metadata: ElfMetadata;
  findings: FirmwareAuditFinding[];
} | null {
  if (
    buf.length < 52 ||
    buf[0] !== 0x7f ||
    buf[1] !== 0x45 ||
    buf[2] !== 0x4c ||
    buf[3] !== 0x46
  ) {
    return null;
  }

  const eiClass = buf[4];
  const eiData = buf[5];
  if ((eiClass !== 1 && eiClass !== 2) || (eiData !== 1 && eiData !== 2)) {
    return null;
  }

  const bitness: 32 | 64 = eiClass === 2 ? 64 : 32;
  const endianness: "little" | "big" = eiData === 2 ? "big" : "little";
  if (bitness === 64 && buf.length < 64) {
    return null;
  }

  const readU16 = (off: number): number =>
    endianness === "little" ? buf.readUInt16LE(off) : buf.readUInt16BE(off);
  const readU32 = (off: number): number =>
    endianness === "little" ? buf.readUInt32LE(off) : buf.readUInt32BE(off);
  const readU64 = (off: number): bigint =>
    endianness === "little"
      ? buf.readBigUInt64LE(off)
      : buf.readBigUInt64BE(off);

  const eTypeCode = readU16(16);
  const elfType: ElfMetadata["elfType"] =
    eTypeCode === 1
      ? "ET_REL"
      : eTypeCode === 2
        ? "ET_EXEC"
        : eTypeCode === 3
          ? "ET_DYN"
          : eTypeCode === 4
            ? "ET_CORE"
            : "ET_UNKNOWN";

  const machineCode = readU16(18);
  const architecture =
    ELF_MACHINE_NAMES[machineCode] ?? `EM_0x${machineCode.toString(16).toUpperCase()}`;

  const entryBig = bitness === 64 ? readU64(24) : BigInt(readU32(24));
  const phOffBig = bitness === 64 ? readU64(32) : BigInt(readU32(28));
  const phEntSize = bitness === 64 ? readU16(54) : readU16(42);
  const phNum = bitness === 64 ? readU16(56) : readU16(44);

  const entryPoint = formatHexAddress(entryBig, bitness === 64 ? 8 : 8);
  const findings: FirmwareAuditFinding[] = [];
  const loadSegments: ElfLoadSegmentInfo[] = [];

  let gnuStackPresent = false;
  let gnuStackFlags: string | undefined;
  let nxEnabled = true;

  const PT_LOAD = 1;
  const PT_GNU_STACK = 0x6474e551;

  const minPhSize = bitness === 64 ? 56 : 32;
  if (
    phOffBig > 0n &&
    phOffBig < BigInt(buf.length) &&
    phEntSize >= minPhSize &&
    phNum > 0
  ) {
    const maxHeaders = Math.min(phNum, 128);
    const phBase = Number(phOffBig);

    for (let idx = 0; idx < maxHeaders; idx++) {
      const off = phBase + idx * phEntSize;
      if (off + minPhSize > buf.length) break;

      const pType = readU32(off);
      const pFlags = bitness === 64 ? readU32(off + 4) : readU32(off + 24);
      const pOffset =
        bitness === 64 ? Number(readU64(off + 8)) : readU32(off + 4);
      const pVaddr = bitness === 64 ? readU64(off + 16) : BigInt(readU32(off + 8));
      const pFilesz =
        bitness === 64 ? Number(readU64(off + 32)) : readU32(off + 16);
      const pMemsz =
        bitness === 64 ? Number(readU64(off + 40)) : readU32(off + 20);
      const flagStr = formatSegmentFlags(pFlags);

      if (pType === PT_LOAD) {
        loadSegments.push({
          offset: pOffset,
          vaddr: pVaddr,
          filesz: pFilesz,
          memsz: pMemsz,
          flags: flagStr,
        });

        // Simultaneous Write + Execute on PT_LOAD
        if ((pFlags & 0x3) === 0x3) {
          findings.push({
            ruleId: "FW-ELF-RWX-SEGMENT",
            vulnClass: "rwx_memory_segment",
            title: `Writable and executable PT_LOAD segment (${flagStr}) at ${formatHexAddress(pVaddr)}`,
            category: "elf_hardening",
            severity: "high",
            cvssWeight: 7.6,
            cwe: ["CWE-119"],
            reapPlaybookId: "reap-10-vulnerability-research",
            address: formatHexAddress(pVaddr),
            evidence: `ELF${bitness} (${architecture}) PT_LOAD[${idx}] mapped ${flagStr} at vaddr=${formatHexAddress(pVaddr)} (memsz=0x${pMemsz.toString(16)})`,
            remediation:
              "Enforce W^X segment permissions in the linker script / toolchain (--no-omagic, separate .text RX and .data/.bss RW).",
          });
        }
      } else if (pType === PT_GNU_STACK) {
        gnuStackPresent = true;
        gnuStackFlags = flagStr;
        if ((pFlags & 0x1) !== 0) {
          nxEnabled = false;
          findings.push({
            ruleId: "FW-ELF-EXEC-STACK",
            vulnClass: "executable_stack",
            title: `ELF executable stack enabled (PT_GNU_STACK ${flagStr}, NX disabled)`,
            category: "elf_hardening",
            severity: "high",
            cvssWeight: 7.8,
            cwe: ["CWE-119"],
            reapPlaybookId: "reap-10-vulnerability-research",
            address: entryPoint,
            evidence: `ELF${bitness} (${architecture}, ${endianness}-endian) PT_GNU_STACK carries executable permission (${flagStr}), allowing direct stack shellcode execution`,
            remediation:
              "Compile and link with -Wl,-z,noexecstack so PT_GNU_STACK is RW- and hardware NX/XN page protection is enforced.",
          });
        }
      }
    }
  }

  const pieEnabled = elfType === "ET_DYN";
  if (elfType === "ET_EXEC") {
    findings.push({
      ruleId: "FW-ELF-NO-PIE",
      vulnClass: "missing_pie_aslr",
      title: `Non-PIE static base ELF executable (ET_EXEC at ${entryPoint})`,
      category: "elf_hardening",
      severity: "medium",
      cvssWeight: 5.5,
      cwe: ["CWE-119"],
      reapPlaybookId: "reap-10-vulnerability-research",
      address: entryPoint,
      evidence: `ELF${bitness} (${architecture}) linked as fixed-address ET_EXEC (entry=${entryPoint}) rather than position-independent ET_DYN (PIE), making ROP/JOP gadget addresses deterministic`,
      remediation:
        "Build user-space daemons and Linux/embedded services with -fPIE -pie (ET_DYN) so ASLR randomizes code base addresses.",
    });
  }

  return {
    metadata: {
      bitness,
      endianness,
      elfType,
      machineCode,
      architecture,
      entryPoint,
      pieEnabled,
      nxEnabled,
      gnuStackPresent,
      gnuStackFlags,
      loadSegments,
    },
    findings,
  };
}

// =============================================================================
// 5. U-BOOT, DEVICE-TREE (.DTS/.DTSI), SECRETS & UNSAFE C/RTOS SINK ANALYZERS
// =============================================================================

export function scanBinaryContainerSignatures(
  buf: Buffer,
  baseAddress = 0,
): {
  containers: UBootContainerHit[];
  findings: FirmwareAuditFinding[];
} {
  const containers: UBootContainerHit[] = [];
  const findings: FirmwareAuditFinding[] = [];

  for (let off = 0; off + 64 <= buf.length; off += 4) {
    const magic = buf.readUInt32BE(off);
    if (magic === 0x27051956) {
      // Legacy U-Boot uImage header (64 bytes)
      const dataSize = buf.readUInt32BE(off + 12);
      const loadAddr = buf.readUInt32BE(off + 16);
      const entryAddr = buf.readUInt32BE(off + 20);
      const ihType = buf[off + 30];
      if (dataSize === 0 || ihType === 0 || ihType > 40) {
        continue;
      }
      const rawName = buf
        .subarray(off + 32, off + 64)
        .toString("latin1")
        .split("\0")[0]
        .replace(/[^\x20-\x7e]/g, "")
        .trim();
      const absAddr = baseAddress + off;
      containers.push({
        kind: "uimage",
        offset: absAddr,
        formattedOffset: formatHexAddress(absAddr),
        totalSize: dataSize + 64,
        loadAddress: formatHexAddress(loadAddr),
        entryPoint: formatHexAddress(entryAddr),
        imageName: rawName || "unnamed-uImage",
      });
      findings.push({
        ruleId: "FW-UBOOT-LEGACY-UIMAGE",
        vulnClass: "unverified_boot_image",
        title: `Legacy U-Boot uImage header without cryptographic signature (${rawName || "uImage"})`,
        category: "bootloader",
        severity: "medium",
        cvssWeight: 6.5,
        cwe: ["CWE-353"],
        reapPlaybookId: "reap-07-firmware-and-embedded",
        address: formatHexAddress(absAddr),
        evidence: `U-Boot legacy uImage magic 0x27051956 at ${formatHexAddress(absAddr)} (name="${rawName || "uImage"}", load=${formatHexAddress(loadAddr)}, entry=${formatHexAddress(entryAddr)}) relies on non-cryptographic CRC32 only`,
        remediation:
          "Migrate from legacy uImage (0x27051956) to U-Boot Verified Boot FIT images signed with RSA/ECDSA keys stored in read-only control DTB.",
      });
    } else if (magic === 0xd00dfeed) {
      // Flattened Device Tree (FDT / DTB) or U-Boot FIT container
      const totalSize = buf.readUInt32BE(off + 4);
      const offDtStruct = buf.readUInt32BE(off + 8);
      const version = buf.readUInt32BE(off + 20);
      if (
        totalSize < 40 ||
        totalSize > 64 * 1024 * 1024 ||
        offDtStruct < 28 ||
        offDtStruct >= totalSize ||
        version < 1 ||
        version > 30
      ) {
        continue;
      }
      const absAddr = baseAddress + off;
      containers.push({
        kind: "fdt_or_fit",
        offset: absAddr,
        formattedOffset: formatHexAddress(absAddr),
        totalSize,
      });

      const sliceEnd = Math.min(buf.length, off + totalSize);
      const dtbSliceText = buf.subarray(off, sliceEnd).toString("latin1");
      if (
        dtbSliceText.includes("images") &&
        dtbSliceText.includes("configurations") &&
        !dtbSliceText.includes("signature")
      ) {
        findings.push({
          ruleId: "FW-UBOOT-UNSIGNED-FIT",
          vulnClass: "unverified_boot_image",
          title: `Unsigned U-Boot FIT container (0xd00dfeed) at ${formatHexAddress(absAddr)}`,
          category: "bootloader",
          severity: "high",
          cvssWeight: 7.4,
          cwe: ["CWE-353"],
          reapPlaybookId: "reap-07-firmware-and-embedded",
          address: formatHexAddress(absAddr),
          evidence: `FDT/FIT header 0xd00dfeed at ${formatHexAddress(absAddr)} (size=${totalSize} bytes) defines FIT images/configurations without cryptographic signature nodes`,
          remediation:
            "Add RSA/ECDSA signature subnodes with required = \"conf\" in U-Boot FIT configurations and enable CONFIG_FIT_SIGNATURE.",
        });
      }
    }
  }

  return { containers, findings };
}

interface UnsafeSinkRule {
  ruleId: string;
  vulnClass: string;
  title: string;
  severity: Severity;
  cvssWeight: number;
  cwe: string[];
  callRe: RegExp;
  exactSymbolRe?: RegExp;
  remediation: string;
}

const UNSAFE_SINK_RULES: readonly UnsafeSinkRule[] = [
  {
    ruleId: "FW-SINK-GETS-SCANF",
    vulnClass: "unbounded_input_sink",
    title: "Unbounded gets() or scanf(\"%s\") stack/heap buffer overflow sink",
    severity: "critical",
    cvssWeight: 9.0,
    cwe: ["CWE-120", "CWE-119"],
    callRe: /\b(?:gets\s*\(|(?:s|f)?scanf\s*\([^;\n)]*["']%s["'])/,
    exactSymbolRe: /^(?:_?gets|__isoc99_scanf)$/,
    remediation:
      "Replace gets() with fgets(buf, sizeof(buf), stdin) and bound scanf width specifiers or parse lengths explicitly.",
  },
  {
    ruleId: "FW-SINK-STRCPY-SPRINTF",
    vulnClass: "unbounded_memory_copy",
    title: "Unbounded C/RTOS string formatting or copy sink (strcpy / sprintf / vsprintf)",
    severity: "high",
    cvssWeight: 8.2,
    cwe: ["CWE-120", "CWE-119"],
    callRe: /\b(?:strcpy|strcat|sprintf|vsprintf)\s*\(/,
    exactSymbolRe: /^_?(?:strcpy|strcat|sprintf|vsprintf)$/,
    remediation:
      "Replace strcpy/strcat/sprintf/vsprintf with bounded snprintf/vsnprintf/strlcpy and validate destination buffer capacity.",
  },
  {
    ruleId: "FW-SINK-CMD-EXEC",
    vulnClass: "command_injection_sink",
    title: "Embedded shell command execution sink (system / popen)",
    severity: "high",
    cvssWeight: 8.6,
    cwe: ["CWE-78"],
    callRe: /\b(?:system|popen)\s*\(/,
    exactSymbolRe: /^_?(?:system|popen)$/,
    remediation:
      "Avoid shell invocation via system()/popen(); use execve() with fixed argument arrays and strict input allowlists.",
  },
];

const EMBEDDED_CREDENTIAL_PATTERNS: ReadonlyArray<{
  id: string;
  label: string;
  severity: Severity;
  cvssWeight: number;
  re: RegExp;
}> = [
  {
    id: "FW-PRIVATE-KEY",
    label: "Embedded private key header",
    severity: "critical",
    cvssWeight: 9.4,
    re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/,
  },
  {
    id: "FW-SHADOW-HASH",
    label: "Embedded root/service password hash entry",
    severity: "high",
    cvssWeight: 8.4,
    re: /(?:^|[\s"'])(?:root|admin|support|operator|debug):\$[1256yab]\$[A-Za-z0-9./$]{8,}/i,
  },
  {
    id: "FW-EMBEDDED-PSK",
    label: "Hardcoded firmware credential, PSK, or API secret",
    severity: "high",
    cvssWeight: 8.6,
    re: /\b(?:wpa[_-]?psk|wifi[_-]?pass(?:word)?|mqtt[_-]?(?:tls[_-]?)?(?:pass(?:word)?|key|secret)|tls[_-]?(?:private[_-]?)?key|root[_-]?pass(?:word)?|admin[_-]?pass(?:word)?|passphrase|psk|passwd|password|api[_-]?key|auth[_-]?token|secret[_-]?key|private[_-]?key|jwt[_-]?secret)\s*[:=]\s*(?!["']?(?:none|null|false|disabled|\[?redacted\]?)\b)["']?[^\s,;#}"']{4,}["']?/i,
  },
];

export function scanPositionedStringsAndBootEnv(
  strings: readonly PositionedString[],
  options: { allowSymbolMatch: boolean },
): FirmwareAuditFinding[] {
  const findings: FirmwareAuditFinding[] = [];
  const seenKeys = new Set<string>();
  const hasBootStopSha = strings.some((s) =>
    /bootstopkeysha256\s*=/.test(s.value),
  );
  const hasUnboundedPercentS = strings.some((s) => /(?:^|[^0-9])%s/.test(s.value));

  for (const item of strings) {
    const val = item.value.trim();
    if (!val) continue;

    // 1. U-Boot bootcmd / network TFTP / shell injection vectors
    if (/(?:^|\b)(?:bootcmd|altbootcmd|failbootcmd|preboot)\s*=/.test(val)) {
      const hasNetBoot = /\b(?:tftpboot|tftp|dhcp|nfs|pxe|usbboot)\b/i.test(val);
      const hasShellChain =
        /[;&|`]|(?:\$\()|\binit=\/bin\/(?:sh|bash|ash)\b/i.test(val);
      if (hasNetBoot || hasShellChain) {
        const dedup = `uboot-cmd:${item.formattedAddress}`;
        if (!seenKeys.has(dedup)) {
          seenKeys.add(dedup);
          findings.push({
            ruleId: "FW-UBOOT-BOOTCMD-INJECT",
            vulnClass: "bootloader_command_injection",
            title: hasNetBoot
              ? `Unauthenticated U-Boot network boot / command vector at ${item.formattedAddress}`
              : `Chained U-Boot shell command expansion in bootcmd at ${item.formattedAddress}`,
            category: "bootloader",
            severity: hasNetBoot ? "critical" : "high",
            cvssWeight: hasNetBoot ? 9.1 : 8.2,
            cwe: ["CWE-78", "CWE-353"],
            reapPlaybookId: "reap-07-firmware-and-embedded",
            address: item.formattedAddress,
            evidence: redactFirmwareEvidence(val),
            remediation:
              "Disable unauthenticated tftpboot/nfs fallback in production U-Boot environments, lock environment variables (CONFIG_ENV_WRITEABLE_LIST), and enforce Verified Boot.",
          });
        }
      }
    }

    // 2. U-Boot interactive console bootdelay exposure
    const delayMatch = val.match(/(?:^|\b)bootdelay\s*=\s*(-?\d+)/i);
    if (delayMatch && !hasBootStopSha) {
      const delaySecs = parseInt(delayMatch[1], 10);
      if (delaySecs > 0 || delaySecs === -1) {
        const dedup = `uboot-delay:${item.formattedAddress}`;
        if (!seenKeys.has(dedup)) {
          seenKeys.add(dedup);
          findings.push({
            ruleId: "FW-UBOOT-CONSOLE-EXPOSED",
            vulnClass: "exposed_bootloader_console",
            title: `Unlocked U-Boot interactive autoboot prompt (bootdelay=${delaySecs}) at ${item.formattedAddress}`,
            category: "bootloader",
            severity: "medium",
            cvssWeight: 6.4,
            cwe: ["CWE-1244"],
            reapPlaybookId: "reap-07-firmware-and-embedded",
            address: item.formattedAddress,
            evidence: redactFirmwareEvidence(val),
            remediation:
              "Set bootdelay=-2 (disable console abort) or configure CONFIG_AUTOBOOT_KEYED with bootstopkeysha256 in production firmware.",
          });
        }
      }
    }

    // 3. Hardcoded secrets, private keys, JWTs, & provider tokens (redacted!)
    let matchedSecret = false;
    for (const credRule of EMBEDDED_CREDENTIAL_PATTERNS) {
      if (credRule.re.test(val)) {
        const dedup = `${credRule.id}:${item.formattedAddress}`;
        if (!seenKeys.has(dedup)) {
          seenKeys.add(dedup);
          findings.push({
            ruleId: credRule.id,
            vulnClass: "hardcoded_credential",
            title: `${credRule.label} at ${item.formattedAddress}`,
            category: "secret",
            severity: credRule.severity,
            cvssWeight: credRule.cvssWeight,
            cwe: ["CWE-798"],
            reapPlaybookId: "reap-07-firmware-and-embedded",
            address: item.formattedAddress,
            evidence: redactFirmwareEvidence(val),
            remediation:
              "Provision per-device unique keys/credentials in hardware secure elements / OTP fuses rather than embedding static secrets in firmware images.",
          });
        }
        matchedSecret = true;
        break;
      }
    }

    if (!matchedSecret) {
      for (const [secretName, spec] of Object.entries(SECRET_PATTERNS)) {
        // Skip generic 40-char base64 aws_secret_key heuristic on binary/hex symbol strings unless AWS context exists
        if (secretName === "aws_secret_key" && !/aws|akia/i.test(val)) {
          continue;
        }
        spec.pattern.lastIndex = 0;
        if (spec.pattern.test(val)) {
          spec.pattern.lastIndex = 0;
          const sev: Severity =
            spec.severity === "critical" ? "critical" : "high";
          const dedup = `secret:${secretName}:${item.formattedAddress}`;
          if (!seenKeys.has(dedup)) {
            seenKeys.add(dedup);
            findings.push({
              ruleId: "FW-HARDCODED-SECRET",
              vulnClass: "hardcoded_credential",
              title: `Hardcoded ${spec.provider} secret (${secretName}) at ${item.formattedAddress}`,
              category: "secret",
              severity: sev,
              cvssWeight: sev === "critical" ? 9.1 : 8.3,
              cwe: ["CWE-798"],
              reapPlaybookId: "reap-07-firmware-and-embedded",
              address: item.formattedAddress,
              evidence: redactFirmwareEvidence(val),
              remediation:
                "Revoke exposed credentials immediately and remove hardcoded tokens/JWTs/keys from firmware images.",
            });
          }
          break;
        }
      }
    }

    // 4. Unsafe C / RTOS memory & command execution sinks
    for (const sinkRule of UNSAFE_SINK_RULES) {
      const callMatched = sinkRule.callRe.test(val);
      const symbolMatched =
        options.allowSymbolMatch &&
        item.nullTerminated &&
        Boolean(sinkRule.exactSymbolRe && sinkRule.exactSymbolRe.test(val)) &&
        (sinkRule.ruleId !== "FW-SINK-GETS-SCANF" ||
          val.includes("gets") ||
          hasUnboundedPercentS);

      if (callMatched || symbolMatched) {
        const dedup = `${sinkRule.ruleId}:${item.formattedAddress}`;
        if (!seenKeys.has(dedup)) {
          seenKeys.add(dedup);
          findings.push({
            ruleId: sinkRule.ruleId,
            vulnClass: sinkRule.vulnClass,
            title: `${sinkRule.title} at ${item.formattedAddress}`,
            category: "memory_sink",
            severity: sinkRule.severity,
            cvssWeight: sinkRule.cvssWeight,
            cwe: sinkRule.cwe,
            reapPlaybookId: "reap-10-vulnerability-research",
            address: item.formattedAddress,
            evidence: redactFirmwareEvidence(val),
            remediation: sinkRule.remediation,
          });
        }
      }
    }
  }

  return findings;
}

export function scanDeviceTreeSource(dtsText: string): FirmwareAuditFinding[] {
  const lines = dtsText.split(/\r?\n/);
  const findings: FirmwareAuditFinding[] = [];

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    const trimmed = rawLine.trim();
    if (
      !trimmed ||
      trimmed.startsWith("//") ||
      trimmed.startsWith("/*") ||
      trimmed.startsWith("*")
    ) {
      continue;
    }
    const lineNo = i + 1;

    // Check chosen bootargs for root shells, disabled KASLR/IOMMU, or /dev/mem exposure
    if (/\bbootargs\s*=/.test(trimmed)) {
      const hasRootShell = /\binit=\/bin\/(?:sh|bash|ash)\b/i.test(trimmed);
      const weakensKernel =
        /\b(?:nokaslr|nosmep|nosmap|nopti|iommu=off|intel_iommu=off|amd_iommu=off|arm-smmu\.disable_bypass=0|strict-devmem=0)\b/i.test(
          trimmed,
        );
      if (hasRootShell || weakensKernel) {
        findings.push({
          ruleId: "FW-DTS-INSECURE-BOOTARGS",
          vulnClass: "insecure_kernel_bootargs",
          title: `Insecure kernel/IOMMU bootargs in Device-Tree at line ${lineNo}`,
          category: "bootloader",
          severity: hasRootShell ? "critical" : "high",
          cvssWeight: hasRootShell ? 9.0 : 8.1,
          cwe: ["CWE-1244", "CWE-119"],
          reapPlaybookId: "reap-19-kernel-and-driver-exploitation-research",
          line: lineNo,
          evidence: redactFirmwareEvidence(trimmed),
          remediation:
            "Remove init=/bin/sh, nokaslr, iommu=off, and strict-devmem=0 from production Device-Tree chosen.bootargs.",
        });
      }
    }

    // Check embedded U-Boot bootcmd / tftpboot properties inside DTS/FIT .its/.dts files
    // Extract the quoted RHS property string (or strip the DTS statement-terminating ';')
    // so benign single-command properties like `u-boot,bootcmd = "bootm 0x82000000";`
    // do not false-positive on the trailing DTS semicolon.
    if (/\b(?:bootcmd|u-boot,bootcmd|altbootcmd)\s*=/.test(trimmed)) {
      const quotedRhs = trimmed.match(/=\s*"([^"]*)"/);
      const bootcmdBody = quotedRhs
        ? quotedRhs[1]
        : trimmed.replace(/;\s*$/, "");
      if (
        /\b(?:tftpboot|tftp|dhcp|nfs|pxe|usbboot)\b|[;&|`]|(?:\$\()|\binit=\/bin\/(?:sh|bash|ash)\b/i.test(
          bootcmdBody,
        )
      ) {
        findings.push({
          ruleId: "FW-UBOOT-BOOTCMD-INJECT",
          vulnClass: "bootloader_command_injection",
          title: `Unauthenticated U-Boot bootcmd / network boot vector in Device-Tree at line ${lineNo}`,
          category: "bootloader",
          severity: "critical",
          cvssWeight: 9.1,
          cwe: ["CWE-78", "CWE-353"],
          reapPlaybookId: "reap-07-firmware-and-embedded",
          line: lineNo,
          evidence: redactFirmwareEvidence(trimmed),
          remediation:
            "Remove unauthenticated tftpboot/shell command chains from Device-Tree U-Boot config nodes and require signed FIT boot.",
        });
      }
    }

    // Check bootdelay in DTS config node (supports <-2>, <(-2)>, and "-2")
    const dtsDelay = trimmed.match(
      /\bbootdelay\s*=\s*(?:<(?:\(\s*)?(-?\d+)(?:\s*\))?>|"(-?\d+)")/i,
    );
    if (dtsDelay) {
      const val = parseInt(dtsDelay[1] ?? dtsDelay[2], 10);
      if (val > 0 || val === -1) {
        findings.push({
          ruleId: "FW-UBOOT-CONSOLE-EXPOSED",
          vulnClass: "exposed_bootloader_console",
          title: `Interactive U-Boot autoboot delay enabled in Device-Tree at line ${lineNo}`,
          category: "bootloader",
          severity: "medium",
          cvssWeight: 6.4,
          cwe: ["CWE-1244"],
          reapPlaybookId: "reap-07-firmware-and-embedded",
          line: lineNo,
          evidence: redactFirmwareEvidence(trimmed),
          remediation:
            "Set bootdelay to -2 in production Device-Tree U-Boot configurations to prevent physical UART console abort.",
        });
      }
    }

    // Check flash partition blocks for writable bootloader / u-boot-env partitions
    if (/^(?:[\w-]+\s*:\s*)?partition@[0-9a-fA-F]+\s*\{/.test(trimmed)) {
      let depth = 0;
      const blockLines: string[] = [];
      for (let j = i; j < Math.min(lines.length, i + 30); j++) {
        blockLines.push(lines[j]);
        for (const ch of lines[j]) {
          if (ch === "{") depth++;
          else if (ch === "}") depth--;
        }
        if (depth <= 0 && j > i) break;
      }
      const blockText = blockLines.join("\n");
      const labelMatch = blockText.match(
        /\blabel\s*=\s*"(u-boot(?:-env)?|bootloader|factory|art|uboot-env)"/i,
      );
      if (labelMatch && !/\b(?:read-only|lock)\s*;/.test(blockText)) {
        findings.push({
          ruleId: "FW-DTS-WRITABLE-BOOT-PARTITION",
          vulnClass: "writable_boot_partition",
          title: `Writable critical MTD flash partition "${labelMatch[1]}" at line ${lineNo}`,
          category: "bootloader",
          severity: "medium",
          cvssWeight: 5.8,
          cwe: ["CWE-353", "CWE-1244"],
          reapPlaybookId: "reap-07-firmware-and-embedded",
          line: lineNo,
          evidence: `MTD partition "${labelMatch[1]}" lacks 'read-only;' property at line ${lineNo}`,
          remediation:
            "Mark bootloader, U-Boot environment, and factory calibration MTD partitions 'read-only;' in the Device-Tree and enforce hardware WP#.",
        });
      }
    }

    // Also inspect DTS lines for hardcoded PSKs/keys/passwords
    for (const credRule of EMBEDDED_CREDENTIAL_PATTERNS) {
      if (credRule.re.test(trimmed)) {
        findings.push({
          ruleId: credRule.id,
          vulnClass: "hardcoded_credential",
          title: `${credRule.label} in Device-Tree at line ${lineNo}`,
          category: "secret",
          severity: credRule.severity,
          cvssWeight: credRule.cvssWeight,
          cwe: ["CWE-798"],
          reapPlaybookId: "reap-07-firmware-and-embedded",
          line: lineNo,
          evidence: redactFirmwareEvidence(trimmed),
          remediation:
            "Never store Wi-Fi PSKs, passwords, or private keys in plaintext Device-Tree source/blobs.",
        });
        break;
      }
    }
  }

  return findings;
}

// =============================================================================
// 6. HARDWARE EDA SCHEMATIC & PCB S-EXPRESSION SCANNER (.KICAD_SCH / .KICAD_PCB)
// =============================================================================

interface SExprAtom {
  kind: "atom";
  value: string;
  quoted: boolean;
  line: number;
}

interface SExprList {
  kind: "list";
  items: SExprNode[];
  line: number;
}

type SExprNode = SExprAtom | SExprList;

function parseKicadSExpressions(source: string): SExprList[] {
  const roots: SExprList[] = [];
  const stack: SExprList[] = [];
  let line = 1;
  let i = 0;

  const pushNode = (node: SExprNode): void => {
    if (stack.length > 0) {
      stack[stack.length - 1].items.push(node);
    } else if (node.kind === "list") {
      roots.push(node);
    }
  };

  while (i < source.length) {
    const ch = source[i];
    if (ch === "\n") {
      line++;
      i++;
      continue;
    }
    if (ch === "\r" || ch === " " || ch === "\t") {
      i++;
      continue;
    }
    if (ch === ";") {
      while (i < source.length && source[i] !== "\n") i++;
      continue;
    }
    if (ch === "(") {
      const listNode: SExprList = { kind: "list", items: [], line };
      pushNode(listNode);
      stack.push(listNode);
      i++;
      continue;
    }
    if (ch === ")") {
      if (stack.length > 0) stack.pop();
      i++;
      continue;
    }
    if (ch === '"') {
      const startLine = line;
      i++;
      let str = "";
      while (i < source.length && source[i] !== '"') {
        if (source[i] === "\\" && i + 1 < source.length) {
          i++;
          str += source[i];
        } else {
          if (source[i] === "\n") line++;
          str += source[i];
        }
        i++;
      }
      if (i < source.length && source[i] === '"') i++;
      pushNode({ kind: "atom", value: str, quoted: true, line: startLine });
      continue;
    }

    const startLine = line;
    let bare = "";
    while (
      i < source.length &&
      source[i] !== "(" &&
      source[i] !== ")" &&
      source[i] !== '"' &&
      source[i] !== " " &&
      source[i] !== "\t" &&
      source[i] !== "\r" &&
      source[i] !== "\n"
    ) {
      bare += source[i];
      i++;
    }
    if (bare.length > 0) {
      pushNode({ kind: "atom", value: bare, quoted: false, line: startLine });
    }
  }

  return roots;
}

function listHead(node: SExprNode): string | null {
  if (node.kind !== "list" || node.items.length === 0) return null;
  const first = node.items[0];
  return first.kind === "atom" && !first.quoted ? first.value : null;
}

function atomAt(list: SExprList, index: number): string | null {
  const item = list.items[index];
  return item && item.kind === "atom" ? item.value : null;
}

interface ExtractedEdaComponent {
  reference: string;
  value: string;
  footprint: string;
  description: string;
  dnp: boolean;
  nets: string[];
  line: number;
}

const CONNECTOR_OR_TP_REF_RE = /^(?:J|P|TP|CN|CON|DBG|HDR|JP|SW)\d+/i;
const TEST_POINT_REF_RE = /^TP\d+/i;
const DNP_MARKER_RE = /\b(?:DNP|DNI|NOPOP|DO[_\s-]*NOT[_\s-]*POPULATE|NM)\b/i;

type HardwareInterfaceClass = KicadDebugInterfaceHit["interfaceType"];

interface HardwareRuleSpec {
  interfaceType: HardwareInterfaceClass;
  ruleId: string;
  vulnClass: string;
  titlePrefix: string;
  severity: Severity;
  cvssWeight: number;
  cwe: string[];
  signalRe: RegExp;
  componentValueOrFpRe?: RegExp;
  allowIcRef?: boolean;
  remediation: string;
}

const HARDWARE_INTERFACE_SPECS: readonly HardwareRuleSpec[] = [
  {
    interfaceType: "JTAG",
    ruleId: "FW-EDA-JTAG-EXPOSED",
    vulnClass: "exposed_jtag_interface",
    titlePrefix: "Exposed JTAG hardware debug interface",
    severity: "critical",
    cvssWeight: 8.8,
    cwe: ["CWE-1244"],
    signalRe:
      /(?:^|[/._-])(?:JTAG(?:_[A-Z0-9]+)?|TDI|TDO|TMS|TCK|N?TRST)(?:$|[/._0-9-])/i,
    componentValueOrFpRe: /\bJTAG\b/i,
    remediation:
      "Blow JTAG security fuses / eFuses (e.g., STM32 RDP Level 2, ARM CoreSight authentication, ESP32 DIS_PAD_JTAG) in production and remove external JTAG header routing.",
  },
  {
    interfaceType: "SWD",
    ruleId: "FW-EDA-SWD-EXPOSED",
    vulnClass: "exposed_swd_interface",
    titlePrefix: "Exposed ARM Serial Wire Debug (SWD) interface",
    severity: "high",
    cvssWeight: 8.4,
    cwe: ["CWE-1244"],
    signalRe: /(?:^|[/._-])(?:SWD(?:_[A-Z0-9]+)?|SWDIO|SWCLK|SWO)(?:$|[/._0-9-])/i,
    componentValueOrFpRe: /\b(?:SWD|CORTEX[_-]?DEBUG)\b/i,
    remediation:
      "Enable MCU readout protection / authenticated debug access (CWE-1244) and scrub exposed SWDIO/SWCLK test points or pogo-pin pads on production PCB revisions.",
  },
  {
    interfaceType: "UART",
    ruleId: "FW-EDA-UART-EXPOSED",
    vulnClass: "exposed_uart_console",
    titlePrefix: "Exposed hardware UART debug/console interface",
    severity: "high",
    cvssWeight: 7.4,
    cwe: ["CWE-1244"],
    signalRe:
      /(?:^|[/._-])(?:UART\d*(?:_[A-Z0-9]+)?|USART\d*(?:_[A-Z0-9]+)?|TXD\d*|RXD\d*|DBG_TX|DBG_RX|CONSOLE_TX|CONSOLE_RX)(?:$|[/._0-9-])/i,
    componentValueOrFpRe: /\b(?:UART(?:[_-]?DBG|[_-]?CONSOLE)?|SERIAL[_-]?DBG)\b/i,
    remediation:
      "Disable unauthenticated bootloader/root login shells on UART interfaces, silence sensitive boot logs, and omit external debug UART headers in production.",
  },
  {
    interfaceType: "SPI_FLASH",
    ruleId: "FW-EDA-SPI-FLASH-EXPOSED",
    vulnClass: "exposed_spi_flash",
    titlePrefix: "External SPI NOR flash / SOIC-8 in-circuit extraction surface",
    severity: "high",
    cvssWeight: 7.8,
    cwe: ["CWE-1244", "CWE-353"],
    signalRe:
      /(?:^|[/._-])(?:SPI_FLASH\w*|QSPI_FLASH\w*|FLASH_(?:CS|CLK|SCK|MOSI|MISO|IO\d)|SOIC8)(?:$|[/._0-9-])/i,
    componentValueOrFpRe:
      /\b(?:(?:SPI|NOR|QSPI|SERIAL)[_-]?FLASH|FLASH[_-]?SOIC-?8|SOIC-?8[_-]?FLASH|W25Q\d+\w*|MX25L\d+\w*|GD25Q\d+\w*|SST25\w*|IS25\w*|AT25(?:DF|SF|SL|XE)\w*|S25FL\w*)\b/i,
    allowIcRef: true,
    remediation:
      "Encrypt external SPI flash contents with per-device hardware keys, verify boot integrity before execution, and guard flash status registers with WP#.",
  },
  {
    interfaceType: "BOOT_PIN",
    ruleId: "FW-EDA-BOOT-PIN-EXPOSED",
    vulnClass: "exposed_boot_mode_strap",
    titlePrefix: "Exposed ROM bootloader mode strap pin (BOOT0 / BOOT_SEL)",
    severity: "high",
    cvssWeight: 7.5,
    cwe: ["CWE-1244"],
    signalRe:
      /(?:^|[/._-])(?:BOOT0|BOOT1|BOOT_SEL|BOOTSEL|ISP_EN|DFU_BOOT|FORCE_RECOVERY)(?:$|[/._0-9-])/i,
    componentValueOrFpRe: /\b(?:BOOT0|BOOT_SEL|BOOTSEL|DFU_HDR)\b/i,
    remediation:
      "Fuse-lock boot device selection in OTP/option bytes so physical BOOT0/BOOT_SEL strapping cannot force mask-ROM DFU/ISP download mode.",
  },
  {
    interfaceType: "I2C_EEPROM",
    ruleId: "FW-EDA-I2C-EEPROM-EXPOSED",
    vulnClass: "exposed_i2c_eeprom_bus",
    titlePrefix: "Unauthenticated external I2C EEPROM / configuration bus",
    severity: "medium",
    cvssWeight: 6.5,
    cwe: ["CWE-1244", "CWE-353"],
    signalRe:
      /(?:^|[/._-])(?:I2C\d*_(?:SDA|SCL)|EEPROM_(?:SDA|SCL|WP)|SDA_EEPROM|SCL_EEPROM)(?:$|[/._0-9-])/i,
    componentValueOrFpRe:
      /\b(?:AT24C\d+\w*|24LC\d+\w*|24AA\d+\w*|M24C\d+\w*|I2C[_-]?EEPROM)\b/i,
    allowIcRef: true,
    remediation:
      "Authenticate and MAC-protect data stored on external I2C EEPROMs (CWE-353) so bus interposition cannot spoof device configuration or credentials.",
  },
];

export function scanKicadEda(
  source: string,
  format: "kicad_sch" | "kicad_pcb",
): {
  hits: KicadDebugInterfaceHit[];
  findings: FirmwareAuditFinding[];
} {
  const roots = parseKicadSExpressions(source);
  const components: ExtractedEdaComponent[] = [];
  const schematicLabels: Array<{ name: string; line: number }> = [];

  for (const root of roots) {
    const head = listHead(root);
    if (head !== "kicad_sch" && head !== "kicad_pcb") {
      continue;
    }

    for (const child of root.items.slice(1)) {
      const childHead = listHead(child);
      if (!childHead || child.kind !== "list") continue;

      // Skip schematic library symbol templates (not placed board components)
      if (childHead === "lib_symbols") {
        continue;
      }

      if (
        childHead === "label" ||
        childHead === "global_label" ||
        childHead === "hierarchical_label"
      ) {
        const labelName = atomAt(child, 1);
        if (labelName) {
          schematicLabels.push({ name: labelName, line: child.line });
        }
        continue;
      }

      if (
        childHead === "symbol" ||
        childHead === "footprint" ||
        childHead === "module"
      ) {
        let reference = "";
        let value = "";
        let footprint =
          childHead === "footprint" || childHead === "module"
            ? (atomAt(child, 1) ?? "")
            : "";
        let description = "";
        let dnp = false;
        const compNets = new Set<string>();

        for (const sub of child.items.slice(1)) {
          if (sub.kind !== "list") continue;
          const subHead = listHead(sub);
          if (subHead === "property") {
            const propKey = (atomAt(sub, 1) ?? "").toLowerCase();
            const propVal = atomAt(sub, 2) ?? "";
            if (propKey === "reference") reference = propVal;
            else if (propKey === "value") value = propVal;
            else if (propKey === "footprint") footprint = propVal;
            else if (propKey === "description") description = propVal;
            else if (
              (propKey === "dnp" || propKey === "populated") &&
              /^(?:yes|true|1|dnp|no_pop)$/i.test(propVal)
            ) {
              dnp = true;
            }
          } else if (subHead === "fp_text") {
            const kind = (atomAt(sub, 1) ?? "").toLowerCase();
            const val = atomAt(sub, 2) ?? "";
            if (kind === "reference") reference = val;
            else if (kind === "value") value = val;
          } else if (subHead === "dnp") {
            const flag = (atomAt(sub, 1) ?? "").toLowerCase();
            if (flag === "yes" || flag === "true") dnp = true;
          } else if (subHead === "in_bom") {
            const flag = (atomAt(sub, 1) ?? "").toLowerCase();
            if (flag === "no" || flag === "false") dnp = true;
          } else if (subHead === "attr") {
            for (const attrItem of sub.items.slice(1)) {
              if (
                attrItem.kind === "atom" &&
                attrItem.value.toLowerCase() === "dnp"
              ) {
                dnp = true;
              }
            }
          } else if (subHead === "pad") {
            for (const padSub of sub.items.slice(1)) {
              if (padSub.kind === "list" && listHead(padSub) === "net") {
                const netName = atomAt(padSub, 2) ?? atomAt(padSub, 1) ?? "";
                if (netName && !/^(?:unconnected-|\?|$)/i.test(netName)) {
                  compNets.add(netName);
                }
              }
            }
          } else if (subHead === "pin") {
            const pinNameOrNum = atomAt(sub, 1) ?? "";
            for (const pinSub of sub.items.slice(1)) {
              if (pinSub.kind === "list" && listHead(pinSub) === "name") {
                const nm = atomAt(pinSub, 1);
                if (nm && nm !== "~") compNets.add(nm);
              }
            }
            if (pinNameOrNum && !/^\d+$/.test(pinNameOrNum)) {
              compNets.add(pinNameOrNum);
            }
          } else if (subHead === "instances") {
            // KiCad 7/8 symbol instance reference fallback
            const stackInst: SExprList[] = [sub];
            while (stackInst.length > 0 && !reference) {
              const cur = stackInst.pop();
              if (!cur) break;
              if (listHead(cur) === "reference") {
                reference = atomAt(cur, 1) ?? reference;
              } else {
                for (const item of cur.items) {
                  if (item.kind === "list") stackInst.push(item);
                }
              }
            }
          }
        }

        if (DNP_MARKER_RE.test(value) || DNP_MARKER_RE.test(description)) {
          dnp = true;
        }

        if (reference) {
          components.push({
            reference,
            value,
            footprint,
            description,
            dnp,
            nets: Array.from(compNets),
            line: child.line,
          });
        }
      }
    }
  }

  const hits: KicadDebugInterfaceHit[] = [];
  const findings: FirmwareAuditFinding[] = [];

  for (const spec of HARDWARE_INTERFACE_SPECS) {
    const matchedDesignators = new Set<string>();
    const matchedNets = new Set<string>();
    let anyUnpopulated = false;
    let anyTestPoint = false;
    let firstLine = 0;

    // Matchschematic net labels first so connector + label schematics correlate cleanly
    const matchingSchematicLabels = schematicLabels.filter((lbl) =>
      spec.signalRe.test(lbl.name),
    );

    for (const comp of components) {
      const isConnectorOrTp = CONNECTOR_OR_TP_REF_RE.test(comp.reference);
      const isIcAllowed = Boolean(spec.allowIcRef && /^U\d+/i.test(comp.reference));
      if (!isConnectorOrTp && !isIcAllowed) {
        continue;
      }

      const compNetsMatched = comp.nets.filter((n) => spec.signalRe.test(n));
      const compMetaText = `${comp.value} ${comp.footprint} ${comp.description}`;
      const valueSignalMatched = spec.signalRe.test(comp.value);
      const metaMatched =
        valueSignalMatched ||
        Boolean(
          spec.componentValueOrFpRe &&
            spec.componentValueOrFpRe.test(compMetaText),
        );

      if (compNetsMatched.length > 0 || metaMatched) {
        matchedDesignators.add(comp.reference);
        for (const n of compNetsMatched) matchedNets.add(n);
        if (valueSignalMatched) matchedNets.add(comp.value);
        if (comp.dnp) anyUnpopulated = true;
        if (TEST_POINT_REF_RE.test(comp.reference)) anyTestPoint = true;
        if (firstLine === 0 || comp.line < firstLine) firstLine = comp.line;
      }
    }

    // In .kicad_sch files, net labels (e.g. (label "SWDIO")) sit on wires adjacent to generic J*/TP*/P*
    // symbols (like Value="Conn_01x04") rather than nested inside (symbol ...) pads.
    if (format === "kicad_sch" && matchingSchematicLabels.length > 0) {
      for (const lbl of matchingSchematicLabels) {
        matchedNets.add(lbl.name);
        if (firstLine === 0 || lbl.line < firstLine) firstLine = lbl.line;
      }
      if (matchedDesignators.size === 0) {
        for (const comp of components) {
          if (!CONNECTOR_OR_TP_REF_RE.test(comp.reference)) continue;
          const compMetaText = `${comp.value} ${comp.footprint} ${comp.description}`;
          // Skip components explicitly labeled for a different debug protocol
          const belongsToOtherProtocol = HARDWARE_INTERFACE_SPECS.some(
            (other) =>
              other.interfaceType !== spec.interfaceType &&
              (other.signalRe.test(comp.value) ||
                Boolean(
                  other.componentValueOrFpRe &&
                    other.componentValueOrFpRe.test(compMetaText),
                )),
          );
          if (belongsToOtherProtocol) continue;

          if (
            /\b(?:conn|header|testpoint|pinheader|dbg|debug|prog|isp|boot)\b/i.test(
              compMetaText,
            ) ||
            TEST_POINT_REF_RE.test(comp.reference)
          ) {
            matchedDesignators.add(comp.reference);
            if (comp.dnp) anyUnpopulated = true;
            if (TEST_POINT_REF_RE.test(comp.reference)) anyTestPoint = true;
          }
        }
      }
    }

    // Require either a matched connector/TP/IC designator OR >=1 debug net alongside a placed connector/TP
    if (matchedDesignators.size === 0) {
      continue;
    }

    // For I2C_EEPROM in schematics where U* EEPROM matched by value, include schematic I2C SDA/SCL labels
    if (spec.interfaceType === "I2C_EEPROM" && format === "kicad_sch") {
      for (const lbl of schematicLabels) {
        if (/(?:^|[/._-])(?:I2C\w*|SDA\d*|SCL\d*)(?:$|[/._0-9-])/i.test(lbl.name)) {
          matchedNets.add(lbl.name);
        }
      }
    }

    const designators = Array.from(matchedDesignators).sort();
    const nets = Array.from(matchedNets).sort();
    const line = firstLine || 1;

    hits.push({
      interfaceType: spec.interfaceType,
      designators,
      nets,
      unpopulated: anyUnpopulated,
      testPointExposed: anyTestPoint,
      line,
    });

    const exposureQualifiers: string[] = [];
    if (anyUnpopulated) {
      exposureQualifiers.push(
        "unpopulated/DNP footprint pads remain physically accessible to pogo-pin probes",
      );
    }
    if (anyTestPoint) {
      exposureQualifiers.push("exposed bare PCB test-point pad(s)");
    }

    const netDesc = nets.length > 0 ? `nets=[${nets.join(", ")}]` : "component metadata match";
    const qualDesc =
      exposureQualifiers.length > 0 ? ` (${exposureQualifiers.join("; ")})` : "";

    findings.push({
      ruleId: spec.ruleId,
      vulnClass: spec.vulnClass,
      title: `${spec.titlePrefix} on ${designators.join(", ")}${anyUnpopulated ? " (unpopulated/DNP)" : ""}`,
      category: "hardware_debug",
      severity: spec.severity,
      cvssWeight: spec.cvssWeight,
      cwe: spec.cwe,
      reapPlaybookId: "reap-13-dma-and-hardware-assisted-cheat-research-defensive",
      line,
      designators,
      nets,
      unpopulatedOrTestPoint: anyUnpopulated || anyTestPoint,
      evidence: `KiCad ${format} line ${line}: designators=[${designators.join(", ")}], ${netDesc}${qualDesc}`,
      remediation: spec.remediation,
    });
  }

  return { hits, findings };
}

// =============================================================================
// 7. UNIFIED ARTIFACT DISPATCHER & CUSTOM TOOL DEFINITION
// =============================================================================

function detectFirmwareArtifactFormat(
  fileName: string,
  buf: Buffer,
): FirmwareArtifactFormat {
  const ext = extname(fileName).toLowerCase();
  if (ext === ".kicad_sch") return "kicad_sch";
  if (ext === ".kicad_pcb") return "kicad_pcb";
  if (ext === ".dts" || ext === ".dtsi") return "dts";
  if (ext === ".hex" || ext === ".ihex") return "ihex";
  if (
    ext === ".srec" ||
    ext === ".s19" ||
    ext === ".s28" ||
    ext === ".s37" ||
    ext === ".mot"
  ) {
    return "srec";
  }

  if (
    buf.length >= 4 &&
    buf[0] === 0x7f &&
    buf[1] === 0x45 &&
    buf[2] === 0x4c &&
    buf[3] === 0x46
  ) {
    return "elf";
  }

  if (buf.length >= 4) {
    const magic = buf.readUInt32BE(0);
    if (magic === 0x27051956 || magic === 0xd00dfeed) {
      return "uboot";
    }
  }

  const headText = buf
    .subarray(0, Math.min(buf.length, 512))
    .toString("utf8")
    .trimStart();
  if (headText.startsWith("(kicad_sch")) return "kicad_sch";
  if (headText.startsWith("(kicad_pcb")) return "kicad_pcb";
  if (/^\/dts-v1\/\s*;/.test(headText)) return "dts";
  if (/^:[0-9a-fA-F]{10,}/m.test(headText)) return "ihex";
  if (/^S[0123789][0-9a-fA-F]{6,}/m.test(headText)) return "srec";
  if (/\b(?:bootcmd|bootdelay)\s*=/.test(headText)) return "uboot";

  return "raw_firmware";
}

export function analyzeFirmwareBuffer(
  buf: Buffer,
  filePath: string,
): FirmwareAuditReport {
  const fileName = basename(filePath);
  const detectedFormat = detectFirmwareArtifactFormat(fileName, buf);
  const findings: FirmwareAuditFinding[] = [];
  let hexDecode: HexDecodeResult | undefined;
  let elf: ElfMetadata | undefined;
  let ubootContainers: UBootContainerHit[] = [];
  let kicadHits: KicadDebugInterfaceHit[] | undefined;
  let extractedStringCount = 0;

  if (detectedFormat === "kicad_sch" || detectedFormat === "kicad_pcb") {
    const text = buf.toString("utf8");
    const eda = scanKicadEda(text, detectedFormat);
    kicadHits = eda.hits;
    findings.push(...eda.findings);
  } else if (detectedFormat === "dts") {
    const text = buf.toString("utf8");
    findings.push(...scanDeviceTreeSource(text));
    const positioned = extractPositionedStrings([
      { baseAddress: 0, data: buf },
    ]);
    extractedStringCount = positioned.length;
    findings.push(
      ...scanPositionedStringsAndBootEnv(positioned, {
        allowSymbolMatch: false,
      }).filter(
        (f) =>
          f.category !== "bootloader" &&
          !findings.some((existing) => existing.ruleId === f.ruleId),
      ),
    );
  } else if (detectedFormat === "ihex" || detectedFormat === "srec") {
    const text = buf.toString("utf8");
    hexDecode =
      detectedFormat === "ihex"
        ? decodeIntelHex(text)
        : decodeMotorolaSrec(text);
    extractedStringCount = hexDecode.strings.length;
    findings.push(...hexDecode.findings);

    // Inspect every coalesced segment for embedded ELF/uImage/FDT headers, secrets, bootenv, & sinks
    for (const seg of hexDecode.segments) {
      const elfParsed = parseElfMetadata(seg.data);
      if (elfParsed && !elf) {
        elf = elfParsed.metadata;
        findings.push(...elfParsed.findings);
      }
      const containerScan = scanBinaryContainerSignatures(
        seg.data,
        seg.baseAddress,
      );
      ubootContainers.push(...containerScan.containers);
      findings.push(...containerScan.findings);
    }

    findings.push(
      ...scanPositionedStringsAndBootEnv(hexDecode.strings, {
        allowSymbolMatch: true,
      }),
    );
  } else {
    // ELF, U-Boot uImage/FIT/env, or raw binary firmware blob
    const elfParsed = parseElfMetadata(buf);
    if (elfParsed) {
      elf = elfParsed.metadata;
      findings.push(...elfParsed.findings);
    }

    const containerScan = scanBinaryContainerSignatures(buf, 0);
    ubootContainers = containerScan.containers;
    findings.push(...containerScan.findings);

    // Build virtual-address-mapped segments for ELF PT_LOAD ranges when available
    const stringSegments: Array<{ baseAddress: number; data: Buffer }> = [];
    if (elf && elf.loadSegments.length > 0) {
      for (const loadSeg of elf.loadSegments) {
        if (
          loadSeg.filesz > 0 &&
          loadSeg.offset >= 0 &&
          loadSeg.offset + loadSeg.filesz <= buf.length &&
          loadSeg.vaddr <= BigInt(Number.MAX_SAFE_INTEGER)
        ) {
          stringSegments.push({
            baseAddress: Number(loadSeg.vaddr),
            data: buf.subarray(loadSeg.offset, loadSeg.offset + loadSeg.filesz),
          });
        }
      }
    }
    if (stringSegments.length === 0) {
      stringSegments.push({ baseAddress: 0, data: buf });
    }

    const positioned = extractPositionedStrings(stringSegments);
    extractedStringCount = positioned.length;
    findings.push(
      ...scanPositionedStringsAndBootEnv(positioned, {
        allowSymbolMatch: true,
      }),
    );
  }

  return {
    filePath,
    fileName,
    sizeBytes: buf.length,
    detectedFormat,
    hexDecode,
    elf,
    ubootContainers,
    kicadHits,
    extractedStringCount,
    findings,
  };
}

function toToolFinding(f: FirmwareAuditFinding, fileLabel: string): ToolFinding {
  const playbook = getReapPlaybookById(f.reapPlaybookId);
  const playbookLabel = playbook
    ? `${f.reapPlaybookId} (${playbook.id}: ${playbook.title})`
    : f.reapPlaybookId;
  const locParts: string[] = [fileLabel];
  if (f.address) locParts.push(`addr=${f.address}`);
  if (f.line !== undefined) locParts.push(`line=${f.line}`);
  if (f.designators?.length) {
    locParts.push(`designators=[${f.designators.join(", ")}]`);
  }
  if (f.nets?.length) {
    locParts.push(`nets=[${f.nets.join(", ")}]`);
  }

  return {
    title: f.title,
    severity: f.severity,
    cvss: f.cvssWeight,
    cwe: f.cwe,
    remediation: f.remediation,
    provenance: "tool",
    toolName: "firmware_audit_scan",
    details: `[${f.ruleId}] (${locParts.join(", ")}, cvss=${f.cvssWeight.toFixed(1)}, reap_playbook=${playbookLabel}) — ${f.evidence}`,
  };
}

function formatFirmwareReportText(report: FirmwareAuditReport): string {
  const lines: string[] = [
    `firmware_audit_scan ${report.fileName} (${report.sizeBytes} bytes, format=${report.detectedFormat}):`,
  ];

  if (report.hexDecode) {
    const hd = report.hexDecode;
    lines.push(
      `  Hex Decoder (${hd.format.toUpperCase()}): ${hd.validRecordCount}/${hd.recordCount} valid record(s), ${hd.corruptedChecksumCount} checksum/format error(s), ${hd.segments.length} coalesced segment(s), ${hd.strings.length} positioned string(s)` +
        (hd.entryPoint !== undefined
          ? `, entry=${formatHexAddress(hd.entryPoint)}`
          : ""),
    );
    for (const seg of hd.segments.slice(0, 8)) {
      lines.push(
        `    segment ${formatHexAddress(seg.baseAddress)}..${formatHexAddress(seg.endAddress)} (${seg.length} bytes)`,
      );
    }
  }

  if (report.elf) {
    const e = report.elf;
    lines.push(
      `  ELF Header: ELF${e.bitness} ${e.architecture} (${e.endianness}-endian, type=${e.elfType}, entry=${e.entryPoint}, PIE=${e.pieEnabled ? "enabled" : "disabled"}, NX=${e.nxEnabled ? "enabled" : "disabled"}${e.gnuStackFlags ? `, GNU_STACK=${e.gnuStackFlags}` : ""})`,
    );
  }

  if (report.ubootContainers.length > 0) {
    lines.push(
      `  Boot/FDT Containers (${report.ubootContainers.length}):`,
      ...report.ubootContainers.map(
        (c) =>
          `    - ${c.kind} at ${c.formattedOffset}` +
          (c.imageName ? ` name="${c.imageName}"` : "") +
          (c.loadAddress ? ` load=${c.loadAddress}` : "") +
          (c.totalSize ? ` size=${c.totalSize}B` : ""),
      ),
    );
  }

  if (report.kicadHits && report.kicadHits.length > 0) {
    lines.push(
      `  Hardware EDA Debug Surfaces (${report.kicadHits.length}):`,
      ...report.kicadHits.map(
        (h) =>
          `    - ${h.interfaceType}: designators=[${h.designators.join(", ")}] nets=[${h.nets.join(", ")}]${h.unpopulated ? " [UNPOPULATED/DNP]" : ""}${h.testPointExposed ? " [TEST-POINT]" : ""} (line ${h.line})`,
      ),
    );
  }

  if (report.findings.length === 0) {
    lines.push("  No firmware or hardware EDA security findings matched.");
  } else {
    lines.push(`  Security Findings (${report.findings.length}):`);
    for (const f of report.findings) {
      const loc =
        f.address ??
        (f.line !== undefined ? `line ${f.line}` : report.fileName);
      lines.push(
        `    [${f.ruleId}] ${f.cwe.join("/")} (${f.severity}, cvss=${f.cvssWeight.toFixed(1)}, playbook=${f.reapPlaybookId}) @ ${loc}: ${f.title}`,
        `      evidence: ${f.evidence}`,
      );
    }
  }

  return lines.join("\n");
}

export const firmwareAuditScanTool: CustomTool = {
  name: "firmware_audit_scan",
  description:
    "Audit local embedded firmware (.hex, .srec, ELF, U-Boot uImage/FIT/env, .dts/.dtsi) and KiCad hardware EDA files (.kicad_sch, .kicad_pcb) inside T3MP3ST_SOURCE_ROOT for checksum corruption, ELF RWX/PIE weaknesses, bootloader command injection, redacted hardcoded secrets, unsafe C/RTOS sinks, and exposed JTAG/SWD/UART/SPI/BOOT0/I2C debug headers",
  category: "re",
  parameters: [
    {
      name: "path",
      type: "string",
      description:
        "Relative or absolute path within T3MP3ST_SOURCE_ROOT to a firmware image, Intel HEX / S-Record file, ELF binary, .dts/.dtsi, KiCad .kicad_sch/.kicad_pcb, or directory",
      required: true,
    },
    {
      name: "max_bytes",
      type: "number",
      description:
        "Optional maximum artifact byte size ceiling (1..16777216, default 16777216)",
      required: false,
    },
  ],
  handler: async (context) => {
    const rawPath = context.parameters.path;
    const requestedPath =
      typeof rawPath === "string" && rawPath.trim().length > 0
        ? rawPath.trim()
        : "";
    if (!requestedPath) {
      return {
        success: false,
        error: "firmware_audit_scan: path parameter is required",
      };
    }

    const configuredRoot = resolveConfiguredSourceRoot(context);
    if (!configuredRoot) {
      return {
        success: false,
        error:
          "firmware_audit_scan: T3MP3ST_SOURCE_ROOT must name the approved analysis root",
      };
    }

    const maxBytesParam = Number(context.parameters.max_bytes);
    const maxBytes =
      Number.isFinite(maxBytesParam) && maxBytesParam > 0
        ? Math.min(DEFAULT_MAX_FIRMWARE_BYTES, Math.floor(maxBytesParam))
        : DEFAULT_MAX_FIRMWARE_BYTES;

    const approved = resolveApprovedFirmwarePath(
      "firmware_audit_scan",
      configuredRoot,
      requestedPath,
      true,
    );
    if (!approved.ok) {
      return { success: false, error: approved.error };
    }

    const { root: realRoot, path: resolved, stat } = approved;

    if (stat.isDirectory()) {
      let rawEntries: string[];
      try {
        rawEntries = readdirSync(resolved);
      } catch (err) {
        return {
          success: false,
          error: `firmware_audit_scan: failed to read directory (${formatFsError(err)})`,
        };
      }

      const reports: FirmwareAuditReport[] = [];
      const toolFindings: ToolFinding[] = [];
      const warnings: string[] = [];

      for (const entryName of rawEntries) {
        if (reports.length >= 40) break;
        const entryPath = join(resolved, entryName);

        let entryLstat: Stats;
        try {
          entryLstat = lstatSync(entryPath);
        } catch (err) {
          warnings.push(
            `  - ${entryName} (skipped: unreadable entry — ${formatFsError(err)})`,
          );
          continue;
        }

        let realEntry: string;
        try {
          realEntry = realpathSync(entryPath);
        } catch (err) {
          warnings.push(
            `  - ${entryName} (skipped: broken or unresolvable symlink/path — ${formatFsError(err)})`,
          );
          continue;
        }

        if (!isWithinFirmwareRoot(realRoot, realEntry)) {
          warnings.push(
            `  - ${entryName} (skipped: symlink target escapes T3MP3ST_SOURCE_ROOT)`,
          );
          continue;
        }

        let fstat: Stats;
        try {
          fstat = entryLstat.isSymbolicLink() ? statSync(realEntry) : entryLstat;
        } catch (err) {
          warnings.push(
            `  - ${entryName} (skipped: cannot inspect entry — ${formatFsError(err)})`,
          );
          continue;
        }

        if (!fstat.isFile()) {
          continue;
        }

        const ext = extname(entryName).toLowerCase();
        if (!FIRMWARE_CANDIDATE_EXTENSIONS.has(ext) && fstat.size > 262144) {
          continue;
        }
        if (fstat.size > maxBytes) {
          warnings.push(
            `  - ${entryName} (skipped: exceeds ${maxBytes} bytes)`,
          );
          continue;
        }

        let buf: Buffer;
        try {
          buf = readFileSync(realEntry);
        } catch (err) {
          warnings.push(
            `  - ${entryName} (skipped: read failed — ${formatFsError(err)})`,
          );
          continue;
        }

        const rep = analyzeFirmwareBuffer(buf, realEntry);
        reports.push(rep);
        for (const f of rep.findings) {
          toolFindings.push(toToolFinding(f, entryName));
        }
      }

      const outLines: string[] = [
        `firmware_audit_scan directory ${resolved} (${reports.length} artifact(s) scanned):`,
        ...reports.map(
          (r) =>
            `  - ${r.fileName} (${r.detectedFormat}, ${r.sizeBytes}B): ${r.findings.length} finding(s)`,
        ),
      ];
      for (const r of reports) {
        for (const f of r.findings) {
          outLines.push(
            `      [${f.ruleId} ${f.cwe.join("/")}] ${r.fileName}${f.address ? `@${f.address}` : f.line ? `:${f.line}` : ""} — ${f.title} (playbook=${f.reapPlaybookId})`,
          );
        }
      }
      if (warnings.length > 0) {
        outLines.push("Warnings:", ...warnings);
      }

      return {
        success: true,
        output: outLines.join("\n"),
        findings: toolFindings.length > 0 ? toolFindings : undefined,
      };
    }

    if (stat.size > maxBytes) {
      return {
        success: false,
        error: `firmware_audit_scan: file exceeds ${maxBytes} bytes (${stat.size} bytes)`,
      };
    }

    let buf: Buffer;
    try {
      buf = readFileSync(resolved);
    } catch (err) {
      return {
        success: false,
        error: `firmware_audit_scan: failed to read file (${formatFsError(err)})`,
      };
    }

    const report = analyzeFirmwareBuffer(buf, resolved);
    const toolFindings =
      report.findings.length > 0
        ? report.findings.map((f) => toToolFinding(f, report.fileName))
        : undefined;

    return {
      success: true,
      output: formatFirmwareReportText(report),
      findings: toolFindings,
    };
  },
};
