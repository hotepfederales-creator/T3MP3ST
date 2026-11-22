import { describe, it, expect, afterEach } from "vitest";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  Arsenal,
  BUILTIN_TOOLS,
  createToolContext,
  firmwareAuditScanTool,
  decodeIntelHex,
  decodeMotorolaSrec,
  parseElfMetadata,
  scanKicadEda,
  analyzeFirmwareBuffer,
  getReapPlaybookById,
} from "../arsenal/index.js";
import { ARCHETYPE_PROFILES } from "../operators/index.js";
import {
  OpGeneral,
  YES_THRESHOLD,
  buildMissionRoutingState,
  evaluateMissionRouteOffline,
  recommendToolsForMissionRoute,
} from "../general/index.js";
import type { LLMBackbone } from "../llm/index.js";

/** Helper to encode a valid Intel HEX record with exact two's-complement checksum. */
function makeIntelHexRecord(
  offset16: number,
  recordType: number,
  data: Uint8Array | Buffer,
): string {
  const len = data.length;
  const header = [len & 0xff, (offset16 >> 8) & 0xff, offset16 & 0xff, recordType & 0xff];
  let sum = 0;
  for (const b of header) sum = (sum + b) & 0xff;
  for (const b of data) sum = (sum + b) & 0xff;
  const checksum = (0x100 - sum) & 0xff;
  const all = Buffer.concat([
    Buffer.from(header),
    Buffer.from(data),
    Buffer.from([checksum]),
  ]);
  return `:${all.toString("hex").toUpperCase()}`;
}

/** Helper to encode a valid Motorola S-Record with exact one's-complement checksum. */
function makeSrecRecord(
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
  let rem = address;
  for (let i = 0; i < addrLen; i++) {
    addrBytes.unshift(rem & 0xff);
    rem = Math.floor(rem / 256);
  }
  const count = addrBytes.length + data.length + 1;
  const body = [count & 0xff, ...addrBytes, ...data];
  let sum = 0;
  for (const b of body) sum = (sum + b) & 0xff;
  const checksum = (~sum) & 0xff;
  const hex = Buffer.from([...body, checksum])
    .toString("hex")
    .toUpperCase();
  return `S${typeDigit}${hex}`;
}

/** Build a synthetic minimal ELF32 binary with PT_LOAD + PT_GNU_STACK + payload strings. */
function buildSyntheticElf32(options: {
  elfType: 2 | 3; // 2 = ET_EXEC, 3 = ET_DYN
  machine: number; // 40 = ARM, 8 = MIPS, 243 = RISC-V
  bigEndian?: boolean;
  gnuStackFlags: number; // 0x7 = RWX, 0x6 = RW-
  loadVaddr: number;
  payload: Buffer;
}): Buffer {
  const ehdrSize = 52;
  const phentSize = 32;
  const phnum = 2;
  const payloadOffset = 0x100;
  const totalSize = payloadOffset + options.payload.length;
  const buf = Buffer.alloc(totalSize, 0);

  // Magic: \x7fELF
  buf[0] = 0x7f;
  buf[1] = 0x45;
  buf[2] = 0x4c;
  buf[3] = 0x46;
  buf[4] = 1; // ELFCLASS32
  buf[5] = options.bigEndian ? 2 : 1; // ELFDATA2MSB or ELFDATA2LSB
  buf[6] = 1; // EV_CURRENT

  const writeU16 = (off: number, v: number): void => {
    if (options.bigEndian) buf.writeUInt16BE(v, off);
    else buf.writeUInt16LE(v, off);
  };
  const writeU32 = (off: number, v: number): void => {
    if (options.bigEndian) buf.writeUInt32BE(v >>> 0, off);
    else buf.writeUInt32LE(v >>> 0, off);
  };

  writeU16(16, options.elfType);
  writeU16(18, options.machine);
  writeU32(20, 1); // e_version
  writeU32(24, options.loadVaddr); // e_entry
  writeU32(28, ehdrSize); // e_phoff
  writeU16(40, ehdrSize); // e_ehsize
  writeU16(42, phentSize); // e_phentsize
  writeU16(44, phnum); // e_phnum

  // Program Header 0: PT_LOAD (1)
  const ph0 = ehdrSize;
  writeU32(ph0 + 0, 1); // PT_LOAD
  writeU32(ph0 + 4, payloadOffset); // p_offset
  writeU32(ph0 + 8, options.loadVaddr); // p_vaddr
  writeU32(ph0 + 12, options.loadVaddr); // p_paddr
  writeU32(ph0 + 16, options.payload.length); // p_filesz
  writeU32(ph0 + 20, options.payload.length); // p_memsz
  writeU32(ph0 + 24, 0x5); // PF_R | PF_X

  // Program Header 1: PT_GNU_STACK (0x6474e551)
  const ph1 = ehdrSize + phentSize;
  writeU32(ph1 + 0, 0x6474e551);
  writeU32(ph1 + 24, options.gnuStackFlags);

  options.payload.copy(buf, payloadOffset);
  return buf;
}

/** Build a synthetic minimal ELF64 little-endian binary. */
function buildSyntheticElf64(options: {
  elfType: 2 | 3;
  machine: number; // 183 = AArch64, 243 = RISC-V, 62 = x86_64
  gnuStackFlags: number;
  loadVaddr: bigint;
  payload: Buffer;
}): Buffer {
  const ehdrSize = 64;
  const phentSize = 56;
  const phnum = 2;
  const payloadOffset = 0x200;
  const buf = Buffer.alloc(payloadOffset + options.payload.length, 0);

  buf[0] = 0x7f;
  buf[1] = 0x45;
  buf[2] = 0x4c;
  buf[3] = 0x46;
  buf[4] = 2; // ELFCLASS64
  buf[5] = 1; // ELFDATA2LSB
  buf[6] = 1;

  buf.writeUInt16LE(options.elfType, 16);
  buf.writeUInt16LE(options.machine, 18);
  buf.writeUInt32LE(1, 20);
  buf.writeBigUInt64LE(options.loadVaddr, 24); // e_entry
  buf.writeBigUInt64LE(BigInt(ehdrSize), 32); // e_phoff
  buf.writeUInt16LE(ehdrSize, 52);
  buf.writeUInt16LE(phentSize, 54);
  buf.writeUInt16LE(phnum, 56);

  // PH0: PT_LOAD
  const ph0 = ehdrSize;
  buf.writeUInt32LE(1, ph0 + 0); // PT_LOAD
  buf.writeUInt32LE(0x5, ph0 + 4); // PF_R | PF_X
  buf.writeBigUInt64LE(BigInt(payloadOffset), ph0 + 8);
  buf.writeBigUInt64LE(options.loadVaddr, ph0 + 16);
  buf.writeBigUInt64LE(options.loadVaddr, ph0 + 24);
  buf.writeBigUInt64LE(BigInt(options.payload.length), ph0 + 32);
  buf.writeBigUInt64LE(BigInt(options.payload.length), ph0 + 40);

  // PH1: PT_GNU_STACK
  const ph1 = ehdrSize + phentSize;
  buf.writeUInt32LE(0x6474e551, ph1 + 0);
  buf.writeUInt32LE(options.gnuStackFlags, ph1 + 4);

  options.payload.copy(buf, payloadOffset);
  return buf;
}

describe("Hardware EDA & Embedded Firmware Security Scanner (firmware_audit_scan)", () => {
  const prevSourceRoot = process.env.T3MP3ST_SOURCE_ROOT;

  afterEach(() => {
    if (prevSourceRoot === undefined) {
      delete process.env.T3MP3ST_SOURCE_ROOT;
    } else {
      process.env.T3MP3ST_SOURCE_ROOT = prevSourceRoot;
    }
  });

  describe("Intel HEX (.hex / .ihex) & Motorola S-Record (.srec / .s19) Decoders", () => {
    it("decodes valid Intel HEX (04 linear + 02 segment + 00 data + 05 entry + 01 EOF), coalesces contiguous segments, and attributes ASCII & UTF-16LE strings to exact addresses", () => {
      const partA = Buffer.from("BOOT_OK\0", "ascii"); // 8 bytes @ 0x08000100
      const partB = Buffer.from("strcpy(dst, src);\0", "ascii"); // 18 bytes @ 0x08000108 (contiguous!)
      const utf16Payload = Buffer.from("SWD_KEY=9911\0", "utf16le"); // @ 0x08000200

      const hexLines = [
        // Extended Linear Address 0x0800 -> base 0x08000000
        makeIntelHexRecord(0x0000, 0x04, Buffer.from([0x08, 0x00])),
        makeIntelHexRecord(0x0100, 0x00, partA),
        makeIntelHexRecord(0x0108, 0x00, partB),
        makeIntelHexRecord(0x0200, 0x00, utf16Payload),
        // Start Linear Address 0x08000101 (Thumb reset vector)
        makeIntelHexRecord(0x0000, 0x05, Buffer.from([0x08, 0x00, 0x01, 0x01])),
        // Extended Segment Address 0x1000 -> base 0x00010000
        makeIntelHexRecord(0x0000, 0x02, Buffer.from([0x10, 0x00])),
        makeIntelHexRecord(0x0020, 0x00, Buffer.from("SEG20_DATA\0", "ascii")),
        makeIntelHexRecord(0x0000, 0x01, Buffer.alloc(0)),
      ].join("\n");

      const decoded = decodeIntelHex(hexLines);
      expect(decoded.corruptedChecksumCount).toBe(0);
      expect(decoded.findings).toEqual([]);
      expect(decoded.entryPoint).toBe(0x08000101);
      // Two contiguous segments at 0x08000100..0x0800011A, 0x08000200..0x0800021A, and 0x00010020..0x0001002B
      expect(decoded.segments).toHaveLength(3);

      const flashSeg = decoded.segments.find((s) => s.baseAddress === 0x08000100);
      expect(flashSeg).toBeDefined();
      expect(flashSeg?.length).toBe(partA.length + partB.length);

      const strcpyStr = decoded.strings.find(
        (s) => s.encoding === "ascii" && s.value === "strcpy(dst, src);",
      );
      expect(strcpyStr?.formattedAddress).toBe("0x08000108");

      const utf16Str = decoded.strings.find(
        (s) => s.encoding === "utf16le" && s.value === "SWD_KEY=9911",
      );
      expect(utf16Str?.formattedAddress).toBe("0x08000200");

      const seg20Str = decoded.strings.find((s) => s.value === "SEG20_DATA");
      expect(seg20Str?.formattedAddress).toBe("0x00010020");

      // Full analyzer attributes unsafe sink inside .hex to 0x08000108!
      const report = analyzeFirmwareBuffer(
        Buffer.from(hexLines, "utf8"),
        "stm32_app.hex",
      );
      expect(report.detectedFormat).toBe("ihex");
      const sinkFinding = report.findings.find(
        (f) => f.ruleId === "FW-SINK-STRCPY-SPRINTF",
      );
      expect(sinkFinding?.address).toBe("0x08000108");
      expect(sinkFinding?.cwe).toContain("CWE-120");
      expect(sinkFinding?.reapPlaybookId).toBe("reap-10-vulnerability-research");
    });

    it("detects corrupted_checksum in Intel HEX with exact line, address, and CWE-353", () => {
      const goodRec = makeIntelHexRecord(
        0x0000,
        0x04,
        Buffer.from([0x08, 0x00]),
      );
      const validDataRec = makeIntelHexRecord(
        0x0400,
        0x00,
        Buffer.from("VALID_BLOCK\0", "ascii"),
      );
      // Flip last hex byte of checksum
      const tamperedRec =
        validDataRec.slice(0, -2) +
        (validDataRec.endsWith("FF") ? "00" : "FF");
      const eofRec = makeIntelHexRecord(0x0000, 0x01, Buffer.alloc(0));

      const decoded = decodeIntelHex([goodRec, tamperedRec, eofRec].join("\n"));
      expect(decoded.corruptedChecksumCount).toBe(1);
      expect(decoded.findings).toHaveLength(1);
      expect(decoded.findings[0]).toMatchObject({
        ruleId: "FW-HEX-CHECKSUM",
        vulnClass: "corrupted_checksum",
        cwe: ["CWE-353"],
        severity: "high",
        line: 2,
        address: "0x08000400",
        reapPlaybookId: "reap-07-firmware-and-embedded",
      });
    });

    it("decodes valid Motorola S-Record (S0/S1/S2/S3 + S7/S8/S9) and flags corrupted S-Record checksums", () => {
      const s0 = makeSrecRecord("0", 0x0000, Buffer.from("RTOS_FW_V2", "ascii"));
      const s3Part1 = makeSrecRecord(
        "3",
        0x80010000,
        Buffer.from("RTOS_INIT\0", "ascii"),
      );
      const s3Part2 = makeSrecRecord(
        "3",
        0x8001000a,
        Buffer.from('system("reboot");\0', "ascii"),
      );
      const s2Rec = makeSrecRecord(
        "2",
        0x123400,
        Buffer.from("S2_MEM\0", "ascii"),
      );
      const s1Rec = makeSrecRecord(
        "1",
        0x4000,
        Buffer.from("S1_BOOT\0", "ascii"),
      );
      const s7Term = makeSrecRecord("7", 0x80010000, Buffer.alloc(0));

      const validSrec = [s0, s3Part1, s3Part2, s2Rec, s1Rec, s7Term].join("\n");
      const decoded = decodeMotorolaSrec(validSrec);

      expect(decoded.corruptedChecksumCount).toBe(0);
      expect(decoded.headerComment).toBe("RTOS_FW_V2");
      expect(decoded.entryPoint).toBe(0x80010000);
      expect(decoded.segments).toHaveLength(3);

      const highSeg = decoded.segments.find((s) => s.baseAddress === 0x80010000);
      expect(highSeg?.length).toBe(10 + 18);

      const sysStr = decoded.strings.find(
        (s) => s.value === 'system("reboot");',
      );
      expect(sysStr?.formattedAddress).toBe("0x8001000A");

      // Corrupt checksum on S3 record at line 3
      const badS3 =
        s3Part2.slice(0, -2) + (s3Part2.endsWith("AA") ? "55" : "AA");
      const corrupted = decodeMotorolaSrec([s0, s3Part1, badS3, s7Term].join("\n"));
      expect(corrupted.corruptedChecksumCount).toBe(1);
      expect(corrupted.findings[0]).toMatchObject({
        ruleId: "FW-SREC-CHECKSUM",
        vulnClass: "corrupted_checksum",
        cwe: ["CWE-353"],
        line: 3,
        address: "0x8001000A",
      });
    });
  });

  describe("ELF32/ELF64 Hardening, Unsafe Sinks & Secret Redaction", () => {
    it("detects ELF32 ARM ET_EXEC + PT_GNU_STACK RWX, unsafe sinks, and redacts raw secrets in evidence", () => {
      // Construct fake test-only secrets dynamically so no literal provider token sits in repo text
      const fakeJwt = [
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "eyJzdWIiOiJyb290Iiwicm9sZSI6ImFkbWluIn0",
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
      ].join(".");
      const fakePemHeader = "-----BEGIN RSA " + "PRIVATE KEY-----";
      const fakePemBody = "MIIEpAIBAAKCAQEA7589fakePrivateMaterialXYZ998877";
      const fakePsk = "SuperSecretFactoryWiFi98765!";

      const payloadParts = [
        "strcpy\0",
        "vsprintf\0",
        "gets\0",
        'scanf("%s", user_buf);\0',
        'popen(cmd_line, "r");\0',
        `wpa_psk=${fakePsk}\0`,
        `auth_jwt=${fakeJwt}\0`,
        `${fakePemHeader}\n${fakePemBody}\n-----END RSA PRIVATE KEY-----\0`,
      ];
      const payloadBuf = Buffer.from(payloadParts.join(""), "ascii");

      const elf32 = buildSyntheticElf32({
        elfType: 2, // ET_EXEC (non-PIE)
        machine: 0x28, // ARM
        gnuStackFlags: 0x7, // RWX!
        loadVaddr: 0x00010000,
        payload: payloadBuf,
      });

      const report = analyzeFirmwareBuffer(elf32, "camera_daemon.elf");
      expect(report.detectedFormat).toBe("elf");
      expect(report.elf).toMatchObject({
        bitness: 32,
        endianness: "little",
        elfType: "ET_EXEC",
        architecture: "ARM",
        pieEnabled: false,
        nxEnabled: false,
        gnuStackPresent: true,
        gnuStackFlags: "RWX",
      });

      const ruleIds = report.findings.map((f) => f.ruleId);
      expect(ruleIds).toContain("FW-ELF-EXEC-STACK");
      expect(ruleIds).toContain("FW-ELF-NO-PIE");
      expect(ruleIds).toContain("FW-SINK-STRCPY-SPRINTF");
      expect(ruleIds).toContain("FW-SINK-GETS-SCANF");
      expect(ruleIds).toContain("FW-SINK-CMD-EXEC");
      expect(ruleIds).toContain("FW-EMBEDDED-PSK");
      expect(ruleIds).toContain("FW-HARDCODED-SECRET");
      expect(ruleIds).toContain("FW-PRIVATE-KEY");

      // Virtual address attribution: first string "strcpy" starts right at loadVaddr 0x00010000!
      const strcpyFinding = report.findings.find(
        (f) => f.ruleId === "FW-SINK-STRCPY-SPRINTF",
      );
      expect(strcpyFinding?.address).toBe("0x00010000");

      // CRITICAL REDACTION CHECK: raw secret values MUST NOT appear anywhere in evidence!
      const serialized = JSON.stringify(report.findings);
      expect(serialized).not.toContain(fakePsk);
      expect(serialized).not.toContain(fakePemBody);
      expect(serialized).not.toContain(fakeJwt);
      expect(serialized).toContain("[redacted]");
    });

    it("parses hardened ELF64 RISC-V PIE (ET_DYN, GNU_STACK RW-) with zero false-positive ELF hardening findings", () => {
      const elf64 = buildSyntheticElf64({
        elfType: 3, // ET_DYN (PIE)
        machine: 0xf3, // RISC-V
        gnuStackFlags: 0x6, // RW- (NX enabled!)
        loadVaddr: 0x00400000n,
        payload: Buffer.from("snprintf(buf, sizeof(buf), \"%u\", val);\0", "ascii"),
      });

      const parsed = parseElfMetadata(elf64);
      expect(parsed).not.toBeNull();
      expect(parsed?.metadata).toMatchObject({
        bitness: 64,
        endianness: "little",
        elfType: "ET_DYN",
        architecture: "RISC-V",
        pieEnabled: true,
        nxEnabled: true,
        gnuStackFlags: "RW-",
      });
      expect(parsed?.findings).toEqual([]);
    });

    it("detects big-endian MIPS ELF32, AArch64 ELF64, x86 ELF32, and RWX PT_LOAD segments", () => {
      const mipsBe = buildSyntheticElf32({
        elfType: 2,
        machine: 0x08, // MIPS
        bigEndian: true,
        gnuStackFlags: 0x6,
        loadVaddr: 0x00400000,
        payload: Buffer.from("sprintf(out, fmt);\0", "ascii"),
      });
      // Flip PH0 p_flags (+24 from ph0=52 -> offset 76) to RWX (0x7) big-endian
      mipsBe.writeUInt32BE(0x7, 52 + 24);

      const mipsReport = analyzeFirmwareBuffer(mipsBe, "router_mips.elf");
      expect(mipsReport.elf?.architecture).toBe("MIPS");
      expect(mipsReport.elf?.endianness).toBe("big");
      expect(
        mipsReport.findings.some((f) => f.ruleId === "FW-ELF-RWX-SEGMENT"),
      ).toBe(true);
      expect(
        mipsReport.findings.some((f) => f.ruleId === "FW-SINK-STRCPY-SPRINTF"),
      ).toBe(true);

      const aarch64Elf = buildSyntheticElf64({
        elfType: 3,
        machine: 0xb7, // AArch64
        gnuStackFlags: 0x7, // RWX stack
        loadVaddr: 0x00401000n,
        payload: Buffer.from("system(user_cmd);\0", "ascii"),
      });
      const aarch64Report = analyzeFirmwareBuffer(aarch64Elf, "gateway_arm64.elf");
      expect(aarch64Report.elf?.architecture).toBe("AArch64");
      expect(aarch64Report.elf?.nxEnabled).toBe(false);
      expect(
        aarch64Report.findings.some((f) => f.cwe.includes("CWE-78")),
      ).toBe(true);

      const x86Elf = buildSyntheticElf32({
        elfType: 3,
        machine: 0x03, // x86
        gnuStackFlags: 0x6,
        loadVaddr: 0x08048000,
        payload: Buffer.from("SAFE_ONLY\0", "ascii"),
      });
      expect(parseElfMetadata(x86Elf)?.metadata.architecture).toBe("x86");
    });
  });

  describe("U-Boot Containers, Environment & Device-Tree (.dts / .dtsi) Analysis", () => {
    it("detects legacy uImage (0x27051956), unsigned FIT (0xd00dfeed), bootdelay, and bootcmd tftpboot injection", () => {
      const uimage = Buffer.alloc(128, 0);
      uimage.writeUInt32BE(0x27051956, 0); // ih_magic
      uimage.writeUInt32BE(0x00200000, 12); // ih_size
      uimage.writeUInt32BE(0x80008000, 16); // ih_load
      uimage.writeUInt32BE(0x80008040, 20); // ih_ep
      uimage[30] = 2; // IH_TYPE_KERNEL
      uimage.write("Linux-5.15-Router", 32, "ascii");

      const fit = Buffer.alloc(128, 0);
      fit.writeUInt32BE(0xd00dfeed, 0); // FDT magic
      fit.writeUInt32BE(120, 4); // totalsize
      fit.writeUInt32BE(48, 8); // off_dt_struct
      fit.writeUInt32BE(17, 20); // version
      fit.write("images\0configurations\0kernel@1\0", 48, "ascii");

      const envBlob = Buffer.from(
        [
          "bootdelay=3",
          "serverip=192.168.1.100",
          "bootcmd=tftpboot 0x82000000 uImage; bootm 0x82000000",
          "",
        ].join("\0"),
        "ascii",
      );

      const combined = Buffer.concat([uimage, fit, envBlob]);
      const report = analyzeFirmwareBuffer(combined, "flash_dump.bin");

      expect(report.ubootContainers).toHaveLength(2);
      expect(report.ubootContainers[0]).toMatchObject({
        kind: "uimage",
        imageName: "Linux-5.15-Router",
        loadAddress: "0x80008000",
        entryPoint: "0x80008040",
      });
      expect(report.ubootContainers[1]).toMatchObject({
        kind: "fdt_or_fit",
      });

      const ruleIds = report.findings.map((f) => f.ruleId);
      expect(ruleIds).toContain("FW-UBOOT-LEGACY-UIMAGE");
      expect(ruleIds).toContain("FW-UBOOT-UNSIGNED-FIT");
      expect(ruleIds).toContain("FW-UBOOT-CONSOLE-EXPOSED");
      expect(ruleIds).toContain("FW-UBOOT-BOOTCMD-INJECT");

      const cmdInject = report.findings.find(
        (f) => f.ruleId === "FW-UBOOT-BOOTCMD-INJECT",
      );
      expect(cmdInject?.severity).toBe("critical");
      expect(cmdInject?.cwe).toEqual(expect.arrayContaining(["CWE-78", "CWE-353"]));
      expect(cmdInject?.reapPlaybookId).toBe("reap-07-firmware-and-embedded");
    });

    it("analyzes .dts Device-Tree files for insecure kernel bootargs, writable boot partitions, and U-Boot bootcmd", () => {
      const dtsSource = [
        "/dts-v1/;",
        "/ {",
        "  chosen {",
        '    bootargs = "console=ttyS0,115200 root=/dev/mtdblock2 rw init=/bin/sh nokaslr iommu=off strict-devmem=0";',
        "  };",
        "  config {",
        '    u-boot,bootcmd = "dhcp; tftpboot 0x81000000 fit.itb && bootm";',
        "    bootdelay = <5>;",
        "  };",
        "  partitions {",
        '    compatible = "fixed-partitions";',
        "    partition@0 {",
        '      label = "u-boot-env";',
        "      reg = <0x00040000 0x00010000>;",
        "    };",
        "    partition@50000 {",
        '      label = "bootloader";',
        "      reg = <0x00050000 0x00080000>;",
        "      read-only;",
        "    };",
        "  };",
        "};",
      ].join("\n");

      const report = analyzeFirmwareBuffer(
        Buffer.from(dtsSource, "utf8"),
        "soc-gateway.dts",
      );
      expect(report.detectedFormat).toBe("dts");

      const bootargsFinding = report.findings.find(
        (f) => f.ruleId === "FW-DTS-INSECURE-BOOTARGS",
      );
      expect(bootargsFinding).toBeDefined();
      expect(bootargsFinding?.severity).toBe("critical");
      expect(bootargsFinding?.cwe).toContain("CWE-1244");
      expect(bootargsFinding?.reapPlaybookId).toBe(
        "reap-19-kernel-and-driver-exploitation-research",
      );

      const partFindings = report.findings.filter(
        (f) => f.ruleId === "FW-DTS-WRITABLE-BOOT-PARTITION",
      );
      // Only partition@0 ("u-boot-env") lacks read-only; partition@50000 has read-only;
      expect(partFindings).toHaveLength(1);
      expect(partFindings[0]?.evidence).toContain("u-boot-env");
    });
  });

  describe("KiCad Hardware EDA (.kicad_sch & .kicad_pcb) Debug & Attack-Surface Scanner", () => {
    it("identifies JTAG (DNP header), SWD test-points, UART, SPI_FLASH SOIC-8, BOOT0, and I2C EEPROM in .kicad_sch while ignoring lib_symbols", () => {
      const kicadSch = `
(kicad_sch (version 20231120) (generator "eeschema")
  (lib_symbols
    (symbol "Connector_Generic:Conn_01x05"
      (property "Reference" "J" (at 0 0 0))
      (property "Value" "JTAG_TEMPLATE_ONLY" (at 0 0 0))
    )
  )
  (symbol (lib_id "Connector_Generic:Conn_01x05") (at 100 50 0)
    (dnp yes)
    (property "Reference" "J1" (at 100 45 0))
    (property "Value" "JTAG_DEBUG_HDR" (at 100 55 0))
    (property "Description" "Unpopulated JTAG pogo header" (at 0 0 0))
  )
  (symbol (lib_id "Connector:TestPoint") (at 120 60 0)
    (property "Reference" "TP1" (at 120 58 0))
    (property "Value" "SWDIO" (at 120 62 0))
  )
  (symbol (lib_id "Connector:TestPoint") (at 125 60 0)
    (property "Reference" "TP2" (at 125 58 0))
    (property "Value" "SWCLK" (at 125 62 0))
  )
  (symbol (lib_id "Connector_Generic:Conn_01x03") (at 140 70 0)
    (property "Reference" "P1" (at 140 68 0))
    (property "Value" "UART_CONSOLE" (at 140 72 0))
  )
  (symbol (lib_id "Memory_Flash:W25Q128JVS") (at 160 80 0)
    (property "Reference" "U3" (at 160 78 0))
    (property "Value" "W25Q128JV_SPI_FLASH" (at 160 82 0))
    (property "Footprint" "Package_SO:SOIC-8_5.23x5.23mm_P1.27mm" (at 0 0 0))
  )
  (symbol (lib_id "Jumper:SolderJumper_2_Open") (at 180 90 0)
    (property "Reference" "JP1" (at 180 88 0))
    (property "Value" "BOOT0" (at 180 92 0))
  )
  (symbol (lib_id "Memory_EEPROM:AT24C256") (at 200 100 0)
    (property "Reference" "U4" (at 200 98 0))
    (property "Value" "AT24C256" (at 200 102 0))
  )
  (label "JTAG_TDI" (at 95 50 0))
  (label "JTAG_TDO" (at 95 52 0))
  (label "JTAG_TMS" (at 95 54 0))
  (label "JTAG_TCK" (at 95 56 0))
  (label "SWDIO" (at 118 60 0))
  (label "SWCLK" (at 123 60 0))
  (global_label "UART0_TXD" (shape output) (at 138 70 0))
  (global_label "UART0_RXD" (shape input) (at 138 72 0))
  (label "SPI_FLASH_CS" (at 158 80 0))
  (label "BOOT0" (at 178 90 0))
  (label "I2C1_SDA" (at 198 100 0))
  (label "I2C1_SCL" (at 198 102 0))
)`;

      const res = scanKicadEda(kicadSch, "kicad_sch");
      const byType = Object.fromEntries(res.hits.map((h) => [h.interfaceType, h]));

      expect(byType.JTAG).toBeDefined();
      expect(byType.JTAG.designators).toEqual(["J1"]);
      expect(byType.JTAG.unpopulated).toBe(true);
      expect(byType.JTAG.nets).toEqual(
        expect.arrayContaining(["JTAG_TCK", "JTAG_TDI", "JTAG_TDO", "JTAG_TMS"]),
      );

      expect(byType.SWD).toBeDefined();
      expect(byType.SWD.designators).toEqual(["TP1", "TP2"]);
      expect(byType.SWD.testPointExposed).toBe(true);
      expect(byType.SWD.nets).toEqual(expect.arrayContaining(["SWCLK", "SWDIO"]));

      expect(byType.UART).toBeDefined();
      expect(byType.UART.designators).toContain("P1");
      expect(byType.UART.nets).toEqual(
        expect.arrayContaining(["UART0_RXD", "UART0_TXD"]),
      );

      expect(byType.SPI_FLASH).toBeDefined();
      expect(byType.SPI_FLASH.designators).toContain("U3");

      expect(byType.BOOT_PIN).toBeDefined();
      expect(byType.BOOT_PIN.designators).toContain("JP1");

      expect(byType.I2C_EEPROM).toBeDefined();
      expect(byType.I2C_EEPROM.designators).toContain("U4");
      expect(byType.I2C_EEPROM.nets).toEqual(
        expect.arrayContaining(["I2C1_SCL", "I2C1_SDA"]),
      );

      for (const f of res.findings) {
        expect(f.cwe).toContain("CWE-1244");
        expect(f.reapPlaybookId).toBe(
          "reap-13-dma-and-hardware-assisted-cheat-research-defensive",
        );
      }
    });

    it("parses .kicad_pcb footprints, pad net bindings, and DNP attributes", () => {
      const kicadPcb = `
(kicad_pcb (version 20231014) (generator "pcbnew")
  (net 1 "/JTAG_TMS")
  (net 2 "/JTAG_TCK")
  (net 3 "/UART_TXD")
  (net 4 "/UART_RXD")
  (net 5 "/BOOT_SEL")
  (footprint "Connector_PinHeader_1.27mm:PinHeader_1x04"
    (layer "F.Cu")
    (attr through_hole dnp)
    (fp_text reference "J4" (at 0 0))
    (fp_text value "DNP_HDR" (at 0 2))
    (pad "1" thru_hole rect (at 0 0) (size 1 1) (net 1 "/JTAG_TMS"))
    (pad "2" thru_hole oval (at 0 1.27) (size 1 1) (net 2 "/JTAG_TCK"))
  )
  (footprint "TestPoint:TestPoint_Pad_D1.5mm"
    (layer "B.Cu")
    (property "Reference" "TP7")
    (property "Value" "TestPoint")
    (pad "1" smd circle (at 5 5) (size 1.5 1.5) (net 3 "/UART_TXD"))
  )
  (footprint "TestPoint:TestPoint_Pad_D1.5mm"
    (layer "B.Cu")
    (property "Reference" "TP8")
    (property "Value" "TestPoint")
    (pad "1" smd circle (at 7 5) (size 1.5 1.5) (net 5 "/BOOT_SEL"))
  )
)`;

      const report = analyzeFirmwareBuffer(
        Buffer.from(kicadPcb, "utf8"),
        "router_mainboard.kicad_pcb",
      );
      expect(report.detectedFormat).toBe("kicad_pcb");
      expect(report.kicadHits).toHaveLength(3);

      const jtagFinding = report.findings.find(
        (f) => f.ruleId === "FW-EDA-JTAG-EXPOSED",
      );
      expect(jtagFinding?.severity).toBe("critical");
      expect(jtagFinding?.designators).toEqual(["J4"]);
      expect(jtagFinding?.nets).toEqual(["/JTAG_TCK", "/JTAG_TMS"]);
      expect(jtagFinding?.unpopulatedOrTestPoint).toBe(true);

      const uartFinding = report.findings.find(
        (f) => f.ruleId === "FW-EDA-UART-EXPOSED",
      );
      expect(uartFinding?.designators).toEqual(["TP7"]);
      expect(uartFinding?.nets).toEqual(["/UART_TXD"]);

      const bootFinding = report.findings.find(
        (f) => f.ruleId === "FW-EDA-BOOT-PIN-EXPOSED",
      );
      expect(bootFinding?.designators).toEqual(["TP8"]);
      expect(bootFinding?.nets).toEqual(["/BOOT_SEL"]);
    });
  });

  describe("Containment, Symlink Escape Rejection, Arsenal Wiring & Mission Routing", () => {
    it("enforces T3MP3ST_SOURCE_ROOT containment, rejects traversal/sibling/symlink escapes & oversized blobs, and isolates target metadata", async () => {
      const parentDir = mkdtempSync(join(tmpdir(), "t3mp3st-fw-sec-"));
      const rootDir = join(parentDir, "approved_root");
      const siblingDir = join(parentDir, "approved_root_escape");
      mkdirSync(rootDir, { recursive: true });
      mkdirSync(siblingDir, { recursive: true });

      try {
        const validHex = [
          makeIntelHexRecord(0x0000, 0x04, Buffer.from([0x08, 0x00])),
          makeIntelHexRecord(
            0x0000,
            0x00,
            Buffer.from('gets(uart_rx_buf);\0', "ascii"),
          ),
          makeIntelHexRecord(0x0000, 0x01, Buffer.alloc(0)),
        ].join("\n");
        writeFileSync(join(rootDir, "mcu.hex"), validHex, "utf8");
        writeFileSync(
          join(siblingDir, "outside.hex"),
          validHex,
          "utf8",
        );
        writeFileSync(
          join(rootDir, "oversized.bin"),
          Buffer.alloc(2048, 0x41),
        );

        // 1. Fails closed when T3MP3ST_SOURCE_ROOT is unset
        delete process.env.T3MP3ST_SOURCE_ROOT;
        const noRootRes = await firmwareAuditScanTool.handler(
          createToolContext(undefined, { path: "mcu.hex" }),
        );
        expect(noRootRes.success).toBe(false);
        expect(noRootRes.error).toContain("T3MP3ST_SOURCE_ROOT");

        process.env.T3MP3ST_SOURCE_ROOT = rootDir;

        // 2. Rejects .. path traversal & sibling prefix boundary escape
        const traversalRes = await firmwareAuditScanTool.handler(
          createToolContext(undefined, {
            path: "../approved_root_escape/outside.hex",
          }),
        );
        expect(traversalRes.success).toBe(false);
        expect(traversalRes.error).toContain("outside T3MP3ST_SOURCE_ROOT");

        const absOutsideRes = await firmwareAuditScanTool.handler(
          createToolContext(undefined, {
            path: join(siblingDir, "outside.hex"),
          }),
        );
        expect(absOutsideRes.success).toBe(false);
        expect(absOutsideRes.error).toContain("outside T3MP3ST_SOURCE_ROOT");

        // 3. Rejects oversized firmware blob when exceeding max_bytes
        const oversizeRes = await firmwareAuditScanTool.handler(
          createToolContext(undefined, {
            path: "oversized.bin",
            max_bytes: 512,
          }),
        );
        expect(oversizeRes.success).toBe(false);
        expect(oversizeRes.error).toContain("exceeds 512 bytes");

        // 4. Symlink escape & broken symlink rejection (when OS permits symlinks)
        const escapeLink = join(rootDir, "escape_link.hex");
        const brokenLink = join(rootDir, "broken_link.hex");
        let symlinksCreated = false;
        try {
          symlinkSync(join(siblingDir, "outside.hex"), escapeLink, "file");
          symlinkSync(join(rootDir, "nonexistent.hex"), brokenLink, "file");
          symlinksCreated = true;
        } catch (err: unknown) {
          const code =
            err && typeof err === "object" && "code" in err
              ? String(err.code)
              : "";
          if (code !== "EPERM" && code !== "EACCES") throw err;
        }

        if (symlinksCreated) {
          const symEscapeRes = await firmwareAuditScanTool.handler(
            createToolContext(undefined, { path: "escape_link.hex" }),
          );
          expect(symEscapeRes.success).toBe(false);
          expect(symEscapeRes.error).toContain("outside T3MP3ST_SOURCE_ROOT");

          const brokenRes = await firmwareAuditScanTool.handler(
            createToolContext(undefined, { path: "broken_link.hex" }),
          );
          expect(brokenRes.success).toBe(false);
          expect(brokenRes.error).toContain("cannot be resolved");
        }

        // 5. Directory scan inside root succeeds on mcu.hex while skipping escaping symlink & oversize
        const dirRes = await firmwareAuditScanTool.handler(
          createToolContext(undefined, { path: ".", max_bytes: 1024 }),
        );
        expect(dirRes.success).toBe(true);
        expect(dirRes.output).toContain("mcu.hex");
        expect(dirRes.findings?.some((f) => f.cwe?.includes("CWE-120"))).toBe(
          true,
        );
        if (symlinksCreated) {
          expect(dirRes.output).toContain("escapes T3MP3ST_SOURCE_ROOT");
        }

        // 6. Isolated target.metadata.sourceRoot works without env mutation
        delete process.env.T3MP3ST_SOURCE_ROOT;
        const scopedTarget = {
          id: "t-fw-1",
          name: "mcu.hex",
          type: "iot" as const,
          zone: "internal" as const,
          status: "discovered" as const,
          address: "mcu.hex",
          metadata: { sourceRoot: rootDir },
          discoveredAt: Date.now(),
        };
        const arsenal = new Arsenal();
        arsenal.registerMany(BUILTIN_TOOLS);
        const execRes = await arsenal.execute(
          "firmware_audit_scan",
          createToolContext(scopedTarget, { path: "mcu.hex" }),
        );
        expect(execRes.success).toBe(true);
        expect(execRes.findings?.[0]?.provenance).toBe("tool");
        expect(execRes.findings?.[0]?.details).toContain(
          "reap-10-vulnerability-research",
        );
        expect(process.env.T3MP3ST_SOURCE_ROOT).toBeUndefined();
      } finally {
        rmSync(parentDir, { recursive: true, force: true });
      }
    });

    it("wires firmware_audit_scan into BUILTIN_TOOLS, operator toolkits, REAP playbooks, and TypeSafe/OpGeneral mission routing", async () => {
      expect(BUILTIN_TOOLS.some((t) => t.name === "firmware_audit_scan")).toBe(
        true,
      );
      expect(ARCHETYPE_PROFILES.scanner.defaultTools).toContain(
        "firmware_audit_scan",
      );
      expect(ARCHETYPE_PROFILES.analyst.defaultTools).toContain(
        "firmware_audit_scan",
      );
      expect(ARCHETYPE_PROFILES.coordinator.defaultTools).toContain(
        "firmware_audit_scan",
      );

      // Every cross-linked REAP playbook skill ID resolves to a registered playbook
      for (const skill of [
        "reap-07-firmware-and-embedded",
        "reap-10-vulnerability-research",
        "reap-13-dma-and-hardware-assisted-cheat-research-defensive",
        "reap-19-kernel-and-driver-exploitation-research",
      ]) {
        expect(getReapPlaybookById(skill)).toBeDefined();
      }

      // TypeSafe router routes KiCad EDA & Intel HEX / U-Boot directives to reverse_binary with firmware_audit_scan
      const edaState = buildMissionRoutingState({
        directive: {
          objective:
            "Audit KiCad schematic and PCB layout (.kicad_sch, .kicad_pcb) for exposed JTAG, SWD, UART, and SPI flash debug interfaces",
        },
        targets: [
          { address: "board.kicad_sch", expectedType: "hardware" },
          { address: "bootloader.hex", expectedType: "firmware" },
        ],
      });
      expect(edaState.targets[0]?.inferredKind).toBe("binary");
      expect(edaState.targets[1]?.inferredKind).toBe("binary");

      const decision = evaluateMissionRouteOffline({
        directive: {
          objective:
            "Audit KiCad schematic and PCB layout (.kicad_sch, .kicad_pcb) and Intel HEX U-Boot firmware for exposed JTAG, SWD, and bootcmd injection",
        },
        targets: [
          { address: "board.kicad_sch", expectedType: "hardware" },
          { address: "bootloader.hex", expectedType: "firmware" },
        ],
      });
      expect(decision.primaryFamily).toBe("reverse_binary");
      expect(
        decision.judgments.familyProbabilities.reverse_binary,
      ).toBeGreaterThanOrEqual(YES_THRESHOLD);
      expect(recommendToolsForMissionRoute(decision, edaState)[0]).toBe(
        "firmware_audit_scan",
      );

      // OpGeneral end-to-end toolPlan includes firmware_audit_scan on firmware/EDA missions
      const mockLlm = {
        prompt: async () =>
          JSON.stringify({
            codename: "OP SILICON PROBE",
            summary: "Firmware & KiCad EDA debug surface audit",
            targets: [
              { address: "gateway.srec", expectedType: "iot", priority: 1 },
            ],
            objectives: ["Audit S-Record image and JTAG/SWD attack surface"],
            operators: ["scanner", "analyst"],
          }),
      } as unknown as LLMBackbone;

      const general = new OpGeneral(mockLlm);
      const plan = await general.planOperation({
        objective:
          "Scan gateway.srec Motorola S-Record firmware and gateway.kicad_pcb for corrupted checksums, U-Boot tftpboot vectors, and JTAG/SWD debug pads",
      });
      expect(plan.missionFamily).toBe("reverse_binary");
      expect(plan.toolPlan[0]?.primaryTools).toContain("firmware_audit_scan");
    });
  });
});
