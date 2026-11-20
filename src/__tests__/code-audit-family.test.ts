import { describe, it, expect, afterEach } from "vitest";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  codeAuditScanTool,
  isWithinCanonicalRoot,
  scanSourceText,
} from "../arsenal/code-audit.js";
import { createToolContext } from "../arsenal/index.js";
import { adaptersForFamily } from "../arsenal/catalog.js";
import { ARCHETYPE_PROFILES } from "../operators/index.js";
import {
  promptPacksForFamily,
  runbookForFamily,
  WORKFLOW_PRESETS,
} from "../resources/index.js";
import { OpGeneral } from "../general/index.js";
import type { LLMBackbone } from "../llm/index.js";

describe("code_audit mission family & code_audit_scan tooling", () => {
  const prevSourceRoot = process.env.T3MP3ST_SOURCE_ROOT;

  afterEach(() => {
    if (prevSourceRoot === undefined) {
      delete process.env.T3MP3ST_SOURCE_ROOT;
    } else {
      process.env.T3MP3ST_SOURCE_ROOT = prevSourceRoot;
    }
  });

  it("registers code_audit runbook, workflow preset, prompt pack, and adapters", () => {
    const runbook = runbookForFamily("code_audit");
    expect(runbook).toBeDefined();
    expect(runbook?.phases.length).toBeGreaterThanOrEqual(3);

    const packs = promptPacksForFamily("code_audit");
    expect(packs.map((p) => p.id)).toContain("prompt-code-audit-cartographer");

    expect(WORKFLOW_PRESETS.some((w) => w.family === "code_audit")).toBe(true);
    expect(adaptersForFamily("code_audit").map((a) => a.id)).toEqual(
      expect.arrayContaining(["semgrep", "gitleaks", "file"]),
    );
  });

  it("exposes code_audit_scan on scanner and analyst operator toolkits", () => {
    expect(ARCHETYPE_PROFILES.scanner.defaultTools).toContain(
      "code_audit_scan",
    );
    expect(ARCHETYPE_PROFILES.analyst.defaultTools).toContain(
      "code_audit_scan",
    );
  });

  it("routes local source-audit directives to code_audit in OpGeneral with tooling", async () => {
    const mockLlm = {
      prompt: async () =>
        JSON.stringify({
          codename: "OP IRON LENS",
          summary: "Local source-code sink and guard audit",
          targets: [
            { address: "source.java", expectedType: "host", priority: 1 },
          ],
          objectives: ["Trace untrusted inputs to CWE sinks"],
          operators: ["scanner", "analyst"],
        }),
    } as unknown as LLMBackbone;

    const general = new OpGeneral(mockLlm);
    const plan = await general.planOperation({
      objective:
        "Perform a local source file audit on source.java and report CWE-502 sink line findings",
      scopeHints: "code_audit local source-only",
    });

    expect(plan.missionFamily).toBe("code_audit");
    expect(plan.huntLanes[0]?.family).toBe("code_audit");
    expect(plan.toolPlan[0]?.primaryTools).toContain("code_audit_scan");
  });

  it("identifies sinks on real cve-hunt samples and suppresses hardened decoys", async () => {
    const samplesDir = join(process.cwd(), "bench", "cve-hunt", "samples");
    process.env.T3MP3ST_SOURCE_ROOT = samplesDir;

    const decoyC = await codeAuditScanTool.handler(
      createToolContext(undefined, { path: "DECOY-clean-c/source.c" }),
    );
    expect(decoyC.success).toBe(true);
    expect(decoyC.findings).toBeUndefined();

    const decoyJava = await codeAuditScanTool.handler(
      createToolContext(undefined, { path: "DECOY-clean-java/source.java" }),
    );
    expect(decoyJava.success).toBe(true);
    expect(decoyJava.findings).toBeUndefined();

    const log4j = await codeAuditScanTool.handler(
      createToolContext(undefined, { path: "CVE-2021-44228/source.java" }),
    );
    expect(log4j.success).toBe(true);
    expect(log4j.findings?.some((f) => f.cwe?.includes("CWE-917"))).toBe(true);
  });

  it("enforces T3MP3ST_SOURCE_ROOT containment and distinguishes unguarded vs guarded sinks", async () => {
    const rootDir = mkdtempSync(join(tmpdir(), "t3mp3st-ca-"));
    const outsideDir = mkdtempSync(join(tmpdir(), "t3mp3st-out-"));
    try {
      const vulnFile = join(rootDir, "vuln.java");
      writeFileSync(
        vulnFile,
        [
          "public class Handler {",
          "  public Object parse(String xml) {",
          "    XStream xs = new XStream();",
          "    return xs.fromXML(xml);",
          "  }",
          "}",
        ].join("\n"),
        "utf8",
      );

      const hardenedFile = join(rootDir, "clean.java");
      writeFileSync(
        hardenedFile,
        [
          "public class SafeHandler {",
          "  public Object parse(String xml) {",
          "    XStream xs = new XStream();",
          "    XStream.setupDefaultSecurity(xs);",
          '    xs.allowTypesByWildcard(new String[] { "com.safe.**" });',
          "    return xs.fromXML(xml);",
          "  }",
          "}",
        ].join("\n"),
        "utf8",
      );

      const outsideFile = join(outsideDir, "secret.c");
      writeFileSync(outsideFile, "int main() { return 0; }\n", "utf8");

      process.env.T3MP3ST_SOURCE_ROOT = rootDir;

      const blocked = await codeAuditScanTool.handler(
        createToolContext(undefined, { path: outsideFile }),
      );
      expect(blocked.success).toBe(false);
      expect(blocked.error).toContain("outside T3MP3ST_SOURCE_ROOT");

      const vulnRes = await codeAuditScanTool.handler(
        createToolContext(undefined, { path: "vuln.java" }),
      );
      expect(vulnRes.success).toBe(true);
      expect(vulnRes.findings?.length).toBe(1);
      expect(vulnRes.findings?.[0]?.cwe).toContain("CWE-502");
      expect(vulnRes.output).toContain("line 4");

      const cleanHits = scanSourceText(
        [
          "XStream xs = new XStream();",
          "XStream.setupDefaultSecurity(xs);",
          'xs.allowTypesByWildcard(new String[] { "com.safe.**" });',
          "return xs.fromXML(xml);",
        ].join("\n"),
      );
      expect(cleanHits.length).toBe(1);
      expect(cleanHits[0]?.guarded).toBe(true);

      const cleanRes = await codeAuditScanTool.handler(
        createToolContext(undefined, { path: "clean.java" }),
      );
      expect(cleanRes.success).toBe(true);
      expect(cleanRes.findings).toBeUndefined();
      expect(cleanRes.output).toContain("Guarded / mitigated sinks");
    } finally {
      rmSync(rootDir, { recursive: true, force: true });
      rmSync(outsideDir, { recursive: true, force: true });
    }
  });

  it("returns structured errors without throwing on missing or broken paths", async () => {
    const rootDir = mkdtempSync(join(tmpdir(), "t3mp3st-ca-err-"));
    try {
      process.env.T3MP3ST_SOURCE_ROOT = rootDir;

      const missingFile = await codeAuditScanTool.handler(
        createToolContext(undefined, { path: "does-not-exist.java" }),
      );
      expect(missingFile.success).toBe(false);
      expect(missingFile.error).toContain("cannot be resolved");

      process.env.T3MP3ST_SOURCE_ROOT = join(rootDir, "nonexistent-root");
      const missingRoot = await codeAuditScanTool.handler(
        createToolContext(undefined, { path: "." }),
      );
      expect(missingRoot.success).toBe(false);
      expect(missingRoot.error).toContain("cannot be resolved");
    } finally {
      rmSync(rootDir, { recursive: true, force: true });
    }
  });

  it("blocks sibling prefix-boundary escapes and symlink escapes in file and directory modes", async () => {
    const parentDir = mkdtempSync(join(tmpdir(), "t3mp3st-ca-prefix-"));
    const rootDir = join(parentDir, "root");
    const siblingDir = join(parentDir, "root2");
    mkdirSync(rootDir, { recursive: true });
    mkdirSync(siblingDir, { recursive: true });

    try {
      const safeFile = join(rootDir, "safe.c");
      writeFileSync(safeFile, "int main(void) { return 0; }\n", "utf8");

      const siblingSecret = join(siblingDir, "secret.java");
      writeFileSync(
        siblingSecret,
        "public class Leak { Object f(String x) { return xs.fromXML(x); } }\n",
        "utf8",
      );

      // Prefix-boundary unit check (root vs root2)
      expect(isWithinCanonicalRoot(rootDir, rootDir)).toBe(true);
      expect(isWithinCanonicalRoot(rootDir, safeFile)).toBe(true);
      expect(isWithinCanonicalRoot(rootDir, siblingDir)).toBe(false);
      expect(isWithinCanonicalRoot(rootDir, siblingSecret)).toBe(false);

      process.env.T3MP3ST_SOURCE_ROOT = rootDir;

      const siblingBlocked = await codeAuditScanTool.handler(
        createToolContext(undefined, { path: siblingSecret }),
      );
      expect(siblingBlocked.success).toBe(false);
      expect(siblingBlocked.error).toContain("outside T3MP3ST_SOURCE_ROOT");

      // Symlink escape & broken symlink checks (when OS permits symlink creation)
      const escapeLink = join(rootDir, "escape.java");
      const brokenLink = join(rootDir, "broken.java");
      let symlinksCreated = false;
      try {
        symlinkSync(siblingSecret, escapeLink, "file");
        symlinkSync(join(rootDir, "missing-target.java"), brokenLink, "file");
        symlinksCreated = true;
      } catch (err: unknown) {
        const code =
          err && typeof err === "object" && "code" in err
            ? String(err.code)
            : "";
        if (code !== "EPERM" && code !== "EACCES") {
          throw err;
        }
      }

      if (symlinksCreated) {
        const directEscape = await codeAuditScanTool.handler(
          createToolContext(undefined, { path: "escape.java" }),
        );
        expect(directEscape.success).toBe(false);
        expect(directEscape.error).toContain("outside T3MP3ST_SOURCE_ROOT");

        const directBroken = await codeAuditScanTool.handler(
          createToolContext(undefined, { path: "broken.java" }),
        );
        expect(directBroken.success).toBe(false);
        expect(directBroken.error).toContain("cannot be resolved");

        const dirScan = await codeAuditScanTool.handler(
          createToolContext(undefined, { path: "." }),
        );
        expect(dirScan.success).toBe(true);
        expect(dirScan.findings).toBeUndefined();
        expect(dirScan.output).toContain("safe.c");
        expect(dirScan.output).not.toContain("Leak");
        expect(dirScan.output).toContain("escapes T3MP3ST_SOURCE_ROOT");
        expect(dirScan.output).toContain("broken.java");
      }
    } finally {
      rmSync(parentDir, { recursive: true, force: true });
    }
  });

  it("isolates sourceRoot via target metadata without mutating process.env.T3MP3ST_SOURCE_ROOT", async () => {
    const rootDir = mkdtempSync(join(tmpdir(), "t3mp3st-ca-iso-"));
    try {
      delete process.env.T3MP3ST_SOURCE_ROOT;
      writeFileSync(
        join(rootDir, "vuln.java"),
        "public class A { Object f(String x) { return xs.fromXML(x); } }\n",
        "utf8",
      );

      const scopedTarget = {
        id: "t-code-audit",
        name: "vuln.java",
        type: "host" as const,
        zone: "internal" as const,
        status: "discovered" as const,
        address: "vuln.java",
        protocol: "file",
        metadata: { sourceRoot: rootDir },
        discoveredAt: Date.now(),
      };

      const scopedRes = await codeAuditScanTool.handler(
        createToolContext(scopedTarget, { path: "vuln.java" }),
      );
      expect(scopedRes.success).toBe(true);
      expect(scopedRes.findings?.length).toBe(1);
      expect(process.env.T3MP3ST_SOURCE_ROOT).toBeUndefined();

      // A subsequent request without sourceRoot must NOT inherit the prior root.
      const unscopedRes = await codeAuditScanTool.handler(
        createToolContext(undefined, { path: "vuln.java" }),
      );
      expect(unscopedRes.success).toBe(false);
      expect(unscopedRes.error).toContain(
        "T3MP3ST_SOURCE_ROOT must name the approved analysis root",
      );

      // Verify server.ts never mutates process.env.T3MP3ST_SOURCE_ROOT globally
      const serverSrc = readFileSync(
        join(process.cwd(), "src", "server.ts"),
        "utf8",
      );
      expect(serverSrc).not.toMatch(/process\.env\.T3MP3ST_SOURCE_ROOT\s*=/);
      expect(serverSrc).toContain("sourceRoot: validSourceRoot ?? undefined");
    } finally {
      rmSync(rootDir, { recursive: true, force: true });
    }
  });
});
