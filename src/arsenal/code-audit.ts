/**
 * T3MP3ST code_audit_scan — local source-code sink, taint-cue, and guard scanner.
 *
 * Confined to T3MP3ST_SOURCE_ROOT via approvedLocalPath (no network egress, no
 * out-of-scope host reads). Inspects source files line-by-line across C/C++, Java,
 * Go, Python, JS/TS, Rust, Bash, and Perl, reporting:
 *   1. Numbered source slices (when start_line / end_line are requested, or around hits)
 *   2. General CWE sink & taint candidates with exact 1-based line numbers
 *   3. Nearby hardening-guard cues (bounds checks, allowlists, constant-time compare)
 *      so operators verify exploitability before filing to the findings ledger.
 */

import { readFileSync, readdirSync, statSync } from "fs";
import { basename, extname, join } from "path";
import type { CustomTool, Severity, ToolFinding } from "../types/index.js";
import { approvedLocalPath } from "./local-file-scope.js";

const MAX_FILE_BYTES = 2 * 1024 * 1024;
const SOURCE_EXTENSIONS = new Set([
  ".c",
  ".h",
  ".cc",
  ".cpp",
  ".hpp",
  ".java",
  ".kt",
  ".py",
  ".js",
  ".mjs",
  ".cjs",
  ".ts",
  ".tsx",
  ".go",
  ".rs",
  ".sh",
  ".bash",
  ".pl",
  ".pm",
  ".php",
  ".rb",
]);

export interface CodeAuditRule {
  id: string;
  cwe: string;
  severity: Severity;
  vulnClass: string;
  description: string;
  sinkRe: RegExp;
  guardRe?: RegExp;
}

export const CODE_AUDIT_RULES: readonly CodeAuditRule[] = [
  {
    id: "CA-CMD-EXEC",
    cwe: "CWE-78",
    severity: "critical",
    vulnClass: "command_injection",
    description:
      "Shell or OS command execution sink (eval / system / popen / Runtime.exec / qx)",
    sinkRe:
      /\b(eval\s+["'$]|system\s*\(|popen\s*\(|Runtime\.getRuntime\(\)\.exec\s*\(|ProcessBuilder\s*\(|child_process\.(exec|execSync)\s*\(|subprocess\.(Popen|run|call)\s*\([^)]*shell\s*=\s*True|qx\s*[{(/])/i,
  },
  {
    id: "CA-EXPR-LOOKUP",
    cwe: "CWE-917",
    severity: "critical",
    vulnClass: "expression_injection",
    description:
      "Dynamic expression, template, or lookup substitution on message/header data",
    sinkRe:
      /\b(substitutor\.replace|StrSubstitutor|LocalizedTextUtil\.findText|Ognl\.getValue|ValueStack|SpelExpressionParser|eval\s*\()/i,
    guardRe: /\b(noLookups\s*=\s*true|formatMsgNoLookups)\b/,
  },
  {
    id: "CA-UNSAFE-DESER",
    cwe: "CWE-502",
    severity: "critical",
    vulnClass: "insecure_deserialization",
    description:
      "Untrusted object deserialization sink (fromXML / readObject / pickle.loads / yaml.unsafe_load)",
    sinkRe:
      /\b(\.fromXML\s*\(|ObjectInputStream\b|\.readObject\s*\(|pickle\.loads?\s*\(|yaml\.unsafe_load\s*\(|unserialize\s*\()/i,
    guardRe:
      /\b(setupDefaultSecurity|allowTypes|allowTypesByWildcard|NoTypePermission\.NONE|SafeLoader)\b/,
  },
  {
    id: "CA-PROP-BINDING",
    cwe: "CWE-915",
    severity: "critical",
    vulnClass: "improper_property_binding",
    description:
      "Reflective nested bean/property path traversal without classLoader denylist",
    sinkRe:
      /\b(setNestedProperty|BeanWrapperImpl|PropertyUtils\.setProperty|getPropertyDescriptor)\b/,
    guardRe:
      /\b(classLoader|disallowedFields|allowedFields)\b.*\b(reject|throw|continue|return|deny)\b/i,
  },
  {
    id: "CA-MEM-BOUNDS",
    cwe: "CWE-125",
    severity: "high",
    vulnClass: "out_of_bounds_memory",
    description:
      "Raw memory copy or signed pointer-offset indexing without adjacent bounds guard",
    sinkRe:
      /\b(memcpy\s*\(|memmove\s*\(|strcpy\s*\(|sprintf\s*\()|\[\s*[a-zA-Z_]\w*offset\w*\s*\]\s*=/,
    guardRe:
      /\b(1\s*\+\s*2\s*\+\s*payload|(payload|declared\w*)\s*>\s*[\w.>-]*(len|length|size|rem)|offset\s*<\s*0)\b/i,
  },
  {
    id: "CA-PATH-TRAVERSAL",
    cwe: "CWE-22",
    severity: "critical",
    vulnClass: "path_traversal",
    description:
      "Filesystem open/write with unsanitized request parameter or relative path segments",
    sinkRe:
      /\b(open\s*\(\s*\w+\s*,\s*["']>[^"']*\$|writeFileSync\s*\([^)]*req\.|os\.Rename\s*\(|shutil\.move\s*\()/,
    guardRe:
      /\b(realpath|filepath\.Clean|basename|\.\.)\b.*\b(reject|return|throw|die)\b/i,
  },
  {
    id: "CA-WEAK-CRYPTO-IV",
    cwe: "CWE-330",
    severity: "critical",
    vulnClass: "weak_cryptography",
    description:
      "All-zero or static initialization vector in stream/CFB cipher mode",
    sinkRe:
      /\b(AES_cfb\d*_encrypt|Cipher\.getInstance\s*\(\s*["'][^"']*CFB|memset\s*\(\s*iv\s*,\s*0\b|iv\s*\[\s*\d*\s*\]\s*=\s*\{\s*0\s*\})/i,
  },
  {
    id: "CA-TIMING-COMPARE",
    cwe: "CWE-208",
    severity: "high",
    vulnClass: "timing_side_channel",
    description:
      "Byte-by-byte early-exit equality check on MAC, HMAC, or token signature",
    sinkRe:
      /if\s*\(?\s*\w+\s*\[\s*\w+\s*\]\s*!=\s*\w+\s*\[\s*\w+\s*\]\s*\)?\s*\{\s*return\s+false/,
    guardRe:
      /\b(timingSafeEqual|ConstantTimeCompare|compare_digest|constant_time_eq)\b/,
  },
  {
    id: "CA-DNS-TOCTOU",
    cwe: "CWE-918",
    severity: "high",
    vulnClass: "ssrf_or_toctou",
    description:
      "Separate pre-check resolution or file validation followed by unpinned dial/move (TOCTOU)",
    sinkRe:
      /\b(net\.LookupIP|socket\.getaddrinfo)\b[\s\S]{0,400}\b(http\.(DefaultClient|Get|Post)|requests\.(get|post))\b/,
    guardRe: /\bDialContext\b/,
  },
];

export interface SourceAuditHit {
  ruleId: string;
  cwe: string;
  severity: Severity;
  vulnClass: string;
  line: number;
  snippet: string;
  guarded: boolean;
  description: string;
}

export function scanSourceText(source: string): SourceAuditHit[] {
  const lines = source.split(/\r?\n/);
  const hits: SourceAuditHit[] = [];
  const fullGuardCheck = (rule: CodeAuditRule, lineIdx: number): boolean => {
    if (!rule.guardRe) return false;
    const winStart = Math.max(0, lineIdx - 16);
    const winEnd = Math.min(lines.length, lineIdx + 6);
    const windowText = lines.slice(winStart, winEnd).join("\n");
    return rule.guardRe.test(windowText);
  };

  for (const rule of CODE_AUDIT_RULES) {
    if (rule.id === "CA-DNS-TOCTOU") {
      const m = rule.sinkRe.exec(source);
      if (m && m.index !== undefined) {
        const line = source.slice(0, m.index).split(/\r?\n/).length;
        const guarded = rule.guardRe ? rule.guardRe.test(source) : false;
        hits.push({
          ruleId: rule.id,
          cwe: rule.cwe,
          severity: rule.severity,
          vulnClass: rule.vulnClass,
          line,
          snippet: (lines[line - 1] || "").trim().slice(0, 140),
          guarded,
          description: rule.description,
        });
      }
      continue;
    }

    for (let i = 0; i < lines.length; i++) {
      const rawLine = lines[i];
      const trimmed = rawLine.trim();
      if (
        !trimmed ||
        trimmed.startsWith("//") ||
        trimmed.startsWith("*") ||
        trimmed.startsWith("/*") ||
        (trimmed.startsWith("#") && !trimmed.startsWith("#!"))
      ) {
        continue;
      }
      if (rule.sinkRe.test(rawLine)) {
        hits.push({
          ruleId: rule.id,
          cwe: rule.cwe,
          severity: rule.severity,
          vulnClass: rule.vulnClass,
          line: i + 1,
          snippet: trimmed.slice(0, 140),
          guarded: fullGuardCheck(rule, i),
          description: rule.description,
        });
      }
    }
  }
  return hits;
}

function formatNumberedSlice(
  lines: string[],
  startLine: number,
  endLine: number,
): string {
  const lo = Math.max(1, startLine);
  const hi = Math.min(lines.length, endLine);
  const out: string[] = [];
  for (let ln = lo; ln <= hi; ln++) {
    out.push(`${String(ln).padStart(4, " ")}: ${lines[ln - 1]}`);
  }
  return out.join("\n");
}

export const codeAuditScanTool: CustomTool = {
  name: "code_audit_scan",
  description:
    "Audit a local source file or directory (inside T3MP3ST_SOURCE_ROOT) for exploitable CWE sinks, guard presence, and numbered line context",
  category: "vuln",
  parameters: [
    {
      name: "path",
      type: "string",
      description:
        "Relative or absolute path within T3MP3ST_SOURCE_ROOT to a source file or directory",
      required: true,
    },
    {
      name: "start_line",
      type: "number",
      description: "Optional 1-based start line for numbered source excerpt",
      required: false,
    },
    {
      name: "end_line",
      type: "number",
      description: "Optional 1-based end line for numbered source excerpt",
      required: false,
    },
  ],
  handler: async (context) => {
    const requestedPath = String(context.parameters.path || ".").trim();
    const approved = approvedLocalPath("code_audit_scan", requestedPath, true);
    if (!approved.ok) {
      return { success: false, error: approved.error };
    }

    const resolved = approved.path;
    const st = statSync(resolved);

    if (st.isDirectory()) {
      const entries = readdirSync(resolved)
        .filter((name) => {
          try {
            const full = join(resolved, name);
            return (
              statSync(full).isFile() &&
              (SOURCE_EXTENSIONS.has(extname(name).toLowerCase()) ||
                statSync(full).size <= 65536)
            );
          } catch {
            return false;
          }
        })
        .slice(0, 40);

      const findings: ToolFinding[] = [];
      const reportLines: string[] = [
        `code_audit_scan directory ${resolved} (${entries.length} candidate file(s)):`,
      ];

      for (const name of entries) {
        if (
          name.endsWith(".yaml") ||
          name.endsWith(".yml") ||
          name.endsWith(".md")
        ) {
          continue;
        }
        const full = join(resolved, name);
        const fstat = statSync(full);
        if (fstat.size > MAX_FILE_BYTES) continue;
        const content = readFileSync(full, "utf8");
        const hits = scanSourceText(content);
        const unguarded = hits.filter((h) => !h.guarded);
        reportLines.push(
          `  - ${name} (${content.split(/\r?\n/).length} lines): ${unguarded.length} unguarded sink(s), ${hits.length - unguarded.length} guarded`,
        );
        for (const h of unguarded) {
          reportLines.push(
            `      [${h.ruleId} ${h.cwe}] ${name}:${h.line} — ${h.snippet}`,
          );
          findings.push({
            title: `${h.vulnClass} candidate at ${name}:${h.line}`,
            severity: h.severity,
            details: `${h.description} at ${name} line ${h.line}: ${h.snippet}`,
            cwe: [h.cwe],
          });
        }
      }

      return {
        success: true,
        output: reportLines.join("\n"),
        findings: findings.length > 0 ? findings : undefined,
      };
    }

    if (st.size > MAX_FILE_BYTES) {
      return {
        success: false,
        error: `code_audit_scan: file exceeds ${MAX_FILE_BYTES} bytes`,
      };
    }

    const text = readFileSync(resolved, "utf8");
    const lines = text.split(/\r?\n/);
    const fileLabel = basename(resolved);
    const hits = scanSourceText(text);
    const unguarded = hits.filter((h) => !h.guarded);
    const guarded = hits.filter((h) => h.guarded);

    const startLineRaw = Number(context.parameters.start_line);
    const endLineRaw = Number(context.parameters.end_line);
    const startLine =
      Number.isFinite(startLineRaw) && startLineRaw > 0 ? startLineRaw : 1;
    const endLine =
      Number.isFinite(endLineRaw) && endLineRaw >= startLine
        ? Math.min(lines.length, endLineRaw)
        : Math.min(lines.length, startLine + 119);

    const outSections: string[] = [
      `code_audit_scan ${fileLabel} (${lines.length} lines):`,
      unguarded.length > 0
        ? `Unguarded sink candidates (${unguarded.length}):`
        : "No unguarded sink candidates matched heuristic rules.",
      ...unguarded.map(
        (h) =>
          `  [${h.ruleId}] ${h.cwe} (${h.severity}) line ${h.line}: ${h.description}\n    sink: ${h.snippet}`,
      ),
    ];

    if (guarded.length > 0) {
      outSections.push(
        `Guarded / mitigated sinks (${guarded.length} — verify guard completeness before reporting):`,
        ...guarded.map(
          (h) =>
            `  [GUARDED ${h.ruleId}] ${h.cwe} line ${h.line}: ${h.snippet}`,
        ),
      );
    }

    outSections.push(
      "",
      `Source (${fileLabel} lines ${startLine}..${endLine}):`,
      formatNumberedSlice(lines, startLine, endLine),
    );

    const findings: ToolFinding[] | undefined =
      unguarded.length > 0
        ? unguarded.map((h) => ({
            title: `${h.vulnClass} candidate in ${fileLabel}:${h.line}`,
            severity: h.severity,
            details: `${h.description} at ${fileLabel} line ${h.line}: ${h.snippet}`,
            cwe: [h.cwe],
          }))
        : undefined;

    return {
      success: true,
      output: outSections.join("\n"),
      findings,
    };
  },
};
