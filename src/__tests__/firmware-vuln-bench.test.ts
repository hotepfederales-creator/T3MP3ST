import { describe, it, expect } from "vitest";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  REQUIRED_BENCH_CWES,
  auditSecretRedaction,
  formatFirmwareBenchJson,
  formatFirmwareBenchMarkdown,
  generateFirmwareBenchCorpus,
  parseFirmwareBenchCliArgs,
  runFirmwareBenchCli,
  runFirmwareVulnBench,
} from "../bench/index.js";
import { analyzeFirmwareBuffer } from "../arsenal/firmware-audit.js";

describe("Multi-Artifact Embedded Firmware & Hardware EDA CVE/CWE Benchmark (firmware-vuln-bench)", () => {
  it("achieves precision >= 0.95, recall >= 0.95, and falsePositiveRate === 0 across all 4 firmware/EDA families and hardened controls", async () => {
    const scorecard = await runFirmwareVulnBench({
      cvssWeighted: true,
      multiJudge: true,
    });

    expect(scorecard.schema).toBe("t3mp3st.bench.firmware-vuln/v1");
    expect(scorecard.scoringMode).toBe("cvss_weighted");
    expect(scorecard.multiJudgeEnabled).toBe(true);

    // Aggregate thresholds mandated by benchmark contract
    expect(scorecard.aggregate.precision).toBeGreaterThanOrEqual(0.95);
    expect(scorecard.aggregate.recall).toBeGreaterThanOrEqual(0.95);
    expect(scorecard.aggregate.f1).toBeGreaterThanOrEqual(0.95);
    expect(scorecard.aggregate.cvssWeightedRecall).toBeGreaterThanOrEqual(0.95);
    expect(scorecard.aggregate.falsePositiveRate).toBe(0);
    expect(scorecard.aggregate.falsePositivesOnControls).toBe(0);
    expect(scorecard.aggregate.contaminatedControls).toBe(0);
    expect(scorecard.aggregate.judgeDisagreements).toBe(0);
    expect(scorecard.aggregate.judgeAgreementRate).toBe(1);

    // Every artifact must be detected under its expected format & succeed in firmware_audit_scan
    expect(scorecard.artifacts.length).toBe(14);
    for (const art of scorecard.artifacts) {
      expect(art.toolExecutionSucceeded).toBe(true);
      expect(art.formatMatched).toBe(true);
      if (art.isNegativeControl) {
        expect(art.findingsCount).toBe(0);
        expect(art.falsePositives).toBe(0);
      } else {
        expect(art.falseNegatives).toBe(0);
        expect(art.falsePositives).toBe(0);
      }
    }

    // Per-category checks across all 4 hardware/firmware families
    expect(scorecard.categories).toHaveLength(4);
    for (const cat of scorecard.categories) {
      expect(cat.precision).toBeGreaterThanOrEqual(0.95);
      expect(cat.recall).toBeGreaterThanOrEqual(0.95);
      expect(cat.f1).toBeGreaterThanOrEqual(0.95);
      expect(cat.falsePositiveRate).toBe(0);
      expect(cat.falsePositivesOnControls).toBe(0);
      expect(cat.cvssWeightedRecall).toBeGreaterThanOrEqual(0.95);
    }
  });

  it("populates full CWE coverage heatmap (CWE-78, CWE-119, CWE-120, CWE-353, CWE-798, CWE-1244) with zero blind spots", async () => {
    const scorecard = await runFirmwareVulnBench({ cvssWeighted: true });

    const cweIds = scorecard.cweHeatmap.map((r) => r.cwe);
    expect(cweIds).toEqual([...REQUIRED_BENCH_CWES]);

    for (const row of scorecard.cweHeatmap) {
      expect(row.total).toBeGreaterThanOrEqual(1);
      expect(row.detected).toBe(row.total);
      expect(row.missed).toBe(0);
      expect(row.recall).toBeGreaterThanOrEqual(0.95);
      expect(row.blindSpot).toBe(false);
      expect(row.missedVulnIds).toEqual([]);
      expect(row.cvssAwarded).toBe(row.cvssPossible);
    }
  });

  it("verifies reap_playbook triage accuracy and OpGeneral / TypeSafe mission-routing accuracy (including negative controls)", async () => {
    const scorecard = await runFirmwareVulnBench();

    // REAP Playbook triage accuracy (finding skill attribution + query top-k ranking)
    expect(scorecard.reapTriage.findingPlaybookChecks).toBeGreaterThanOrEqual(
      18,
    );
    expect(scorecard.reapTriage.findingPlaybookAccuracy).toBeGreaterThanOrEqual(
      0.95,
    );
    expect(scorecard.reapTriage.queryTopMatchAccuracy).toBeGreaterThanOrEqual(
      0.95,
    );
    expect(scorecard.reapTriage.combinedAccuracy).toBeGreaterThanOrEqual(0.95);
    expect(scorecard.reapTriage.unresolvedPlaybookIds).toEqual([]);

    // OpGeneral & TypeSafe System One mission-routing accuracy
    expect(scorecard.missionRouting.totalCases).toBeGreaterThanOrEqual(6);
    expect(scorecard.missionRouting.accuracy).toBeGreaterThanOrEqual(0.95);
    expect(scorecard.missionRouting.firmwareCasesAccuracy).toBe(1);
    expect(scorecard.missionRouting.negativeControlCasesAccuracy).toBe(1);
  });

  it("guarantees 0 unredacted secrets in benchmark findings, JSON exports, and Markdown scorecards", async () => {
    const tmpRoot = mkdtempSync(join(tmpdir(), "t3mp3st-fw-redact-check-"));
    try {
      const corpus = generateFirmwareBenchCorpus(tmpRoot);
      expect(corpus.plantedRawSecrets.length).toBeGreaterThanOrEqual(2);

      // Confirm raw secrets genuinely exist inside the planted binary/S-Record fixtures on disk
      const srecDisk = readFileSync(
        join(tmpRoot, "industrial", "plc_agent.srec"),
        "utf8",
      );
      const elfDisk = readFileSync(
        join(tmpRoot, "industrial", "httpd_arm.elf"),
      ).toString("latin1");
      const srecHexSecret = Buffer.from(corpus.plantedRawSecrets[0], "ascii")
        .toString("hex")
        .toUpperCase();
      expect(srecDisk).toContain(srecHexSecret);
      expect(elfDisk).toContain(corpus.plantedRawSecrets[1]);

      const scorecard = await runFirmwareVulnBench({
        rootDir: tmpRoot,
        keepWorkspace: true,
        multiJudge: true,
      });

      expect(scorecard.secretRedaction.passed).toBe(true);
      expect(scorecard.secretRedaction.unredactedLeakCount).toBe(0);
      expect(scorecard.secretRedaction.leakedIdentifiers).toEqual([]);
      expect(
        scorecard.secretRedaction.redactedFindingCount,
      ).toBeGreaterThanOrEqual(2);

      const jsonText = formatFirmwareBenchJson(scorecard);
      const mdText = formatFirmwareBenchMarkdown(scorecard);
      const rawScorecardStr = JSON.stringify(scorecard);

      for (const rawSecret of corpus.plantedRawSecrets) {
        expect(rawScorecardStr).not.toContain(rawSecret);
        expect(jsonText).not.toContain(rawSecret);
        expect(mdText).not.toContain(rawSecret);
      }
      expect(rawScorecardStr).toContain("[redacted]");

      // Verify auditSecretRedaction fails closed if a raw secret ever slips into a payload
      const failedAudit = auditSecretRedaction(
        [`leaked value: ${corpus.plantedRawSecrets[0]}`],
        corpus.plantedRawSecrets,
        1,
      );
      expect(failedAudit.passed).toBe(false);
      expect(failedAudit.unredactedLeakCount).toBe(1);
      expect(failedAudit.leakedIdentifiers).toEqual(["planted_secret_1"]);
    } finally {
      rmSync(tmpRoot, { recursive: true, force: true });
    }
  });

  it("produces byte-for-byte deterministic JSON and Markdown scorecards across independent runs and supports CLI export", async () => {
    const runA = await runFirmwareVulnBench({
      cvssWeighted: true,
      multiJudge: true,
    });
    const runB = await runFirmwareVulnBench({
      cvssWeighted: true,
      multiJudge: true,
    });

    const jsonA = formatFirmwareBenchJson(runA);
    const jsonB = formatFirmwareBenchJson(runB);
    expect(jsonA).toBe(jsonB);
    expect(() => JSON.parse(jsonA)).not.toThrow();

    const mdA = formatFirmwareBenchMarkdown(runA);
    const mdB = formatFirmwareBenchMarkdown(runB);
    expect(mdA).toBe(mdB);
    expect(mdA).toContain("## Aggregate Metrics");
    expect(mdA).toContain("## Per-Category Breakdown");
    expect(mdA).toContain("## CWE Coverage Heatmap");
    expect(mdA).toContain("## Artifact Verification Ledger");

    // CLI runner file export + --self-test verification
    const outDir = mkdtempSync(join(tmpdir(), "t3mp3st-fw-cli-out-"));
    try {
      const jsonPath = join(outDir, "scorecard.json");
      const mdPath = join(outDir, "scorecard.md");

      const cliRes = await runFirmwareBenchCli([
        "--cvss-weighted",
        "--multi-judge",
        "--self-test",
        "--json",
        jsonPath,
        "--markdown",
        mdPath,
      ]);

      expect(existsSync(jsonPath)).toBe(true);
      expect(existsSync(mdPath)).toBe(true);
      expect(readFileSync(jsonPath, "utf8")).toBe(cliRes.json);
      expect(readFileSync(mdPath, "utf8")).toBe(cliRes.markdown);

      expect(() =>
        parseFirmwareBenchCliArgs(["--category", "invalid_cat"]),
      ).toThrow(/invalid --category/);
    } finally {
      rmSync(outDir, { recursive: true, force: true });
    }
  });

  it("surfaces multi-judge disagreements, blind spots, and non-zero FPR under adversarial detector perturbations", async () => {
    // Perturb detector: corrupt REAP playbook attribution on findings & drop CWE-120 + inject FP on controls
    const perturbed = await runFirmwareVulnBench({
      category: "automotive_ihex",
      multiJudge: true,
      cvssWeighted: true,
      detectorOverride: (buf, filePath) => {
        const real = analyzeFirmwareBuffer(buf, filePath).findings;
        if (filePath.endsWith("bms_cal_tables_clean.hex")) {
          return [
            {
              ruleId: "FW-SINK-STRCPY-SPRINTF",
              vulnClass: "unbounded_memory_copy",
              title: "Synthetic false positive on benign calibration table",
              category: "memory_sink",
              severity: "high",
              cvssWeight: 8.2,
              cwe: ["CWE-120"],
              reapPlaybookId: "reap-10-vulnerability-research",
              evidence: "snprintf misclassified",
              remediation:
                "Replace unbounded formatting with bounded snprintf calls.",
            },
          ];
        }
        // Drop CWE-120 finding & corrupt playbook on CWE-353 checksum finding
        return real
          .filter((f) => !f.cwe.includes("CWE-120"))
          .map((f) => ({
            ...f,
            reapPlaybookId: "reap-19-kernel-and-driver-exploitation-research",
          }));
      },
    });

    expect(perturbed.aggregate.falsePositiveRate).toBeGreaterThan(0);
    expect(perturbed.aggregate.judgeDisagreements).toBeGreaterThanOrEqual(1);
    expect(perturbed.aggregate.recall).toBeLessThan(1);

    const cwe120Row = perturbed.cweHeatmap.find((r) => r.cwe === "CWE-120");
    expect(cwe120Row?.blindSpot).toBe(true);
    expect(cwe120Row?.missedVulnIds).toContain("BMS-HEX-02");
  });
});
