import { describe, it, expect } from "vitest";
import {
  REAP_PLAYBOOKS,
  selectReapPlaybooks,
  getReapPlaybookById,
  reapPlaybookTool,
} from "../arsenal/reap-playbooks.js";
import {
  Arsenal,
  BUILTIN_TOOLS,
  createToolContext,
} from "../arsenal/index.js";
import { summarizeToolCatalog } from "../arsenal/catalog.js";
import { ARCHETYPE_PROFILES } from "../operators/index.js";

describe("REAP Playbooks & reap_playbook Arsenal Tool", () => {
  describe("Catalog Integrity", () => {
    it("contains the full distilled REAP taxonomy with unique IDs and skill names", () => {
      const ids = REAP_PLAYBOOKS.map((p) => p.id);
      const skillNames = REAP_PLAYBOOKS.map((p) => p.skillName);

      expect(new Set(ids).size).toBe(REAP_PLAYBOOKS.length);
      expect(new Set(skillNames).size).toBe(REAP_PLAYBOOKS.length);

      const expectedIds = [
        "reap-02",
        "reap-03",
        "reap-04",
        "reap-05",
        "reap-06",
        "reap-07",
        "reap-08",
        "reap-09",
        "reap-10",
        "reap-11",
        "reap-12",
        "reap-15",
        "reap-16",
        "reap-17",
        "reap-18",
        "reap-19",
        "reap-20",
        "reap-21",
        "reap-22",
        "reap-wildcard",
        "reap-prompt-writing-tips",
      ];
      expect(ids).toEqual(expect.arrayContaining(expectedIds));

      for (const playbook of REAP_PLAYBOOKS) {
        expect(playbook.title.length).toBeGreaterThan(3);
        expect(playbook.summary.length).toBeGreaterThan(15);
        expect(playbook.targetFormats.length).toBeGreaterThan(0);
        expect(playbook.objectives.length).toBeGreaterThan(0);
        expect(playbook.reaToolPipeline.length).toBeGreaterThan(0);
        expect(playbook.evidenceChecklist.length).toBeGreaterThan(0);
        expect(playbook.promptTemplates.length).toBeGreaterThan(0);
        expect(playbook.staticFirst).toBe(true);
      }
    });

    it("is wired into BUILTIN_TOOLS, catalog summary, and reverse_binary/analyst/coordinator toolkits", () => {
      expect(BUILTIN_TOOLS.some((t) => t.name === "reap_playbook")).toBe(true);
      expect(ARCHETYPE_PROFILES.scanner.defaultTools).toContain("reap_playbook");
      expect(ARCHETYPE_PROFILES.analyst.defaultTools).toContain("reap_playbook");
      expect(ARCHETYPE_PROFILES.coordinator.defaultTools).toContain(
        "reap_playbook",
      );

      const summary = summarizeToolCatalog();
      expect(summary.reapPlaybooks).toBe(REAP_PLAYBOOKS.length);
    });
  });

  describe("Deterministic Multi-Factor Selection", () => {
    it("selects native binary exploration for Windows PE triage", () => {
      const res = selectReapPlaybooks({
        binaryFormat: "pe",
        objective: "explore",
        targetType: "Windows PE32 executable imports and sections",
      });

      expect(res.normalizedFormat).toBe("pe");
      expect(res.normalizedObjective).toBe("explore");
      expect(res.matches[0]?.playbook.id).toBe("reap-03");
      expect(res.recommendedPipeline).toContain("rea.triage_binary");
      expect(res.recommendedPipeline).toContain("rea.list_imports");
    });

    it("selects firmware & embedded playbook for SquashFS firmware images", () => {
      const res = selectReapPlaybooks({
        targetType: "router firmware.bin with SquashFS rootfs",
        objective: "explore",
      });

      expect(res.normalizedFormat).toBe("firmware");
      expect(res.matches[0]?.playbook.id).toBe("reap-07");
      expect(res.recommendedPipeline).toContain("rea.scan_firmware_partitions");
      expect(res.recommendedPipeline).toContain("rea.extract_filesystem");
    });

    it("selects Android playbook for APK + JNI analysis", () => {
      const res = selectReapPlaybooks({
        binaryFormat: "apk",
        targetType: "Android APK with native JNI library",
        objective: "trace",
      });

      expect(res.normalizedFormat).toBe("apk");
      expect(res.matches[0]?.playbook.id).toBe("reap-08");
      expect(res.recommendedPipeline).toContain("rea.inspect_android_manifest");
      expect(res.recommendedPipeline).toContain("rea.find_jni_bridges");
    });

    it("selects Electron & JS playbook for ASAR IPC audits", () => {
      const res = selectReapPlaybooks({
        binaryFormat: "electron",
        targetType: "app.asar preload contextBridge and ipcMain",
        objective: "vuln",
      });

      expect(res.normalizedFormat).toBe("electron");
      expect(res.matches[0]?.playbook.id).toBe("reap-11");
      expect(res.recommendedPipeline).toContain("rea.unpack_asar");
      expect(res.recommendedPipeline).toContain("rea.inspect_ipc_channels");
    });

    it("selects version comparison & crash playbook for patch diffing", () => {
      const res = selectReapPlaybooks({
        binaryFormat: "diff",
        objective: "diff",
        targetType: "compare v1 and v2 versions for security regression",
      });

      expect(res.normalizedFormat).toBe("diff");
      expect(res.normalizedObjective).toBe("diff");
      expect(res.matches[0]?.playbook.id).toBe("reap-15");
      expect(res.recommendedPipeline).toContain(
        "rea.compare_application_versions",
      );
    });

    it("selects Go/Rust source recovery playbook for stripped Golang or Rust binaries", () => {
      const res = selectReapPlaybooks({
        binaryFormat: "go_rust",
        targetType: "stripped Go binary pclntab and Rust crate panic strings",
        objective: "reconstruct",
      });

      expect(res.normalizedFormat).toBe("go_rust");
      expect(res.matches[0]?.playbook.id).toBe("reap-22");
      expect(res.recommendedPipeline).toContain("rea.recover_go_pclntab");
      expect(res.recommendedPipeline).toContain("rea.recover_rust_metadata");
    });

    it("selects vulnerability research playbook for untrusted source-to-sink audits", () => {
      const res = selectReapPlaybooks({
        binaryFormat: "elf",
        objective: "vuln",
        targetType: "trust boundary sink hunt memcpy deserialization CVE",
      });

      expect(res.normalizedObjective).toBe("vuln");
      expect(res.matches[0]?.playbook.id).toBe("reap-10");
      expect(res.evidenceChecklist.some((c) => c.includes("preconditions"))).toBe(
        true,
      );
    });

    it("selects deobfuscation playbook for control-flow flattening and opaque predicates", () => {
      const res = selectReapPlaybooks({
        binaryFormat: "pe",
        objective: "deobfuscate",
        targetType: "control-flow flattening dispatcher and string decryption",
      });

      expect(res.normalizedObjective).toBe("deobfuscate");
      expect(res.matches[0]?.playbook.id).toBe("reap-18");
      expect(res.recommendedPipeline).toContain("rea.inspect_cfg");
    });

    it("selects kernel & driver vulnerability playbook for Windows IOCTL drivers", () => {
      const res = selectReapPlaybooks({
        binaryFormat: "driver",
        objective: "vuln",
        targetType: "Windows .sys driver IOCTL TOCTOU UAF",
      });

      expect(res.normalizedFormat).toBe("driver");
      expect(res.matches[0]?.playbook.id).toBe("reap-19");
      expect(res.recommendedPipeline).toContain("rea.find_ioctl_handlers");
    });

    it("synthesizes deduplicated pipelines, respects maxPlaybooks, and falls back cleanly on empty queries", () => {
      const emptyRes = selectReapPlaybooks({});
      expect(emptyRes.matches.length).toBe(3);
      expect(emptyRes.matches[0]?.playbook.id).toBe("reap-wildcard");

      const capped = selectReapPlaybooks({
        binaryFormat: "pe",
        objective: "explore",
        maxPlaybooks: 2,
      });
      expect(capped.matches.length).toBe(2);
      expect(new Set(capped.recommendedPipeline).size).toBe(
        capped.recommendedPipeline.length,
      );
      expect(new Set(capped.evidenceChecklist).size).toBe(
        capped.evidenceChecklist.length,
      );
      expect(capped.renderedPrompts.length).toBeGreaterThan(0);
    });
  });

  describe("Arsenal reap_playbook Tool Execution", () => {
    it("executes via Arsenal.execute() for multi-factor queries", async () => {
      const arsenal = new Arsenal();
      arsenal.registerMany(BUILTIN_TOOLS);

      const res = await arsenal.execute(
        "reap_playbook",
        createToolContext(undefined, {
          binary_format: "go_rust",
          objective: "reconstruct",
          target_type: "stripped golang pclntab binary",
          max_playbooks: 2,
        }),
      );

      expect(res.success).toBe(true);
      expect(res.output).toContain("[reap-22]");
      expect(res.output).toContain("rea.recover_go_pclntab");
      expect(res.output).toContain("Evidence & Unknown-Tracking Checklist");
      expect(res.output).toContain("Prompt Templates");
    });

    it("supports direct playbook_id lookup and rejects unknown IDs cleanly", async () => {
      expect(getReapPlaybookById("reap-20")?.skillName).toBe(
        "reap-20-advanced-software-cloning-and-feature-reconstruction",
      );

      const directRes = await reapPlaybookTool.handler(
        createToolContext(undefined, { playbook_id: "reap-16" }),
      );
      expect(directRes.success).toBe(true);
      expect(directRes.output).toContain("[reap-16]");
      expect(directRes.output).toContain("rea.audit_residual_unknowns");

      const badRes = await reapPlaybookTool.handler(
        createToolContext(undefined, { playbook_id: "reap-999" }),
      );
      expect(badRes.success).toBe(false);
      expect(badRes.error).toContain("unknown playbook_id");
    });
  });
});
