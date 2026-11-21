import test from "node:test";
import assert from "node:assert/strict";
import {
  extractGroundingSources,
  formatBytes,
  isSafeSubdirectoryName,
  parseGroundedAiJson,
  previewPiiRedaction,
  verifyCitedArtifactIds,
} from "./forensicValidation";

test("formatBytes formats byte sizes cleanly", () => {
  assert.equal(formatBytes(512), "512 B");
  assert.equal(formatBytes(2048), "2.0 KB");
  assert.equal(formatBytes(1048576), "1.0 MB");
});

test("previewPiiRedaction masks email, IPv4, and phone patterns", () => {
  const res = previewPiiRedaction("Email test@example.org IP 10.0.0.25 Phone +1-555-321-7654");
  assert.equal(res.count, 3);
  assert.ok(res.redacted.includes("[REDACTED_EMAIL]"));
  assert.ok(res.redacted.includes("[REDACTED_IP]"));
  assert.ok(res.redacted.includes("[REDACTED_PHONE]"));
});

test("verifyCitedArtifactIds rejects unknown IDs", () => {
  const known = new Set(["art_111", "art_222"]);
  const out = verifyCitedArtifactIds(["art_111", "art_hallucinated", "art_222"], known);
  assert.deepEqual(out.verified, ["art_111", "art_222"]);
  assert.deepEqual(out.rejected, ["art_hallucinated"]);
});

test("isSafeSubdirectoryName blocks traversal and separators", () => {
  assert.equal(isSafeSubdirectoryName("export_01"), true);
  assert.equal(isSafeSubdirectoryName("../etc"), false);
  assert.equal(isSafeSubdirectoryName("foo/bar"), false);
});

test("extractGroundingSources filters unsafe URLs and deduplicates chunks", () => {
  const meta = {
    webSearchQueries: ["Android CVE-2025 mobile forensics", ""],
    groundingChunks: [
      { web: { uri: "https://nvd.nist.gov/vuln/detail/CVE-2025-0001", title: "NVD CVE-2025-0001" } },
      { web: { uri: "https://nvd.nist.gov/vuln/detail/CVE-2025-0001", title: "Duplicate" } },
      { web: { uri: "javascript:alert(1)", title: "Unsafe link" } },
      { web: { uri: "https://source.android.com/docs/security/bulletin", title: "Android Security Bulletin" } },
    ],
  };
  const extracted = extractGroundingSources(meta);
  assert.deepEqual(extracted.queries, ["Android CVE-2025 mobile forensics"]);
  assert.equal(extracted.sources.length, 2);
  assert.equal(extracted.sources[0].title, "NVD CVE-2025-0001");
  assert.equal(extracted.sources[1].uri, "https://source.android.com/docs/security/bulletin");
});

test("parseGroundedAiJson parses fenced JSON and falls back cleanly on prose", () => {
  const fenced = "Here is the analysis:\n```json\n{\"report_draft_summary\": \"Grounded CVE note\"}\n```";
  assert.equal(parseGroundedAiJson(fenced).report_draft_summary, "Grounded CVE note");

  const prose = "Summary of CVE-2025-1234 impact on iOS backups.";
  const fallback = parseGroundedAiJson(prose);
  assert.equal(fallback.report_draft_summary, prose);
  assert.ok(Array.isArray(fallback.verified_observations));
});
