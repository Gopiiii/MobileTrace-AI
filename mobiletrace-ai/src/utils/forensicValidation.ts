export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unitIdx = 0;
  while (value >= 1024 && unitIdx < units.length - 1) {
    value /= 1024;
    unitIdx++;
  }
  return `${value.toFixed(1)} ${units[unitIdx]}`;
}

export function previewPiiRedaction(text: string): { redacted: string; count: number } {
  let count = 0;
  let out = text.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, () => {
    count++;
    return "[REDACTED_EMAIL]";
  });
  out = out.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, () => {
    count++;
    return "[REDACTED_IP]";
  });
  out = out.replace(/(?<!\w)(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)|\d{2,4})[\s.-]?\d{3,4}[\s.-]?\d{4}(?!\w)/g, () => {
    count++;
    return "[REDACTED_PHONE]";
  });
  return { redacted: out, count };
}

export function verifyCitedArtifactIds(
  citedIds: string[],
  knownIds: Set<string>
): { verified: string[]; rejected: string[] } {
  const verified: string[] = [];
  const rejected: string[] = [];
  for (const raw of citedIds) {
    const id = raw.trim();
    if (!id) continue;
    if (knownIds.has(id)) {
      if (!verified.includes(id)) verified.push(id);
    } else {
      if (!rejected.includes(id)) rejected.push(id);
    }
  }
  return { verified, rejected };
}

export function isSafeSubdirectoryName(name: string): boolean {
  const trimmed = name.trim();
  if (!trimmed) return false;
  if (trimmed.includes("..") || trimmed.includes("/") || trimmed.includes("\\")) return false;
  return /^[A-Za-z0-9._-]+$/.test(trimmed);
}

export interface GroundingSource {
  title: string;
  uri: string;
}

export function isSafeHttpUrl(rawUrl: string): boolean {
  try {
    const parsed = new URL(rawUrl.trim());
    return parsed.protocol === "https:" || parsed.protocol === "http:";
  } catch {
    return false;
  }
}

export function extractGroundingSources(groundingMetadata: any): {
  sources: GroundingSource[];
  queries: string[];
} {
  const sources: GroundingSource[] = [];
  const seenUris = new Set<string>();
  const chunks = Array.isArray(groundingMetadata?.groundingChunks)
    ? groundingMetadata.groundingChunks
    : [];

  for (const chunk of chunks) {
    const uri = typeof chunk?.web?.uri === "string" ? chunk.web.uri.trim() : "";
    const title = typeof chunk?.web?.title === "string" ? chunk.web.title.trim() : "";
    if (!uri || !isSafeHttpUrl(uri) || seenUris.has(uri)) continue;
    seenUris.add(uri);
    sources.push({ title: title || uri, uri });
  }

  const queries = Array.isArray(groundingMetadata?.webSearchQueries)
    ? groundingMetadata.webSearchQueries
        .filter((q: unknown): q is string => typeof q === "string" && q.trim().length > 0)
        .map((q: string) => q.trim())
    : [];

  return { sources, queries };
}

export function parseGroundedAiJson(rawText: string): Record<string, any> {
  const trimmed = (rawText || "").trim();
  if (!trimmed) return {};

  // Try direct parse first
  try {
    const parsed = JSON.parse(trimmed);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed;
    }
  } catch {
    // Try extracting fenced JSON block (common when Google Search grounding returns markdown)
  }

  const fenceMatch = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fenceMatch && fenceMatch[1]) {
    try {
      const parsed = JSON.parse(fenceMatch[1].trim());
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        return parsed;
      }
    } catch {
      // Fall through to prose wrapper
    }
  }

  const braceStart = trimmed.indexOf("{");
  const braceEnd = trimmed.lastIndexOf("}");
  if (braceStart !== -1 && braceEnd > braceStart) {
    try {
      const parsed = JSON.parse(trimmed.slice(braceStart, braceEnd + 1));
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        return parsed;
      }
    } catch {
      // Fall through to prose wrapper
    }
  }

  return {
    verified_observations: [],
    contradictions: [],
    competing_hypotheses: [],
    missing_evidence_gaps: [],
    cross_device_correlations: [],
    suggested_next_steps: [],
    report_draft_summary: trimmed,
    uncertainty_and_limitations:
      "Model returned narrative grounded text instead of strict JSON; review all claims and external sources manually.",
  };
}
