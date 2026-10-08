const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000";

export type TargetScope = "LOCAL_ARTIFACT" | "CTF_PLATFORM" | "AUTHORIZED_TARGET";

export async function createChallenge(params: {
  title: string;
  description: string;
  urls: string[];
  target_scope: TargetScope;
}) {
  const res = await fetch(`${API_BASE}/api/challenges`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params),
  });
  if (!res.ok) throw new Error(`Failed to create challenge: ${res.status}`);
  return res.json();
}

export async function uploadArtifact(challengeId: string, file: File) {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${API_BASE}/api/challenges/${challengeId}/artifacts`, {
    method: "POST",
    body: form,
  });
  if (!res.ok) throw new Error(`Failed to upload ${file.name}: ${res.status}`);
  return res.json();
}

export async function startSolve(challengeId: string) {
  const res = await fetch(`${API_BASE}/api/challenges/${challengeId}/solve`, { method: "POST" });
  if (!res.ok) throw new Error(`Failed to start solve: ${res.status}`);
  return res.json();
}

export async function getResults(challengeId: string) {
  const res = await fetch(`${API_BASE}/api/challenges/${challengeId}/results`);
  if (!res.ok) throw new Error(`Failed to fetch results: ${res.status}`);
  return res.json();
}

export function eventsUrl(challengeId: string) {
  return `${API_BASE}/api/challenges/${challengeId}/events`;
}
