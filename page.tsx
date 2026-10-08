"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { createChallenge, uploadArtifact, startSolve, TargetScope } from "@/lib/api";

export default function HomePage() {
  const router = useRouter();
  const [description, setDescription] = useState("");
  const [urlsText, setUrlsText] = useState("");
  const [targetScope, setTargetScope] = useState<TargetScope>("LOCAL_ARTIFACT");
  const [files, setFiles] = useState<FileList | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSolve() {
    if (!description.trim() && !files?.length) {
      setError("Add a challenge description or at least one file.");
      return;
    }
    setError(null);
    setSubmitting(true);
    try {
      const urls = urlsText
        .split("\n")
        .map((u) => u.trim())
        .filter(Boolean);

      const challenge = await createChallenge({
        title: description.slice(0, 60) || "Untitled challenge",
        description,
        urls,
        target_scope: targetScope,
      });

      if (files) {
        for (const file of Array.from(files)) {
          await uploadArtifact(challenge.id, file);
        }
      }

      await startSolve(challenge.id);
      router.push(`/challenge/${challenge.id}`);
    } catch (e: any) {
      setError(e.message || "Something went wrong.");
      setSubmitting(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-100">New Challenge</h1>
        <p className="text-sm text-gray-400 mt-1">
          Paste a description, add challenge URLs, and/or upload files. For web challenges, only the exact
          URL you paste here is ever fetched, read-only (headers, HTML, robots.txt) — no scanning or
          exploitation.
        </p>
      </div>

      <div>
        <label className="block text-sm text-gray-400 mb-1">Challenge description</label>
        <textarea
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          rows={6}
          placeholder="We intercepted this strange message. Something is hidden inside the attached image..."
          className="w-full bg-panel border border-gray-800 rounded-md p-3 text-sm focus:outline-none focus:border-accent"
        />
      </div>

      <div>
        <label className="block text-sm text-gray-400 mb-1">Challenge URLs (one per line, optional)</label>
        <textarea
          value={urlsText}
          onChange={(e) => setUrlsText(e.target.value)}
          rows={2}
          placeholder="https://example-ctf.local/challenge/image.png"
          className="w-full bg-panel border border-gray-800 rounded-md p-3 text-sm focus:outline-none focus:border-accent"
        />
      </div>

      <div>
        <label className="block text-sm text-gray-400 mb-1">Files</label>
        <input
          type="file"
          multiple
          onChange={(e) => setFiles(e.target.files)}
          className="block w-full text-sm text-gray-400 file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:bg-gray-800 file:text-gray-200 hover:file:bg-gray-700"
        />
      </div>

      <div>
        <label className="block text-sm text-gray-400 mb-1">Target authorization</label>
        <select
          value={targetScope}
          onChange={(e) => setTargetScope(e.target.value as TargetScope)}
          className="bg-panel border border-gray-800 rounded-md p-2 text-sm"
        >
          <option value="LOCAL_ARTIFACT">Local artifact only (files, no network)</option>
          <option value="CTF_PLATFORM">CTF platform (e.g. CTFd instance)</option>
          <option value="AUTHORIZED_TARGET">Explicitly authorized target</option>
        </select>
      </div>

      {error && <p className="text-sm text-red-400">{error}</p>}

      <button
        onClick={handleSolve}
        disabled={submitting}
        className="bg-accent text-black font-semibold px-6 py-3 rounded-md hover:opacity-90 disabled:opacity-50"
      >
        {submitting ? "Starting..." : "SOLVE CHALLENGE"}
      </button>
    </div>
  );
}
