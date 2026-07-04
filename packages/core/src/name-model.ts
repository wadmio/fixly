// Node-side inference for the package-name risk model (ml/ lab → ONNX).
//
// This mirrors ml/fixly_ml/features.py EXACTLY — the feature vector order is
// pinned by name-risk.meta.json (the training artifact). Inference is optional
// at runtime: if the model or onnxruntime-node isn't present, callers fall
// back to the rule-based typosquat signal. So onnxruntime-node is an OPTIONAL
// dependency and is imported lazily.

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const MODELS_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "ml", "models");
const MODEL_PATH = join(MODELS_DIR, "name-risk.onnx");
const META_PATH = join(MODELS_DIR, "name-risk.meta.json");

interface ModelMeta {
  feature_names: string[];
  threshold: number;
  popular: string[];
  bigram: { counts: Record<string, number>; context: Record<string, number> };
}

const VOWELS = new Set(["a", "e", "i", "o", "u"]);
const AFFIXES = ["js-", "node-", "lib", "-js", "-node", "-cli", "-api", "-sdk", "-lib", ".js"];
const BOUNDARY = "\x00";

function stripScope(name: string): string {
  if (name.startsWith("@") && name.includes("/")) return name.slice(name.indexOf("/") + 1);
  return name;
}

function shannonEntropy(s: string): number {
  if (!s) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function maxConsonantRun(s: string): number {
  let run = 0;
  let best = 0;
  for (const ch of s) {
    if (/[a-z]/i.test(ch) && !VOWELS.has(ch.toLowerCase())) {
      run++;
      best = Math.max(best, run);
    } else run = 0;
  }
  return best;
}

function editDistanceCapped(a: string, b: string, cap = 3): number {
  if (Math.abs(a.length - b.length) > cap) return cap + 1;
  const m = a.length;
  const n = b.length;
  let prev2: number[] = [];
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  for (let i = 1; i <= m; i++) {
    const cur = [i, ...new Array<number>(n).fill(0)];
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        cur[j] = Math.min(cur[j], prev2[j - 2] + 1);
      }
    }
    if (Math.min(...cur) > cap) return cap + 1;
    [prev2, prev] = [prev, cur];
  }
  return prev[n];
}

function bigramLogLik(name: string, meta: ModelMeta): number {
  const s = BOUNDARY + stripScope(name.toLowerCase()) + BOUNDARY;
  const vocab = new Set<string>();
  for (const key of Object.keys(meta.bigram.counts)) {
    const [a, b] = key.split("\t");
    vocab.add(a);
    vocab.add(b);
  }
  const v = Math.max(vocab.size, 1);
  let total = 0;
  let pairs = 0;
  for (let i = 0; i < s.length - 1; i++) {
    const a = s[i];
    const b = s[i + 1];
    const count = meta.bigram.counts[`${a}\t${b}`] ?? 0;
    const context = meta.bigram.context[a] ?? 0;
    total += Math.log2((count + 1) / (context + v));
    pairs++;
  }
  return pairs ? total / pairs : 0;
}

/** Build the feature vector — MUST match fixly_ml.features.extract_features. */
export function buildNameFeatures(name: string, meta: ModelMeta): number[] {
  const tail = stripScope(name.toLowerCase());
  const n = Math.max(tail.length, 1);

  let minDist = 4;
  for (const pop of meta.popular) {
    const d = editDistanceCapped(tail, stripScope(pop.toLowerCase()));
    if (d > 0 && d < minDist) minDist = d;
    if (minDist === 1) break;
  }

  const digitRatio = [...tail].filter((c) => /\d/.test(c)).length / n;
  const vowelRatio = [...tail].filter((c) => VOWELS.has(c)).length / n;

  return [
    tail.length,
    digitRatio,
    (tail.match(/-/g) ?? []).length,
    (tail.match(/\./g) ?? []).length,
    (tail.match(/_/g) ?? []).length,
    name.startsWith("@") ? 1 : 0,
    shannonEntropy(tail),
    vowelRatio,
    maxConsonantRun(tail),
    bigramLogLik(name, meta),
    minDist,
    minDist === 1 ? 1 : 0,
    AFFIXES.some((a) => tail.startsWith(a) || tail.endsWith(a)) ? 1 : 0,
  ];
}

export interface NameRiskResult {
  /** P(name resembles the malicious population), 0–1. */
  score: number;
  /** True when score ≥ the model's tuned threshold. */
  flagged: boolean;
}

// Lazy singletons — load the model + runtime once, tolerate their absence.
let loadPromise: Promise<{
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  session: any;
  meta: ModelMeta;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  ort: any;
} | null> | null = null;

async function load() {
  if (loadPromise) return loadPromise;
  loadPromise = (async () => {
    try {
      const [ortNs, metaRaw, modelBytes] = await Promise.all([
        // Optional dependency — absent in the base install. The dynamic
        // specifier keeps TS from resolving its (unshipped) types while still
        // loading it at runtime when present.
        import(/* @vite-ignore */ "onnxruntime-node" as string) as Promise<Record<string, unknown>>,
        readFile(META_PATH, "utf8"),
        readFile(MODEL_PATH),
      ]);
      // CJS/ESM interop: InferenceSession may sit on the namespace or its
      // .default depending on how the loader wrapped the native module.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const ort: any =
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (ortNs as any).InferenceSession ? ortNs : (ortNs as any).default;
      const meta = JSON.parse(metaRaw) as ModelMeta;
      const session = await ort.InferenceSession.create(modelBytes);
      return { session, meta, ort };
    } catch (err) {
      // No model / no runtime → callers use the rule-based fallback.
      if (process.env.FIXLY_DEBUG_ML) {
        process.stderr.write(`[name-model] load failed: ${err instanceof Error ? err.stack : String(err)}\n`);
      }
      return null;
    }
  })();
  return loadPromise;
}

/** True when the ONNX model and runtime are both available. */
export async function isNameModelAvailable(): Promise<boolean> {
  return (await load()) !== null;
}

/**
 * Score a package name with the ONNX model. Returns null when the model isn't
 * available (caller should fall back to the rule-based typosquat signal).
 */
export async function scoreNameRisk(name: string): Promise<NameRiskResult | null> {
  const loaded = await load();
  if (!loaded) return null;
  const { session, meta, ort } = loaded;

  const features = Float32Array.from(buildNameFeatures(name, meta));
  const tensor = new ort.Tensor("float32", features, [1, features.length]);
  const output = await session.run({ [session.inputNames[0]]: tensor });

  // skl2onnx with zipmap:false emits probabilities as the 2nd output ([,P1]).
  const probsName = session.outputNames[session.outputNames.length - 1];
  const data = output[probsName].data as Float32Array;
  const score = data.length >= 2 ? data[1] : data[0];
  return { score, flagged: score >= meta.threshold };
}

/** Reset the lazy cache (tests). */
export function resetNameModel(): void {
  loadPromise = null;
}
