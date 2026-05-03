window.ANCHOR_BENCH_DATA = {
  name: "Anchor Bench",
  generated_at: "2026-05-03T12:48:00.000Z",
  benchmark: "anchor-bench.hard.v1",
  note: "Corrected hard-v1 data on strip --strip-all binaries. Free-tier rows with complete 429 failures are excluded; partial free-tier rows are kept with their run caveat in the provider label.",
  entries: [
    {
      model: "minimax/minimax-m2.5:free",
      provider: "OpenRouter free (partial)",
      mode: "single-pass",
      benchmark: "anchor-bench.hard.v1-stripped",
      trials: 1,
      targets: 29,
      name_targets: 23,
      accuracy: 0.20689655172413793,
      accuracy_stddev: 0,
      name_accuracy: 0,
      name_accuracy_stddev: 0,
      utility: 0.211864406779661,
      utility_stddev: 0,
      points: 12.5,
      max_points: 59,
      correct: 0,
      wrong: 4,
      missing: 19,
      disputed: 0,
      abstained: 6,
      hallucinated: 0,
      hallucinated_total: 0,
      cost_usd: 0,
      latency_s: 223.2,
      slices: {
        difficulty: {
          medium: { targets: 8, accuracy: 0, name_accuracy: 0, utility: -0.5625, hallucinated: 0 },
          hard: { targets: 15, accuracy: 0, name_accuracy: 0, utility: 0.07575757575757576, hallucinated: 0 },
          negative: { targets: 6, accuracy: 1, name_accuracy: 0, utility: 1, hallucinated: 0 }
        }
      }
    },
    {
      model: "deepseek/deepseek-v4-flash",
      provider: "OpenRouter",
      mode: "single-pass",
      benchmark: "anchor-bench.hard.v1-stripped",
      trials: 1,
      targets: 29,
      name_targets: 23,
      accuracy: 0.1724137931034483,
      accuracy_stddev: 0,
      name_accuracy: 0,
      name_accuracy_stddev: 0,
      utility: -0.1271186440677966,
      utility_stddev: 0,
      points: -7.5,
      max_points: 59,
      correct: 0,
      wrong: 8,
      missing: 15,
      disputed: 0,
      abstained: 5,
      hallucinated: 1,
      hallucinated_total: 1,
      cost_usd: 0.029624,
      latency_s: 78.1,
      slices: {
        difficulty: {
          medium: { targets: 8, accuracy: 0, name_accuracy: 0, utility: -0.5625, hallucinated: 0 },
          hard: { targets: 15, accuracy: 0, name_accuracy: 0, utility: -0.015151515151515152, hallucinated: 0 },
          negative: { targets: 6, accuracy: 0.8333333333333334, name_accuracy: 0, utility: 0.5, hallucinated: 1 }
        }
      }
    },
    {
      model: "openrouter/owl-alpha",
      provider: "OpenRouter free (partial)",
      mode: "single-pass",
      benchmark: "anchor-bench.hard.v1-stripped",
      trials: 1,
      targets: 29,
      name_targets: 23,
      accuracy: 0.13793103448275862,
      accuracy_stddev: 0,
      name_accuracy: 0,
      name_accuracy_stddev: 0,
      utility: -0.23728813559322035,
      utility_stddev: 0,
      points: -14,
      max_points: 59,
      correct: 0,
      wrong: 8,
      missing: 15,
      disputed: 0,
      abstained: 4,
      hallucinated: 2,
      hallucinated_total: 2,
      cost_usd: 0,
      latency_s: 139,
      slices: {
        difficulty: {
          medium: { targets: 8, accuracy: 0, name_accuracy: 0, utility: -0.75, hallucinated: 0 },
          hard: { targets: 15, accuracy: 0, name_accuracy: 0, utility: -0.19696969696969696, hallucinated: 0 },
          negative: { targets: 6, accuracy: 0.6666666666666666, name_accuracy: 0, utility: 0.16666666666666666, hallucinated: 2 }
        }
      }
    },
    {
      model: "deepseek/deepseek-v4-pro",
      provider: "OpenRouter",
      mode: "single-pass",
      benchmark: "anchor-bench.hard.v1-stripped",
      trials: 1,
      targets: 29,
      name_targets: 23,
      accuracy: 0.13793103448275862,
      accuracy_stddev: 0,
      name_accuracy: 0,
      name_accuracy_stddev: 0,
      utility: -0.3644067796610169,
      utility_stddev: 0,
      points: -21.5,
      max_points: 59,
      correct: 0,
      wrong: 11,
      missing: 12,
      disputed: 0,
      abstained: 4,
      hallucinated: 2,
      hallucinated_total: 2,
      cost_usd: 0.139539,
      latency_s: 171.5,
      slices: {
        difficulty: {
          medium: { targets: 8, accuracy: 0, name_accuracy: 0, utility: -0.75, hallucinated: 0 },
          hard: { targets: 15, accuracy: 0, name_accuracy: 0, utility: -0.24242424242424243, hallucinated: 0 },
          negative: { targets: 6, accuracy: 0.6666666666666666, name_accuracy: 0, utility: 0.16666666666666666, hallucinated: 2 }
        }
      }
    },
    {
      model: "x-ai/grok-4.1-fast",
      provider: "OpenRouter",
      mode: "single-pass",
      benchmark: "anchor-bench.hard.v1-stripped",
      trials: 1,
      targets: 29,
      name_targets: 23,
      accuracy: 0.06896551724137931,
      accuracy_stddev: 0,
      name_accuracy: 0,
      name_accuracy_stddev: 0,
      utility: -0.6694915254237288,
      utility_stddev: 0,
      points: -39.5,
      max_points: 59,
      correct: 0,
      wrong: 10,
      missing: 13,
      disputed: 0,
      abstained: 2,
      hallucinated: 4,
      hallucinated_total: 4,
      cost_usd: 0.049839,
      latency_s: 42.7,
      slices: {
        difficulty: {
          medium: { targets: 8, accuracy: 0, name_accuracy: 0, utility: -0.75, hallucinated: 0 },
          hard: { targets: 15, accuracy: 0, name_accuracy: 0, utility: -0.45454545454545453, hallucinated: 0 },
          negative: { targets: 6, accuracy: 0.3333333333333333, name_accuracy: 0, utility: -0.3333333333333333, hallucinated: 4 }
        }
      }
    }
  ],
  hard_preview: [
    { band: "stripped", target_mix: "No ELF symbol table; source names are hidden", weight: 1 },
    { band: "medium", target_mix: "FP, print noise, memory helpers", weight: 1 },
    { band: "hard", target_mix: "Indirect tails, cleanup flow, no-string kernels", weight: 2 },
    { band: "negative", target_mix: "Runtime stubs and interior blocks; abstention required", weight: 3 }
  ]
};
