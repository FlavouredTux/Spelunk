async function activate() {
  return {
    commands: [
      {
        id: "show-overview",
        title: "Show binary overview",
        description: "Read-only smoke test: lists the binary path and function count.",
        permissions: ["read.binary-summary"],
        async run(ctx) {
          const [binaryPath, summary] = await Promise.all([
            ctx.currentBinaryPath(),
            ctx.loadSummary(),
          ]);
          const fnCount = summary.functions.length;
          return {
            summary: `Plugin host is live (${fnCount} function${fnCount === 1 ? "" : "s"}).`,
            panel: {
              kind: "list",
              rows: [
                { label: "binary",    detail: binaryPath },
                { label: "functions", detail: String(fnCount) },
              ],
            },
          };
        },
      },
    ],
  };
}

module.exports = { activate };
