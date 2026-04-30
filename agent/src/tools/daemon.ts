import { spawn, type ChildProcessByStdio } from "node:child_process";
import type { Readable, Writable } from "node:stream";

// Long-lived ember daemon client.
//
// The C++ side is `ember --serve <binary>`. It loads the binary once,
// then loops: tab-delimited request line in on stdin, length-framed
// response on stdout. We hold one daemon per binary per worker — the
// strace traces of fanout runs were 95% wait4(); reusing the same
// process across 30 tool calls slashes that.
//
// Frame format (output side):
//   ready ember-serve v1\n         (one-shot startup line)
//   ok <bytes>\n<body>\n
//   err <message>\n
//
// Request line:
//   <method>\t<key>=<val>[\t<key>=<val>]*\n

interface PendingCall {
    resolve: (body: string) => void;
    reject:  (err: Error)  => void;
}

export class EmberDaemon {
    private proc: ChildProcessByStdio<Writable, Readable, Readable>;
    private buf = Buffer.alloc(0);
    private queue: PendingCall[] = [];
    private ready = false;
    private deadErr: Error | null = null;
    private waitingReady: Array<() => void> = [];

    constructor(emberBin: string, binary: string, env: NodeJS.ProcessEnv = process.env) {
        this.proc = spawn(emberBin, ["--serve", binary], {
            stdio: ["pipe", "pipe", "pipe"],
            env,
        });
        this.proc.stdout.on("data", (b: Buffer) => this.onData(b));
        this.proc.stderr.on("data", () => { /* ignore — agent doesn't surface */ });
        this.proc.on("error", (e) => this.die(e));
        this.proc.on("close", (code) => {
            this.die(new Error(`ember --serve exited (${code})`));
        });
    }

    /** Wait for the daemon's "ready" line before sending the first request.
     *  Times out after 30s — without this the client hangs forever if the
     *  daemon binary is wedged loading (huge binary + concurrent cache
     *  contention from a prior orphan, the failure mode that motivated
     *  PR_SET_PDEATHSIG on the C++ side).
     */
    private async waitReady(): Promise<void> {
        if (this.ready) return;
        if (this.deadErr) throw this.deadErr;
        await new Promise<void>((resolve, reject) => {
            const timer = setTimeout(() => {
                reject(new Error(`ember --serve handshake timeout (30s) — daemon failed to emit 'ready' line`));
                this.die(new Error("handshake timeout"));
            }, 30000);
            this.waitingReady.push(() => { clearTimeout(timer); resolve(); });
        });
        if (this.deadErr) throw this.deadErr;
    }

    private die(err: Error) {
        if (this.deadErr) return;
        this.deadErr = err;
        for (const w of this.waitingReady) w();
        this.waitingReady = [];
        for (const c of this.queue) c.reject(err);
        this.queue = [];
    }

    private onData(chunk: Buffer) {
        this.buf = Buffer.concat([this.buf, chunk]);

        // Process frames in order until we either drain the buffer or
        // a frame is partial.
        while (true) {
            if (!this.ready) {
                const nl = this.buf.indexOf(0x0a);
                if (nl < 0) return;
                const line = this.buf.subarray(0, nl).toString("utf8");
                this.buf = this.buf.subarray(nl + 1);
                if (!line.startsWith("ready ")) {
                    this.die(new Error(`unexpected daemon greeting: ${line}`));
                    return;
                }
                this.ready = true;
                for (const w of this.waitingReady) w();
                this.waitingReady = [];
                continue;
            }

            const nl = this.buf.indexOf(0x0a);
            if (nl < 0) return;
            const header = this.buf.subarray(0, nl).toString("utf8");

            if (header.startsWith("err ")) {
                const pending = this.queue.shift();
                this.buf = this.buf.subarray(nl + 1);
                if (pending) pending.reject(new Error(header.slice(4)));
                continue;
            }
            if (!header.startsWith("ok ")) {
                this.die(new Error(`malformed daemon frame: ${header.slice(0, 80)}`));
                return;
            }
            const len = parseInt(header.slice(3), 10);
            if (!Number.isFinite(len)) {
                this.die(new Error(`bad ok length: ${header}`));
                return;
            }
            // Need <header line>\n<body bytes>\n
            const totalNeeded = nl + 1 + len + 1;
            if (this.buf.length < totalNeeded) return;
            const body = this.buf.subarray(nl + 1, nl + 1 + len).toString("utf8");
            this.buf = this.buf.subarray(totalNeeded);
            const pending = this.queue.shift();
            if (pending) pending.resolve(body);
        }
    }

    async call(method: string, params: Record<string, string> = {}): Promise<string> {
        await this.waitReady();
        if (this.deadErr) throw this.deadErr;

        const parts = [method];
        for (const [k, v] of Object.entries(params)) parts.push(`${k}=${v}`);
        const line = parts.join("\t") + "\n";

        return new Promise((resolve, reject) => {
            this.queue.push({ resolve, reject });
            this.proc.stdin.write(line, (err) => {
                if (err) {
                    // The pending call gets rejected via the close
                    // handler when stdin is closed; nothing to do here
                    // beyond noting the write failed.
                    this.die(err);
                }
            });
        });
    }

    close(): void {
        if (this.deadErr) return;
        try { this.proc.stdin.end(); } catch {}
        try { this.proc.kill(); } catch {}
    }
}
