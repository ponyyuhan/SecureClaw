import { spawn } from "node:child_process";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";

function repoRootFromHere() {
  // This plugin lives at: <repo>/integrations/openclaw_plugin/mirage_ogpp.ts
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
}

class McpStdioClient {
  constructor({ python, repoRoot, env, logger }) {
    this._python = python;
    this._repoRoot = repoRoot;
    this._env = env;
    this._logger = logger;

    this._proc = null;
    this._rl = null;
    this._pending = new Map();
    this._nextId = 1;
    this._ready = false;
  }

  async ensureReady() {
    if (this._ready && this._proc && !this._proc.killed) return;
    await this._start();
  }

  async callTool(name, args) {
    await this.ensureReady();
    const res = await this._request("tools/call", { name, arguments: args });
    return res?.result ?? res;
  }

  async _start() {
    await this._shutdown();

    const args = ["-m", (this._env.MIRAGE_GATEWAY_HTTP_URL ? "capsule.mcp_proxy" : "gateway.mcp_server")];
    this._proc = spawn(this._python, args, {
      cwd: this._repoRoot,
      env: this._env,
      stdio: ["pipe", "pipe", "pipe"],
    });

    this._proc.on("exit", (code, signal) => {
      this._ready = false;
      const msg = `MCP child exited (code=${code}, signal=${signal})`;
      this._logger?.warn?.(msg);
      // Fail all pending requests.
      for (const { reject } of this._pending.values()) {
        reject(new Error(msg));
      }
      this._pending.clear();
    });

    // Best-effort log the child's stderr for debugging without breaking MCP stdout framing.
    this._proc.stderr.setEncoding("utf8");
    this._proc.stderr.on("data", (chunk) => {
      const s = String(chunk || "").trim();
      if (s) this._logger?.debug?.(`[secureclaw-mcp stderr] ${s}`);
    });

    this._rl = readline.createInterface({ input: this._proc.stdout });
    this._rl.on("line", (line) => this._onLine(line));

    // MCP init handshake.
    await this._request("initialize", {});
    this._notify("notifications/initialized", {});
    this._ready = true;
  }

  async _shutdown() {
    this._ready = false;
    if (this._rl) {
      try {
        this._rl.close();
      } catch {
        // ignore
      }
      this._rl = null;
    }
    if (this._proc) {
      try {
        this._proc.kill();
      } catch {
        // ignore
      }
      this._proc = null;
    }
    for (const { reject } of this._pending.values()) {
      reject(new Error("MCP client shutdown"));
    }
    this._pending.clear();
  }

  _send(obj) {
    if (!this._proc || !this._proc.stdin.writable) {
      throw new Error("MCP child process not writable");
    }
    this._proc.stdin.write(JSON.stringify(obj) + "\n");
  }

  _notify(method, params) {
    this._send({ jsonrpc: "2.0", method, params });
  }

  _request(method, params) {
    const id = this._nextId++;
    const msg = { jsonrpc: "2.0", id, method, params };
    return new Promise((resolve, reject) => {
      this._pending.set(id, { resolve, reject });
      try {
        this._send(msg);
      } catch (e) {
        this._pending.delete(id);
        reject(e);
      }
    });
  }

  _onLine(line) {
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      // Ignore non-JSON noise; MCP servers should not emit it on stdout, but be robust.
      this._logger?.debug?.(`[secureclaw-mcp] ignoring non-json: ${String(line).slice(0, 200)}`);
      return;
    }
    const id = msg?.id;
    if (id === undefined || id === null) return;
    const p = this._pending.get(id);
    if (!p) return;
    this._pending.delete(id);
    if (msg.error) {
      p.reject(new Error(msg.error?.message || "MCP error"));
      return;
    }
    p.resolve(msg);
  }
}

export default function (api) {
  const logger = api?.logger ?? console;
  const repoRoot = repoRootFromHere();

  const pluginCfg = api?.config?.plugins?.entries?.mirage_ogpp?.config ?? {};
  const python = (pluginCfg.python || process.env.MIRAGE_PYTHON || "python").trim();
  const sessionId = (pluginCfg.session_id || process.env.MIRAGE_SESSION_ID || "openclaw-session").trim();
  const gatewayHttpUrl = String(pluginCfg.gateway_http_url || process.env.MIRAGE_GATEWAY_HTTP_URL || "").trim();
  const httpToken = String(pluginCfg.http_token || process.env.MIRAGE_HTTP_TOKEN || "").trim();

  const env = {
    ...process.env,
    // Ensure the spawned gateway can import repo modules.
    PYTHONPATH: repoRoot,
    // Bind sealed handles to this session so exfiltrated handles are useless elsewhere.
    MIRAGE_SESSION_ID: sessionId,
    ...(gatewayHttpUrl ? { MIRAGE_GATEWAY_HTTP_URL: gatewayHttpUrl } : {}),
    ...(httpToken ? { MIRAGE_HTTP_TOKEN: httpToken } : {}),
  };

  const mcp = new McpStdioClient({ python, repoRoot, env, logger });

  function registerActTool(toolName: string) {
    api.registerTool(
      {
        name: toolName,
        description:
          "Execute a high-level SecureClaw intent. This forwards to the local SecureClaw MCP gateway and returns a structured observation.",
        parameters: {
          type: "object",
          // Keep only intent_id required: some providers/runtimes omit object-typed fields by default.
          required: ["intent_id"],
          properties: {
            intent_id: { type: "string", description: "High-level intent ID (e.g., ReadFile, SendMessage)." },
            inputs: { type: "object", description: "Intent inputs.", additionalProperties: true },
            constraints: { type: "object", description: "Optional constraints.", additionalProperties: true },
            caller: { type: "string", description: "Untrusted caller identity (defaults to openclaw)." },
          },
          additionalProperties: false,
        },
        execute: async (_id, params) => {
          const intentId = String(params.intent_id || "");
          const inputs = params.inputs || {};
          const constraints = params.constraints || {};
          const caller = String(params.caller || "openclaw");

          const args = { intent_id: intentId, inputs, constraints, caller };
          const res = await mcp.callTool("act", args);

          const structured = res?.structuredContent ?? res;
          const text = JSON.stringify(structured, null, 2);
          const isPolicyDeny =
            structured && typeof structured === "object" && !Array.isArray(structured) && structured.status === "DENY";
          return {
            content: [{ type: "text", text }],
            structuredContent: structured,
            // Treat policy DENY as a normal (successful) tool response so the agent can continue.
            isError: Boolean(res?.isError && !isPolicyDeny),
          };
        },
      },
      { optional: true },
    );
  }

  // New primary tool name (paper-facing), with a legacy alias for compatibility.
  registerActTool("secureclaw_act");
  registerActTool("mirage_act");
}
