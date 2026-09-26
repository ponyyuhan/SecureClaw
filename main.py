import argparse
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SCRIPTS = ROOT / "scripts"


def _run(cmd: list[str]) -> int:
    return int(subprocess.run(cmd, cwd=ROOT, check=False).returncode)


def _run_script(name: str, extra: list[str] | None = None) -> int:
    cmd = ["bash", str(SCRIPTS / name)]
    if extra:
        cmd.extend(extra)
    return _run(cmd)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="secureclaw")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("build-dbs", help="Build policy bitset databases.")
    sub.add_parser("policy-server", help="Run one policy server (configure via env SERVER_ID/PORT/DATA_DIR).")
    sub.add_parser("executor-server", help="Run the executor server.")
    sub.add_parser("mcp-gateway", help="Run the SecureClaw MCP gateway over stdio.")
    sub.add_parser("http-gateway", help="Run the SecureClaw HTTP gateway.")
    sub.add_parser("dev-up", help="Start local policy0/policy1/executor/http-gateway.")
    sub.add_parser("dev-down", help="Stop locally started services.")
    sub.add_parser("health", help="Check local service health.")
    sub.add_parser("validate", help="Run the local runtime validation suite (expects the local stack to be up).")

    p_agent = sub.add_parser("agent-demo", help="Run the local Python agent demo.")
    p_agent.add_argument("mode", nargs="?", default="both", choices=["benign", "malicious", "both"])

    p_nanoclaw = sub.add_parser("nanoclaw", help="Run the NanoClaw/Claude Agent SDK demo.")
    p_nanoclaw.add_argument("mode", nargs="?", default="both", choices=["benign", "malicious", "both"])

    p_openclaw = sub.add_parser("openclaw", help="Run one OpenClaw prompt through the SecureClaw plugin bridge.")
    p_openclaw.add_argument("--message", default="", help="Prompt to send to OpenClaw.")
    p_openclaw.add_argument("--session-id", default="secureclaw-openclaw", help="OpenClaw session id.")

    args = p.parse_args(argv)

    if args.cmd == "build-dbs":
        return _run([sys.executable, "-m", "policy_server.build_dbs"])
    if args.cmd == "policy-server":
        return _run([sys.executable, "-m", "policy_server.server"])
    if args.cmd == "executor-server":
        return _run([sys.executable, "-m", "executor_server.server"])
    if args.cmd == "mcp-gateway":
        return _run([sys.executable, "-m", "gateway.mcp_server"])
    if args.cmd == "http-gateway":
        return _run([sys.executable, "-m", "gateway.http_server"])
    if args.cmd == "dev-up":
        return _run_script("dev_up.sh")
    if args.cmd == "dev-down":
        return _run_script("dev_down.sh")
    if args.cmd == "health":
        return _run_script("check_health.sh")
    if args.cmd == "validate":
        return _run([sys.executable, "scripts/validate_runtime.py"])
    if args.cmd == "agent-demo":
        return _run_script("run_agent_demo.sh", [args.mode])
    if args.cmd == "nanoclaw":
        return _run_script("run_nanoclaw.sh", [args.mode])
    if args.cmd == "openclaw":
        extra = ["--session-id", args.session_id]
        if args.message:
            extra.extend(["--message", args.message])
        return _run_script("run_openclaw.sh", extra)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
