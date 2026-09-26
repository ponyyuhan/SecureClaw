"""Exercise interpreter selection without starting services or calling a model."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SOURCE_ROOT = Path(__file__).resolve().parents[1]


class McpLauncherTests(unittest.TestCase):
    def setUp(self):
        # A space in the path also exercises paths used by desktop MCP clients.
        self.tempdir = tempfile.TemporaryDirectory(prefix="secureclaw launcher ")
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        (self.root / "scripts").mkdir()
        for name in ("lib.sh", "launch_mcp_gateway.sh"):
            shutil.copy2(SOURCE_ROOT / "scripts" / name, self.root / "scripts" / name)
        self.path_bin = self.root / "path-bin"
        self.path_bin.mkdir()
        self.make_python(self.path_bin / "python", "path-python")
        self.env = os.environ.copy()
        self.env.pop("SECURECLAW_PYTHON", None)
        self.env.update(
            PATH=f"{self.path_bin}:/usr/bin:/bin",
            SECURECLAW_RUNTIME_DIR=str(self.root / "runtime"),
            SECURECLAW_LOG_DIR=str(self.root / "runtime" / "logs"),
            SECURECLAW_PID_DIR=str(self.root / "runtime" / "pids"),
        )

    def make_python(self, path, label):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"#!/bin/sh\nprintf '%s\\n' '{label}' \"$@\"\n")
        path.chmod(0o755)

    def launch(self):
        return subprocess.run(
            ["/bin/bash", str(self.root / "scripts" / "launch_mcp_gateway.sh")],
            env=self.env,
            cwd=self.root.parent,
            capture_output=True,
            text=True,
            timeout=10,
        )

    def assert_python(self, label):
        result = self.launch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [label, "-m", "gateway.mcp_server"])

    def test_repository_venv_works_without_activation(self):
        self.make_python(self.root / ".venv" / "bin" / "python", "venv-python")
        self.assert_python("venv-python")

    def test_explicit_interpreter_overrides_repository_venv(self):
        self.make_python(self.root / ".venv" / "bin" / "python", "venv-python")
        custom = self.root / "custom python"
        self.make_python(custom, "custom-python")
        self.env["SECURECLAW_PYTHON"] = str(custom)
        self.assert_python("custom-python")

    def test_without_repository_venv_preserves_path_fallback(self):
        self.assert_python("path-python")

    def test_invalid_explicit_interpreter_is_not_silently_replaced(self):
        self.env["SECURECLAW_PYTHON"] = str(self.root / "missing-python")
        result = self.launch()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("path-python", result.stdout)


if __name__ == "__main__":
    unittest.main()
