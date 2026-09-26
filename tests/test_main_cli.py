from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


class MainCliTests(unittest.TestCase):
    def test_build_dbs_keeps_invoking_interpreter_when_path_has_another_python(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copyfile(Path(__file__).resolve().parents[1] / "main.py", root / "main.py")
            package = root / "policy_server"
            package.mkdir()
            (package / "__init__.py").write_text("")
            (package / "build_dbs.py").write_text("import sys\nprint(sys.executable)\n")
            wrong_python = root / "python"
            wrong_python.write_text("#!/bin/sh\necho wrong-interpreter\nexit 73\n")
            wrong_python.chmod(0o755)
            env = dict(os.environ, PATH=str(root), PYTHONPATH="")
            result = subprocess.run(
                [sys.executable, str(root / "main.py"), "build-dbs"],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            self.assertEqual(result.stdout.strip(), sys.executable)


if __name__ == "__main__":
    unittest.main()
