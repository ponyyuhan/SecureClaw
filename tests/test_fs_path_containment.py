import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from gateway.executors import fsexec
from gateway.handles import HandleStore


class FSPathContainmentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve() / "demo_data"
        self.root.mkdir()
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.enterContext(patch.object(fsexec, "DEMO_ROOT", self.root))
        self.enterContext(patch.object(fsexec, "SM_DISABLED", False))
        self.enterContext(patch.dict(os.environ, {
            "HANDLE_DB_PATH": "",
            "MIRAGE_HANDLEIZE_FS_OUTPUT": "1",
        }))
        self.handles = HandleStore()
        self.executor = fsexec.FSExec(self.handles)

    def test_demo_read_rejects_sibling_with_same_name_prefix(self):
        sibling = self.root.with_name("demo_data_neighbor")
        sibling.mkdir()
        target = sibling / "outside.txt"
        target.write_text("outside demo root")
        for path in ("../demo_data_neighbor/outside.txt", str(target)):
            with self.subTest(path=path):
                result = self.executor.read_file({"path_spec": path}, "test")
                self.assertEqual(result["status"], "DENY")
                self.assertEqual(result["reason_code"], "READFILE_ERROR")
                self.assertEqual(result["artifacts"], [])

    def test_workspace_read_rejects_sibling_with_same_name_prefix(self):
        sibling = self.root / "workspace_neighbor"
        sibling.mkdir()
        target = sibling / "outside.txt"
        target.write_text("outside workspace")
        for path in ("../workspace_neighbor/outside.txt", str(target)):
            with self.subTest(path=path):
                result = self.executor.read_workspace_file({"relpath": path}, "test")
                self.assertEqual(result["status"], "DENY")
                self.assertEqual(result["reason_code"], "WORKSPACE_PATH_BLOCKED")
                self.assertEqual(result["artifacts"], [])

    def test_workspace_write_rejects_sibling_with_same_name_prefix(self):
        sibling = self.root / "workspace_neighbor"
        sibling.mkdir()
        target = sibling / "outside.txt"
        target.write_text("unchanged")
        for path in ("../workspace_neighbor/outside.txt", str(target)):
            with self.subTest(path=path):
                result = self.executor.write_workspace_file(
                    {"relpath": path, "content": "must not be written"}, "test"
                )
                self.assertEqual(result["status"], "DENY")
                self.assertEqual(result["reason_code"], "WORKSPACE_PATH_BLOCKED")
                self.assertEqual(target.read_text(), "unchanged")

    def test_in_root_write_and_reads_preserve_opaque_handles(self):
        written = self.executor.write_workspace_file(
            {"relpath": "note.txt", "content": "allowed content"}, "test"
        )
        self.assertEqual(written["status"], "OK")
        self.assertEqual((self.workspace / "note.txt").read_text(), "allowed content")
        reads = [
            self.executor.read_workspace_file({"relpath": "note.txt"}, "test"),
            self.executor.read_file({"path_spec": "workspace/note.txt"}, "test"),
        ]
        for result in reads:
            self.assertEqual(result["status"], "OK")
            self.assertEqual(result["reason_code"], "HANDLE_RETURNED")
            self.assertNotIn("content", result["data"])
            record = self.handles.get(result["artifacts"][0]["handle"])
            self.assertEqual(record.value["content"], "allowed content")


if __name__ == "__main__":
    unittest.main()
