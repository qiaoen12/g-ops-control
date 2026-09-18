from __future__ import annotations

import os
import json
import tempfile
import threading
import unittest
from pathlib import Path

from ops.storage import AtomicJsonStore, RecordExists, StorageCommitUnknown, StorageError


class StorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.store = AtomicJsonStore(self.root)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_atomic_replace_round_trip_and_permissions(self) -> None:
        target = self.store.write_json("observations/one.json", {"value": "old"})
        self.assertEqual(self.store.read_json("observations/one.json"), {"value": "old"})
        self.store.write_json("observations/one.json", {"value": "new"})
        self.assertEqual(self.store.read_json("observations/one.json"), {"value": "new"})
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertFalse(any(path.name.endswith(".tmp") for path in target.parent.iterdir()))

    def test_replace_failure_preserves_old_value_and_cleans_temp(self) -> None:
        self.store.write_json("record.json", {"value": "old"})

        def fail_replace(_source: str, _target: str) -> None:
            raise OSError("injected replace failure")

        failing = AtomicJsonStore(self.root, replace_fn=fail_replace)
        with self.assertRaises(StorageError):
            failing.write_json("record.json", {"value": "new"})
        self.assertEqual(self.store.read_json("record.json"), {"value": "old"})
        self.assertEqual(list(self.root.glob(".ops-control-*.tmp")), [])

    def test_fsync_failure_before_replace_preserves_old_value(self) -> None:
        self.store.write_json("record.json", {"value": "old"})

        def fail_fsync(_fd: int) -> None:
            raise OSError("injected fsync failure")

        failing = AtomicJsonStore(self.root, fsync_fn=fail_fsync)
        with self.assertRaises(StorageError):
            failing.write_json("record.json", {"value": "new"})
        self.assertEqual(self.store.read_json("record.json"), {"value": "old"})

    def test_permission_failure_before_commit_preserves_old_value(self) -> None:
        self.store.write_json("record.json", {"value": "old"})
        replace_calls: list[tuple[str, str]] = []

        def record_replace(source: str, target: str) -> None:
            replace_calls.append((source, target))
            os.replace(source, target)

        def fail_fchmod(_fd: int, _mode: int) -> None:
            raise OSError("injected chmod failure")

        failing = AtomicJsonStore(self.root, replace_fn=record_replace, fchmod_fn=fail_fchmod)
        with self.assertRaises(StorageError):
            failing.write_json("record.json", {"value": "new"})
        self.assertEqual(replace_calls, [])
        self.assertEqual(self.store.read_json("record.json"), {"value": "old"})
        self.assertEqual(list(self.root.glob(".ops-control-*.tmp")), [])

    def test_parent_fsync_failure_after_replace_rolls_back_old_value(self) -> None:
        self.store.write_json("record.json", {"value": "old"})
        fsync_calls = 0

        def fail_parent_fsync_only(fd: int) -> None:
            nonlocal fsync_calls
            fsync_calls += 1
            if fsync_calls == 2:
                raise OSError("injected parent fsync failure")
            os.fsync(fd)

        failing = AtomicJsonStore(self.root, fsync_fn=fail_parent_fsync_only)
        with self.assertRaises(StorageError):
            failing.write_json("record.json", {"value": "new"})
        self.assertEqual(fsync_calls, 2)
        self.assertEqual(self.store.read_json("record.json"), {"value": "old"})
        self.assertEqual(list(self.root.glob(".ops-control-*.tmp")), [])

    def test_failed_rollback_reports_unknown_and_keeps_rollback_evidence(self) -> None:
        self.store.write_json("record.json", {"value": "old"})
        fsync_calls = 0
        replace_calls = 0

        def fail_parent_fsync_only(fd: int) -> None:
            nonlocal fsync_calls
            fsync_calls += 1
            if fsync_calls == 2:
                raise OSError("injected parent fsync failure")
            os.fsync(fd)

        def fail_rollback(source: str, target: str) -> None:
            nonlocal replace_calls
            replace_calls += 1
            if replace_calls == 2:
                raise OSError("injected rollback failure")
            os.replace(source, target)

        failing = AtomicJsonStore(
            self.root,
            replace_fn=fail_rollback,
            fsync_fn=fail_parent_fsync_only,
        )
        with self.assertRaises(StorageCommitUnknown):
            failing.write_json("record.json", {"value": "new"})
        self.assertEqual(self.store.read_json("record.json"), {"value": "new"})
        rollback_files = list(self.root.glob(".ops-control-rollback-*.tmp"))
        self.assertEqual(len(rollback_files), 1)
        self.assertEqual(json.loads(rollback_files[0].read_text(encoding="utf-8")), {"value": "old"})

    def test_immutable_first_creation_has_one_concurrent_winner(self) -> None:
        barrier = threading.Barrier(2)
        outcomes: list[str] = []
        outcome_lock = threading.Lock()

        def create(value: str) -> None:
            barrier.wait()
            try:
                self.store.write_once("uses/plan.json", {"winner": value})
            except RecordExists:
                result = "loser"
            else:
                result = "winner"
            with outcome_lock:
                outcomes.append(result)

        first = threading.Thread(target=create, args=("one",))
        second = threading.Thread(target=create, args=("two",))
        first.start()
        second.start()
        first.join(timeout=5)
        second.join(timeout=5)
        self.assertEqual(sorted(outcomes), ["loser", "winner"])
        self.assertIn(self.store.read_json("uses/plan.json")["winner"], {"one", "two"})

    def test_path_traversal_symlink_and_non_regular_target_fail_closed(self) -> None:
        with self.assertRaises(StorageError):
            self.store.write_json("../outside.json", {"bad": True})
        with self.assertRaises(StorageError):
            self.store.write_json("C:/outside.json", {"bad": True})
        outside = self.root.parent / "ops-control-storage-outside.json"
        try:
            outside.write_text("outside", encoding="utf-8")
            (self.root / "link.json").symlink_to(outside)
            with self.assertRaises(StorageError):
                self.store.write_json("link.json", {"bad": True})
            self.assertEqual(outside.read_text(encoding="utf-8"), "outside")
        finally:
            outside.unlink(missing_ok=True)
        (self.root / "directory").mkdir()
        with self.assertRaises(StorageError):
            self.store.write_json("directory", {"bad": True})

    def test_writable_root_is_not_accepted_as_trusted(self) -> None:
        os.chmod(self.root, 0o777)
        with self.assertRaises(StorageError):
            AtomicJsonStore(self.root)

    def test_corrupt_json_is_storage_failure_not_empty_object(self) -> None:
        corrupt = self.root / "corrupt.json"
        corrupt.write_text("{not-json", encoding="utf-8")
        with self.assertRaises(StorageError) as raised:
            self.store.read_json("corrupt.json")
        self.assertEqual(raised.exception.code, "storage_failed")

    def test_blocker_record_is_immutable_and_corruption_fails_closed(self) -> None:
        fixture = Path(__file__).parents[1] / "fixtures/contracts/valid/blocker-record.json"
        blocker = json.loads(fixture.read_text(encoding="utf-8"))
        self.store.write_immutable_record("blockers/lab-global-primary.json", "BlockerRecord", blocker)
        with self.assertRaises(RecordExists):
            self.store.write_immutable_record("blockers/lab-global-primary.json", "BlockerRecord", blocker)
        target = self.store.safe_path("blockers/lab-global-primary.json")
        target.write_text("{corrupt", encoding="utf-8")
        with self.assertRaises(StorageError):
            self.store.read_record("blockers/lab-global-primary.json", "BlockerRecord")


if __name__ == "__main__":
    unittest.main()
