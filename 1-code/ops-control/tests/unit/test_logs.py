from __future__ import annotations

import io
import unittest
from pathlib import Path

from ops.logs import LogError, SecurityLogger, load_logging_policy
from ops.models import new_uuid, utc_now


POLICY = Path(__file__).parents[2] / "../../2-infra/ops-control/policy/logging.yml"


class LoggingTests(unittest.TestCase):
    def test_policy_is_an_allowlist_and_safe_event_is_emitted(self) -> None:
        policy = load_logging_policy(POLICY)
        self.assertEqual(policy["schema_version"], 1)
        sink = io.StringIO()
        logger = SecurityLogger(POLICY, sink=sink)
        event = logger.emit({"event": "doctor", "stage": "offline", "generated_at": utc_now(), "request_id": new_uuid()})
        self.assertEqual(event["event"], "doctor")
        self.assertIn('"event":"doctor"', sink.getvalue())

    def test_unknown_field_is_rejected_before_sink(self) -> None:
        sink = io.StringIO()
        logger = SecurityLogger(POLICY, sink=sink)
        with self.assertRaises(LogError):
            logger.emit({"event": "doctor", "stage": "offline", "generated_at": utc_now(), "raw_exception": "do not log"})
        self.assertEqual(sink.getvalue(), "")
        self.assertEqual(logger.events, [])

    def test_secret_sentinel_is_rejected_before_sink(self) -> None:
        sink = io.StringIO()
        logger = SecurityLogger(POLICY, sink=sink)
        with self.assertRaises(LogError):
            logger.emit({"event": "doctor", "stage": "offline", "generated_at": utc_now(), "error_code": "FAKE_SECRET_SENTINEL"})
        self.assertEqual(sink.getvalue(), "")
        self.assertNotIn("FAKE_SECRET_SENTINEL", sink.getvalue())

    def test_bad_ids_and_timestamps_are_rejected(self) -> None:
        logger = SecurityLogger(POLICY)
        with self.assertRaises(LogError):
            logger.emit({"event": "doctor", "stage": "offline", "generated_at": "2026-09-10T00:00:00+08:00"})
        with self.assertRaises(LogError):
            logger.emit({"event": "doctor", "stage": "offline", "generated_at": "2024-02-30T00:00:00Z"})
        with self.assertRaises(LogError):
            logger.emit({"event": "doctor", "stage": "offline", "generated_at": utc_now(), "request_id": "not-a-uuid"})


if __name__ == "__main__":
    unittest.main()
