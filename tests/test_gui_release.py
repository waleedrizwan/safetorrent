"""Tests for the GUI's automatic release: only CLEAN downloads that asked for it
are copied to the Mac, and each only once. The VM and CLI are mocked out."""
import unittest
from unittest import mock

from test_server import ServerBase

ID = "abcdef0123"


class Stop(Exception):
    pass


class SyncThread:
    """Runs a worker's background job right away so the test can see its effect."""

    def __init__(self, target, daemon=None):
        self.target = target

    def start(self):
        self.target()


def item(status="scanned", verdict="CLEAN", auto=True, id=ID):
    return {"id": id, "status": status, "auto_release": auto, "scan": {"verdict": verdict} if verdict else None}


class AutoRelease(ServerBase):
    def setUp(self):
        super().setUp()
        State = self.srv.State
        State.auto_released = set()
        State.items = []
        mock.patch.object(self.srv, "vm_status", return_value="Running").start()
        self.release = mock.patch.object(self.srv, "release").start()
        self.wake = mock.patch.object(State, "wake").start()

    def tick(self, items=None, n=1):
        """Run the items worker for n passes over the given download list."""
        if items is not None:
            self.srv.State.items = items
        self.wake.wait.side_effect = [None] * (n - 1) + [Stop()]
        # Only during the tick: the test HTTP server needs real threads.
        with mock.patch.object(self.srv.threading, "Thread", SyncThread), self.assertRaises(Stop):
            self.srv.items_worker()

    def released(self):
        return [c.args[0] for c in self.release.call_args_list]

    def test_clean_released_once(self):
        self.tick([item()], n=3)
        self.assertEqual(self.released(), [ID])

    def test_risky_verdicts_never_auto_released(self):
        for verdict in ("WARNING", "SUSPICIOUS", "INFECTED", None):
            with self.subTest(verdict):
                self.tick([item(verdict=verdict)])
                self.assertEqual(self.released(), [])

    def test_only_when_asked_and_finished(self):
        self.tick([item(auto=False), item(status="released", id="abcdef0124"),
                   item(status="scanning", id="abcdef0125"), item(status="downloaded", id="abcdef0126")])
        self.assertEqual(self.released(), [])

    def test_failed_release_is_not_retried_in_a_loop(self):
        self.release.side_effect = RuntimeError("copy failed")
        with mock.patch.object(self.srv.traceback, "print_exc"):
            self.tick([item()], n=3)
        self.assertEqual(self.released(), [ID])

    def test_deleting_allows_a_fresh_copy_to_auto_release(self):
        self.tick([item()])
        status, _body, _res = self.request("POST", f"/api/items/{ID}/delete", {})
        self.assertEqual(status, 200)
        self.guest.assert_any_call("purge", ID)
        self.tick([item()])
        self.assertEqual(self.released(), [ID, ID])

    def test_manual_release_stops_a_later_auto_release(self):
        self.request("POST", f"/api/items/{ID}/release", {})
        self.tick([item()])
        self.assertEqual(self.released(), [ID])

    def test_vpn_failure_rechecks_health(self):
        self.srv.State.items = [item(status="downloading", verdict=None)]
        self.srv.refresh_items.side_effect = lambda: setattr(
            self.srv.State, "items", [item(status="vpn-failed", verdict=None)])
        self.tick()
        self.srv.refresh_health.assert_called()

    def test_vm_stopped_does_nothing(self):
        self.srv.vm_status.return_value = "Stopped"
        self.tick([item()])
        self.assertEqual(self.released(), [])


if __name__ == "__main__":
    unittest.main()
