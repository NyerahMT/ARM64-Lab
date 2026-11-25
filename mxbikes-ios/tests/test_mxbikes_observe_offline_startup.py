import importlib.util
from pathlib import Path
import unittest

script = Path(__file__).resolve().parents[1] / "scripts/mxbikes_observe_offline_startup.py"
spec = importlib.util.spec_from_file_location("observe_startup", script)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class OfflineObservationTests(unittest.TestCase):
    def sample(self, tasks, code=None):
        return m.observe(tasks, "mxbikes.exe", 42, 1.0, code)

    def test_parse_csv(self):
        self.assertEqual(m.parse_tasks('"Steam.EXE","23","Console","1","1,000 K"\n'
                                      '"mxbikes.exe","42","Console","1","2,000 K"\n'),
                         {23: "steam.exe", 42: "mxbikes.exe"})

    def test_reject_unusable_process_snapshot(self):
        with self.assertRaises(RuntimeError):
            m.parse_tasks("ERROR: unavailable")

    def test_steam_relaunch_detected_even_if_later_absent(self):
        x = m.summarize([self.sample({42: "mxbikes.exe", 23: "steam.exe"}),
                         self.sample({42: "mxbikes.exe"})])
        self.assertEqual(x["classification"], "steam_client_observed_during_launch")
        self.assertIsNone(x["actual_menu_rendered"])

    def test_steam_service_alone_not_client(self):
        x = m.summarize([self.sample({42: "mxbikes.exe", 12: "steamservice.exe"})])
        self.assertEqual(x["classification"], "game_process_alive_without_observed_steam_client")
        self.assertFalse(x["steam_seen"])
        self.assertIsNone(x["actual_engine_initialized"])

    def test_game_exits_without_client(self):
        x = m.summarize([self.sample({42: "mxbikes.exe"}), self.sample({}, 3)])
        self.assertEqual(x["classification"], "initial_process_exited_without_observed_steam_client")
        self.assertEqual(x["initial_exit_code"], 3)

    def test_inconclusive(self):
        self.assertEqual(m.summarize([self.sample({})])["classification"], "inconclusive")

    def test_empty_samples(self):
        with self.assertRaises(ValueError):
            m.summarize([])


if __name__ == "__main__":
    unittest.main()
