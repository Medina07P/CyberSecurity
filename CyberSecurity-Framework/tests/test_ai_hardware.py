"""Pruebas del recomendador de modelo y de la configuración del asistente IA."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

FW = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FW / "00_Config" / "lib"))

from ai import config, hardware  # noqa: E402


class HardwareTests(unittest.TestCase):
    def test_meminfo_parses_available(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "meminfo"
            p.write_text("MemTotal:  5970000 kB\nMemAvailable:  3774320 kB\n")
            self.assertAlmostEqual(hardware.read_mem_available_gib(str(p)), 3.6, delta=0.05)

    def test_meminfo_missing_returns_zero(self):
        self.assertEqual(hardware.read_mem_available_gib("/no/existe/meminfo"), 0.0)

    def test_recommend_tiers(self):
        r = hardware.recommend_model
        self.assertIn("1b", r(2.0, False).model)
        self.assertIn("3b", r(3.6, False).model)
        self.assertIn("7b", r(10, False).model)
        self.assertIn("14b", r(20, False).model)
        self.assertIn(r(4, True).model, (hardware.MODEL_3B, hardware.MODEL_7B, hardware.MODEL_14B))
        self.assertEqual(r(1.0, True).model, hardware.MODEL_3B)

    def test_pull_command_matches_model(self):
        for mem in (1, 4, 10, 20):
            rec = hardware.recommend_model(mem, False)
            self.assertEqual(rec.pull_command, f"ollama pull {rec.model}")
            self.assertTrue(rec.reason and rec.size_label)

    def test_has_nvidia_gpu_only_checks_presence(self):
        self.assertTrue(hardware.has_nvidia_gpu(which=lambda n: "/usr/bin/" + n))
        self.assertFalse(hardware.has_nvidia_gpu(which=lambda n: None))

    def _drm_tree(self, d, vendores):
        """vendores: lista de vendor-id ('0x1002', '0x10de'...) una por tarjeta."""
        drm = Path(d) / "drm"
        drm.mkdir()
        for i, vendor in enumerate(vendores):
            card = drm / f"card{i}" / "device"
            card.mkdir(parents=True)
            (card / "vendor").write_text(vendor + "\n")
        # Un conector (no una tarjeta): no debe hacer que se confunda ni truene.
        (drm / "card0-HDMI-A-1").mkdir()
        return str(drm)

    def test_has_amd_gpu_reads_pci_vendor(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertTrue(hardware.has_amd_gpu(self._drm_tree(d, ["0x1002"])))

    def test_has_amd_gpu_false_for_other_vendors(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(hardware.has_amd_gpu(self._drm_tree(d, ["0x10de", "0x8086"])))

    def test_has_amd_gpu_false_without_sysfs(self):
        self.assertFalse(hardware.has_amd_gpu("/no/existe/drm"))

    def test_recommend_with_amd_includes_rocm_caveat(self):
        rec = hardware.recommend_model(20, False, amd_gpu=True)
        self.assertIn("ROCm", rec.reason)
        self.assertIn("HSA_OVERRIDE_GFX_VERSION", rec.reason)

    def test_recommend_amd_bumps_small_memory_like_nvidia(self):
        self.assertEqual(hardware.recommend_model(1.0, False, amd_gpu=True).model,
                         hardware.MODEL_3B)
        self.assertIn("GPU AMD", hardware.recommend_model(1.0, False, amd_gpu=True).reason)

    def test_recommend_without_amd_has_no_rocm_text(self):
        self.assertNotIn("ROCm", hardware.recommend_model(20, False).reason)
        self.assertNotIn("ROCm", hardware.recommend_model(20, True).reason)


class ConfigTests(unittest.TestCase):
    def test_config_defaults_and_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "ai.yaml"
            cfg = config.load(p)
            self.assertIs(cfg["permitir_endpoint_remoto"], False)
            self.assertIs(cfg["incluir_credenciales"], False)
            for k in ("modelo", "endpoint", "contexto_max_tokens", "turnos_literales", "top_k"):
                self.assertIn(k, cfg)
            config.save_model("qwen2.5:7b", p)
            self.assertEqual(config.load(p)["modelo"], "qwen2.5:7b")
            self.assertIs(config.load(p)["permitir_endpoint_remoto"], False)

    def test_wrong_typed_value_falls_back_to_default_instead_of_crashing(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "ai.yaml"
            p.write_text("turnos_literales: cuatro\ntop_k: si\n", encoding="utf-8")
            cfg = config.load(p)
            self.assertEqual(cfg["turnos_literales"], config.DEFAULTS["turnos_literales"])
            self.assertEqual(cfg["top_k"], config.DEFAULTS["top_k"])

    def test_default_path_honors_env(self):
        old = os.environ.get("AI_CONFIG")
        try:
            os.environ["AI_CONFIG"] = "/tmp/otra/ai.yaml"
            self.assertEqual(config.default_path(), Path("/tmp/otra/ai.yaml"))
            del os.environ["AI_CONFIG"]
            self.assertEqual(config.default_path(), FW / "09_Automation" / "ai" / "ai_config.yaml")
        finally:
            if old is None:
                os.environ.pop("AI_CONFIG", None)
            else:
                os.environ["AI_CONFIG"] = old


if __name__ == "__main__":
    unittest.main()
