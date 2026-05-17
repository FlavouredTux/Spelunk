import stat
import tempfile
import unittest
from pathlib import Path

from emberpy import Ember, EmberError


class EmberWrapperTest(unittest.TestCase):
    def make_fake_ember(self, body):
        tmp = tempfile.TemporaryDirectory()
        path = Path(tmp.name) / "ember"
        path.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        self.addCleanup(tmp.cleanup)
        return path

    def test_builds_pseudo_command(self):
        fake = self.make_fake_ember(
            "import sys\n"
            "print('\\n'.join(sys.argv[1:]))\n"
        )
        out = Ember("target.bin", ember_bin=fake).pseudo("entry", ipa=True)
        self.assertEqual(out.splitlines(), ["-p", "-s", "entry", "--ipa", "target.bin"])

    def test_raises_on_failure(self):
        fake = self.make_fake_ember(
            "import sys\n"
            "print('bad binary', file=sys.stderr)\n"
            "sys.exit(7)\n"
        )
        with self.assertRaises(EmberError) as caught:
            Ember("missing.bin", ember_bin=fake).strings()
        self.assertEqual(caught.exception.result.returncode, 7)
        self.assertIn("bad binary", str(caught.exception))

    def test_can_return_unchecked_result(self):
        fake = self.make_fake_ember("import sys\nsys.exit(3)\n")
        result = Ember("target.bin", ember_bin=fake).run("--strings", check=False)
        self.assertFalse(result.ok)
        self.assertEqual(result.returncode, 3)

    def test_options_repeat_sequences(self):
        fake = self.make_fake_ember(
            "import sys\n"
            "print(' '.join(sys.argv[1:]))\n"
        )
        out = Ember("target.bin", ember_bin=fake).recognize(
            ["a.tsv", "b.tsv"],
            no_cache=True,
        )
        self.assertEqual(
            out.strip(),
            "--recognize --corpus a.tsv --corpus b.tsv --no-cache target.bin",
        )

    def test_function_handle_uses_address_commands(self):
        fake = self.make_fake_ember(
            "import json\n"
            "import sys\n"
            "if '--json' in sys.argv:\n"
            "    print(json.dumps({'va': '0x1041ea0d0', 'callees': []}))\n"
            "else:\n"
            "    print(' '.join(sys.argv[1:]))\n"
        )
        fn = Ember("target.bin", ember_bin=fake).function(0x1041EA0D0)
        self.assertEqual(
            fn.disasm(count=120).strip(),
            "--disasm-at 0x1041ea0d0 --count 120 target.bin",
        )
        self.assertEqual(
            fn.callees().strip(),
            "--callees 0x1041ea0d0 target.bin",
        )
        self.assertEqual(
            fn.guard_map().strip(),
            "--guard-map 0x1041ea0d0 target.bin",
        )
        self.assertEqual(
            fn.callees(json=True),
            {"va": "0x1041ea0d0", "callees": []},
        )

    def test_explain_path_returns_json_rows(self):
        fake = self.make_fake_ember(
            "import json, sys\n"
            "if '--callees' in sys.argv:\n"
            "    print(json.dumps({'va': sys.argv[sys.argv.index('--callees') + 1], 'callees': []}))\n"
            "    raise SystemExit\n"
            "addr = sys.argv[sys.argv.index('--explain-address') + 1]\n"
            "print(json.dumps({'address': addr, 'kind': 'code'}))\n"
        )
        rows = Ember("target.bin", ember_bin=fake).explain_path([0x10, 0x20])
        self.assertEqual(
            rows,
            [
                {"address": "0x10", "kind": "code", "index": 0},
                {"address": "0x20", "kind": "code", "index": 1, "previous": "0x10"},
            ],
        )

    def test_jsonable_helpers(self):
        fake = self.make_fake_ember(
            "import json, sys\n"
            "flag = next(a for a in sys.argv if a.startswith('--') and a != '--json')\n"
            "idx = sys.argv.index(flag)\n"
            "print(json.dumps({'flag': flag, 'value': sys.argv[idx + 1], 'json': '--json' in sys.argv}))\n"
        )
        e = Ember("target.bin", ember_bin=fake)
        self.assertEqual(
            e.containing_function(0x401234),
            {"flag": "--containing-fn", "value": "0x401234", "json": True},
        )
        self.assertEqual(
            e.state_lifetime(0x404000),
            {"flag": "--state-lifetime", "value": "0x404000", "json": True},
        )
        self.assertEqual(
            e.refs_to(0x5000, loose=True, json=True),
            {"flag": "--refs-to-loose", "value": "0x5000", "json": True},
        )

    def test_investigate_bundle(self):
        fake = self.make_fake_ember(
            "import json, sys\n"
            "if '-p' in sys.argv:\n"
            "    print('pseudo body')\n"
            "elif '--disasm-at' in sys.argv:\n"
            "    print('disasm body')\n"
            "else:\n"
            "    flag = next(a for a in sys.argv if a.startswith('--') and a != '--json')\n"
            "    print(json.dumps({'flag': flag}))\n"
        )
        report = Ember("target.bin", ember_bin=fake).investigate(
            0x401234,
            include_pseudo=False,
        )
        self.assertEqual(report["address"], "0x401234")
        self.assertEqual(report["disasm"], "disasm body\n")
        self.assertEqual(report["callees"], {"flag": "--callees"})
        self.assertNotIn("pseudo", report)

    def test_annotate_batch_writes_script_and_applies_it(self):
        fake = self.make_fake_ember(
            "import sys\n"
            "print(' '.join(sys.argv[1:]))\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "findings.ember"
            result = Ember("target.bin", ember_bin=fake).annotate_batch(
                script,
                [
                    {
                        "address": 0x401234,
                        "name": "http_join",
                        "note": "joins URL bits",
                        "confidence": 0.9,
                        "source": "agent:namer",
                        "evidence": "called by 0x40; string refs",
                    }
                ],
                dry_run=True,
            )
            self.assertEqual(result.stdout.strip(), f"--apply {script} --dry-run target.bin")
            self.assertIn("[rename]\n0x401234 = http_join", script.read_text(encoding="utf-8"))
            self.assertIn("[note]\n0x401234 = \"joins URL bits\"", script.read_text(encoding="utf-8"))
            self.assertIn("ev=called by 0x40, string refs", script.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
