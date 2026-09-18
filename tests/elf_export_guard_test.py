"""Unexpected exporter exits must fail the corpus sweep, including known gaps."""
import contextlib
import io
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import elf_export_test as sweep


class ExportGuardTest(unittest.TestCase):
    def run_sweep(self, result, gaps=None):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'sample.prebuilt').touch()
            args = SimpleNamespace(fixtures=directory, spelunk='spelunk', clang='clang')
            with patch.object(sweep, 'KNOWN_GAPS', gaps or {}), \
                 patch.object(sweep.subprocess, 'run', return_value=result), \
                 patch.object(sweep, 'check_source', return_value=[]), \
                 contextlib.redirect_stdout(io.StringIO()):
                sweep.main(args)

    def test_success(self):
        self.run_sweep(subprocess.CompletedProcess([], 0, 'int main(void) { return 0; }', ''))

    def test_unexpected_failures(self):
        for gaps in [{}, {'sample': 'documented limitation'}]:
            for code, stderr in [
                (-11, 'segmentation fault'),
                (1, 'spelunk: internal error'),
                (2, 'invalid arguments'),
                (-6, 'C export for main is incomplete: unresolved intrinsic'),
            ]:
                with self.subTest(gaps=gaps, code=code), self.assertRaises(AssertionError):
                    self.run_sweep(subprocess.CompletedProcess([], code, '', stderr), gaps)

    def test_known_gap(self):
        result = subprocess.CompletedProcess(
            [], 1, '', 'C export for main is incomplete: unresolved intrinsic')
        self.run_sweep(result, {'sample': 'documented limitation'})
        with self.assertRaises(AssertionError):
            self.run_sweep(result)
        result.stdout = 'partial C'
        with self.assertRaises(AssertionError):
            self.run_sweep(result, {'sample': 'documented limitation'})

    def test_fixed_gap(self):
        with self.assertRaises(AssertionError):
            self.run_sweep(subprocess.CompletedProcess([], 0, 'int main(void) {}', ''),
                           {'sample': 'documented limitation'})


if __name__ == '__main__':
    unittest.main()
