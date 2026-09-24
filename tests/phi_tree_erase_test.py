"""A Phi-heavy compiled tree erase must render pseudocode without exploding."""
from pathlib import Path
import subprocess
import sys


exe = sys.argv[1]
fixture = Path(__file__).parent / 'support/phi_tree_erase.prebuilt'
result = subprocess.run(
    [exe, '--no-cache', '--raw-bytes', str(fixture), '--base-va', '0x145020',
     '-p', '-s', '0x145020'],
    capture_output=True, text=True, timeout=5,
)
assert result.returncode == 0, result.stderr
assert len(result.stdout.splitlines()) > 100, result.stdout
assert 'return' in result.stdout, result.stdout
