"""Ensure the output checker rejects real emission defects without executing C."""
import pathlib
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
from check_pseudocode import check_source

compiler = sys.argv[1]
valid = 'int f(int x) { if (x) goto done; x = 3; done: return x; }'
assert not check_source(valid, compiler=compiler), 'valid goto/label control flow rejected'
for source, message in [
    ('int f(void) { return t123; }', 'undeclared identifier'),
    ('int callee(int, int); int f(void) { return callee(1); }', 'too few arguments'),
    ('int callee(int); int f(void) { return callee(1, 2); }', 'too many arguments'),
    ('int f(int x) { return x; x++; }', 'never be executed'),
    ('int f(int *p) { return p->field_8; }', 'not a structure'),
]:
    diagnostics = check_source(source, compiler=compiler, filename='fixture.c')
    assert any(message in d.message and d.severity == 'error' for d in diagnostics), diagnostics
    assert all(d.file == 'fixture.c' and d.line == 1 for d in diagnostics), diagnostics
print('Output checker detects undeclared values, call arity, unreachable statements, and invalid member accesses')
