"""Compare PPC instructions, integer SSA, and recompiled pseudo-C using synthetic programs."""
import argparse
from dataclasses import dataclass
import json
import pathlib
import random
import shutil
import struct
import subprocess
import tempfile

DATA, DATA_SIZE, STACK, STOP = 0x10000, 256, 0x28000, 0x120000
OBSERVE, MUTATE = 0x110000, 0x110010
MASK = 0xffffffff
NAMES = ['add_xor', 'branch_value', 'counted_sum', 'memory_overlap',
         'call_before_branch', 'call_before_store', 'two_calls', 'carry_sum']
RUN_ROOT = None
COMMAND_INDEX = 0


def run(command, **kwargs):
    global COMMAND_INDEX
    result = subprocess.run(command, text=True, capture_output=True, timeout=90, **kwargs)
    if RUN_ROOT is not None:
        stem = RUN_ROOT / f'command-{COMMAND_INDEX}'
        COMMAND_INDEX += 1
        stem.with_suffix('.json').write_text(json.dumps(command))
        stem.with_suffix('.stdout').write_text(result.stdout)
        stem.with_suffix('.stderr').write_text(result.stderr)
    if result.returncode:
        raise RuntimeError(f'{command}\n{result.stdout[-1000:]}\n{result.stderr[-4000:]}')
    return result.stdout


@dataclass(frozen=True)
class Case:
    name: str
    args: tuple[int, int, int]
    memory: bytes


def elf(path):
    data = path.read_bytes()
    assert data[:6] == b'\x7fELF\x01\x02', 'expected PPC32 big-endian ELF'
    offset = struct.unpack_from('>I', data, 32)[0]
    size, count = struct.unpack_from('>HH', data, 46)
    assert size == 40
    sections = [struct.unpack_from('>10I', data, offset + i * size) for i in range(count)]
    image = [(s[3], data[s[4]:s[4] + s[5]]) for s in sections if s[2] & 2 and s[1] != 8]
    symbols = {}
    for s in sections:
        if s[1] != 2:
            continue
        strings = sections[s[6]]
        strings = data[strings[4]:strings[4] + strings[5]]
        for pos in range(s[4], s[4] + s[5], 16):
            name, value, _, _, _, _ = struct.unpack_from('>IIIBBH', data, pos)
            name = strings[name:strings.index(0, name)].decode()
            if name:
                symbols[name] = value
    return image, symbols


def cpu_execute(program, case, limit=10000):
    from unicorn import Uc, UC_ARCH_PPC, UC_MODE_32, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.ppc_const import UC_PPC_REG_0, UC_PPC_REG_3, UC_PPC_REG_1, UC_PPC_REG_LR, UC_PPC_REG_PC, UC_PPC_REG_CR, UC_PPC_REG_XER, UC_PPC_REG_CTR
    image, symbols = program
    machine = Uc(UC_ARCH_PPC, UC_MODE_32 | UC_MODE_BIG_ENDIAN)
    machine.mem_map(0x100000, 0x21000)
    machine.mem_map(DATA, 0x1000)
    machine.mem_map(0x20000, 0x10000)
    machine.mem_write(0x20000, b'\xa5' * 0x10000)
    for address, data in image:
        assert 0x100000 <= address and address + len(data) < OBSERVE, 'fixture exceeds code area'
        machine.mem_write(address, data)
    machine.mem_write(OBSERVE, bytes.fromhex('4e800020'))
    machine.mem_write(MUTATE, bytes.fromhex('4e800020'))
    machine.mem_write(DATA, case.memory)
    for i in range(32):
        machine.reg_write(UC_PPC_REG_0 + i, 0)
    machine.reg_write(UC_PPC_REG_1, STACK)
    machine.reg_write(UC_PPC_REG_LR, STOP)
    for register in [UC_PPC_REG_CR, UC_PPC_REG_XER, UC_PPC_REG_CTR]:
        machine.reg_write(register, 0)
    for i, value in enumerate(case.args):
        machine.reg_write(UC_PPC_REG_3 + i, value)
    trace = []

    def code_hook(uc, address, size, _):
        if address not in [OBSERVE, MUTATE]:
            return
        value = uc.reg_read(UC_PPC_REG_3)
        old = int.from_bytes(uc.mem_read(DATA, 4), 'big')
        name = 'observe' if address == OBSERVE else 'mutate'
        trace.append((name, value, old))
        if address == MUTATE:
            uc.mem_write(DATA, ((old + value) & MASK).to_bytes(4, 'big'))
        # The declared helper ABI returns r3; other caller-saved GPRs are
        # intentionally poisoned so fixtures cannot rely on preservation.
        for i in [0, *range(4, 13)]:
            uc.reg_write(UC_PPC_REG_0 + i, 0xd0000000 + i)
        uc.reg_write(UC_PPC_REG_3, value ^ 0x55 if address == OBSERVE else old)

    def write_hook(uc, access, address, size, value, _):
        if not (DATA <= address and address + size <= DATA + DATA_SIZE or
                0x20000 <= address and address + size <= 0x30000):
            raise RuntimeError(f'write outside test data/stack: {address:#x}+{size}')

    machine.hook_add(UC_HOOK_CODE, code_hook)
    machine.hook_add(UC_HOOK_MEM_WRITE, write_hook)
    machine.emu_start(symbols[case.name], STOP, count=limit)
    if machine.reg_read(UC_PPC_REG_PC) != STOP:
        raise RuntimeError('PPC instruction limit exhausted')
    return machine.reg_read(UC_PPC_REG_3), bytes(machine.mem_read(DATA, DATA_SIZE)), trace


def reference(case):
    a, b, c = case.args
    memory = bytearray(case.memory)
    old = int.from_bytes(memory[:4], 'big')
    trace = []
    if case.name == 'add_xor':
        result = ((a + b) & MASK) ^ c
    elif case.name == 'branch_value':
        result = (b + (7 if a else -5)) & MASK
    elif case.name == 'counted_sum':
        result = (a * b) & MASK
    elif case.name == 'memory_overlap':
        offset = a - DATA
        memory[offset:offset + 4] = b.to_bytes(4, 'big')
        memory[offset + 2:offset + 4] = (c & 0xffff).to_bytes(2, 'big')
        result = int.from_bytes(memory[offset:offset + 4], 'big')
    else:
        if case.name == 'carry_sum':
            return ((a + b + ((a + b) >> 32)) & MASK, bytes(memory), [])
        trace.append(('observe', a, old))
        result = a ^ 0x55
        if case.name == 'call_before_branch':
            if b:
                result = 7
        elif case.name == 'call_before_store':
            memory[:4] = (9).to_bytes(4, 'big')
        elif case.name == 'two_calls':
            trace.append(('mutate', a, old))
            memory[:4] = ((old + a) & MASK).to_bytes(4, 'big')
            result = old
        else:
            raise AssertionError(case.name)
    return result, bytes(memory), trace


def parse_result(fields):
    value, memory, events = fields
    trace = [] if events == '-' else [(name, int(a), int(old)) for name, a, old in
                                     (event.split(':') for event in events.split(';'))]
    return int(value), bytes.fromhex(memory), trace


HEADER = '''
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef signed char int8_t;
typedef short int16_t;
typedef int int32_t;
typedef long long int64_t;
typedef unsigned int uintptr_t;
typedef unsigned int size_t;
typedef _Bool bool;
#define true 1
#define false 0
#define NULL ((void*)0)
extern uint32_t observe(uint32_t);
extern uint32_t mutate(uint32_t);
static uint32_t carry_add(uint32_t a, uint32_t b) { return ((uint64_t)a + b) > 0xffffffffULL; }
'''


def main(args, root):
    support = pathlib.Path(args.support)
    run([args.probe, '--self-test'])
    source = root / 'original.o'
    original = root / 'original.elf'
    run([args.clang, '--target=powerpc-linux-gnu', '-c', str(support / 'ppc_pipeline.S'), '-o', str(source)])
    link = [args.lld, '-m', 'elf32ppc', '-T', str(support / 'ppc_pipeline.ld')]
    run([*link, str(source), '-o', str(original)])
    rng = random.Random(args.seed)
    edges = [0, 1, 2, 0x7fffffff, 0x80000000, 0xfffffffe, MASK]
    triples = [(a, b, 0xa5a5a5a5) for a in edges for b in [0, 1, MASK]]
    triples += [tuple(rng.getrandbits(32) for _ in range(3)) for _ in range(32)]
    cases = []
    for name in NAMES:
        inputs = triples if name != 'counted_sum' else [(n, v, 0) for n in [0, 1, 2, 7, 16] for v in edges]
        for a, b, c in inputs:
            if name == 'memory_overlap':
                a = DATA + 32
            memory = bytes(rng.getrandbits(8) for _ in range(DATA_SIZE))
            cases.append(Case(name, (a, b, c), memory))
    transcript = ''.join(f'{c.name} {c.args[0]} {c.args[1]} {c.args[2]} {c.memory.hex()}\n' for c in cases)
    (root / 'inputs.txt').write_text(transcript)
    (root / 'seed.txt').write_text(str(args.seed))
    output = run([args.probe, str(original), str(root)], input=transcript)
    (root / 'ir-results.txt').write_text(output)
    rows = output.splitlines()
    assert len(rows) == len(cases), 'missing IR results'
    generated = root / 'generated.c'
    generated.write_text(HEADER + '\n'.join((root / (name + '.c')).read_text() for name in NAMES))
    programs = {'instructions': elf(original)}
    for optimization in [0, 2]:
        obj = root / f'generated_O{optimization}.o'
        binary = root / f'generated_O{optimization}.elf'
        run([args.clang, '--target=powerpc-linux-gnu', '-std=c11', '-ffreestanding', '-fno-builtin',
             '-fno-stack-protector', '-fno-pic', f'-O{optimization}', '-Werror=implicit-function-declaration',
             '-c', str(generated), '-o', str(obj)])
        run([*link, str(obj), '-o', str(binary)])
        programs[f'emitted_O{optimization}'] = elf(binary)
    for index, (case, line) in enumerate(zip(cases, rows)):
        fields = line.split()
        assert len(fields) == 7 and fields[0] == case.name, 'invalid IR protocol'
        expected = reference(case)
        results = {'ssa_before': parse_result(fields[1:4]), 'ssa_after': parse_result(fields[4:7])}
        for stage, program in programs.items():
            try:
                results[stage] = cpu_execute(program, case)
            except Exception as error:
                (root / 'failure.json').write_text(json.dumps({'index': index, 'seed': args.seed,
                    'function': case.name, 'args': case.args, 'stage': stage, 'error': str(error)}, indent=2))
                raise RuntimeError(f'{case.name} case {index} seed {args.seed}: {stage} failed') from error
        for stage, actual in results.items():
            if actual != expected:
                (root / 'failure.json').write_text(json.dumps({'index': index, 'seed': args.seed,
                    'function': case.name, 'args': case.args, 'stage': stage,
                    'expected': [expected[0], expected[1].hex(), expected[2]],
                    'actual': [actual[0], actual[1].hex(), actual[2]]}, indent=2))
                raise AssertionError(f'{case.name} case {index} seed {args.seed}: {stage} mismatch')
    # An emulator stopping due to its instruction budget must not count as a
    # successful return (nor compare equal to an interpreter timeout).
    try:
        cpu_execute(programs['instructions'], cases[0], limit=1)
    except RuntimeError as error:
        assert 'limit exhausted' in str(error)
    else:
        raise AssertionError('instruction-limit negative control did not fail')
    print(f'{len(cases)} PPC cases passed: instruction reference, SSA before/after cleanup, emitted C -O0/-O2; seed={args.seed}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--probe', required=True)
    parser.add_argument('--clang', required=True)
    parser.add_argument('--lld', required=True)
    parser.add_argument('--support', required=True)
    parser.add_argument('--seed', type=lambda value: int(value, 0), default=0x505043)
    args = parser.parse_args()
    try:
        import unicorn
    except ImportError:
        print('SKIP: PPC semantics requires Python unicorn >= 2 with PPC support')
        raise SystemExit(77)
    if not hasattr(unicorn, 'UC_ARCH_PPC') or not unicorn.uc_arch_supported(unicorn.UC_ARCH_PPC) or not shutil.which(args.clang) or not shutil.which(args.lld):
        print('SKIP: PPC semantics requires Unicorn PPC, clang and ld.lld')
        raise SystemExit(77)
    directory = pathlib.Path(tempfile.mkdtemp(prefix='spelunk-ppc-pipeline-'))
    RUN_ROOT = directory
    try:
        main(args, directory)
    except Exception:
        print(f'PPC failure artifacts: {directory}', flush=True)
        raise
    else:
        shutil.rmtree(directory)
