import hashlib
import json
import os
import pathlib
import re
import subprocess
import traceback

p = pathlib.Path.cwd()
e = p / 'native-evidence'
e.mkdir(exist_ok=True)
head = os.environ['HEAD_SHA']
base = os.environ['BASE_SHA']
test_path = 'Ghidra/Features/Decompiler/src/decompile/unittests/testinterfaceleaf.cc'
expected = {
    'interface_leaf_save_argument', 'interface_leaf_print_c_argument',
    'interface_leaf_print_inputs_argument', 'interface_leaf_callgraph_argument',
    'interface_leaf_whitespace_rewind', 'interface_leaf_terminal_completion',
    'interface_child_save_signatures', 'interface_child_print_flat',
    'interface_child_print_globals', 'interface_child_print_types',
    'interface_child_print_xml', 'interface_child_print_inputs_all',
    'interface_child_callgraph_quick', 'interface_leaf_eof_controls',
    'interface_ambiguous_prefix_control', 'interface_invalid_prefix_control',
    'interface_child_abbreviation_control', 'interface_child_completion_control',
}
failures = {name for name in expected if name.startswith('interface_leaf_')} - {
    'interface_leaf_eof_controls'}
r = {'head': head, 'base': base, 'status': 'INCONCLUSIVE',
     'publication_gate': False, 'production_unchanged': True,
     'full_build_passed': False, 'steps': []}


def save():
    (e / 'receipt.json').write_text(json.dumps(r, indent=2) + '\n')


def run(label, args, **kwargs):
    with (e / (label + '.log')).open('w') as output:
        result = subprocess.run(args, stdout=output, stderr=subprocess.STDOUT,
                                timeout=1800, **kwargs)
    r['steps'].append({'label': label, 'args': args, 'exit_code': result.returncode})
    save()
    return result.returncode


try:
    assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() == head
    assert subprocess.check_output(['git', 'diff', '--name-only', base, head],
                                   text=True).splitlines() == [test_path]
    assert not subprocess.check_output(['git', 'diff', '--name-only', 'HEAD'], text=True).strip()
    fixture = p / test_path
    assert set(re.findall(r'^TEST\((\w+)\)', fixture.read_text(), re.MULTILINE)) == expected
    assert len(expected) == 18 and len(failures) == 6
    assert pathlib.Path('/usr/include/bfd.h').is_file()
    assert run('bfd-package-version', ['dpkg-query', '-W', 'binutils-dev']) == 0
    cpp = p / 'Ghidra/Features/Decompiler/src/decompile/cpp'
    assert run('actual-unit-build', ['make', '-j2', 'decomp_test_dbg'], cwd=cpp) == 0
    executable = cpp / 'decomp_test_dbg'
    r['native_executable_sha256'] = hashlib.sha256(executable.read_bytes()).hexdigest()
    r['fixture_sha256'] = hashlib.sha256(fixture.read_bytes()).hexdigest()
    code = run('actual-native-matrix', [str(executable), '-sleighpath', str(p),
                                      'unittests'] + sorted(expected), cwd=cpp)
    text = (e / 'actual-native-matrix.log').read_text()
    rows = []
    for chunk in re.split(r'^testing : ', text, flags=re.MULTILINE)[1:]:
        name, body = chunk.split(' ...\n', 1)
        assert name in expected
        failed = re.search(r'^  fail(?:\n|:)', body, re.MULTILINE) is not None
        passed = re.search(r'^  passed\.$', body, re.MULTILINE) is not None
        assert failed != passed
        if failed:
            assert name in failures
            assert 'ERROR: Invalid command' in body
            assert 'INTERFACE_DISPATCH executed=0 command=' in body
            assert 'asserting "0 == 1"' in body
        rows.append({'name': name, 'failed': failed})
    r['cases'] = rows
    save()
    assert len(rows) == 18 and {row['name'] for row in rows} == expected
    assert {row['name'] for row in rows if row['failed']} == failures
    assert code == 6 and '12/18 tests passed.' in text
    assert not subprocess.check_output(['git', 'diff', '--name-only', 'HEAD'], text=True).strip()
    r['status'] = 'REPRODUCED_SIX_PUBLIC_LEAF_ARGUMENT_FAILURES'
except Exception as error:
    r['error'] = str(error)
    r['traceback'] = traceback.format_exc()
    raise
finally:
    save()
