import datetime
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import traceback
import xml.etree.ElementTree as ET

p = pathlib.Path.cwd()
e = p / 'native-evidence'
e.mkdir(exist_ok=True)
head = os.environ['HEAD_SHA']
base = os.environ['BASE_SHA']
production = 'Ghidra/Features/Decompiler/src/decompile/cpp/interface.cc'
fixture = 'Ghidra/Features/Decompiler/src/decompile/unittests/testinterfaceleaf.cc'
cpp = p / 'Ghidra/Features/Decompiler/src/decompile/cpp'
failures = {
    'interface_leaf_save_argument', 'interface_leaf_print_c_argument',
    'interface_leaf_print_inputs_argument', 'interface_leaf_callgraph_argument',
    'interface_leaf_whitespace_rewind', 'interface_leaf_terminal_completion',
}
new_cases = failures | {
    'interface_child_save_signatures', 'interface_child_print_flat',
    'interface_child_print_globals', 'interface_child_print_types',
    'interface_child_print_xml', 'interface_child_print_inputs_all',
    'interface_child_callgraph_quick', 'interface_leaf_eof_controls',
    'interface_ambiguous_prefix_control', 'interface_invalid_prefix_control',
    'interface_child_abbreviation_control', 'interface_child_completion_control',
}
r = {'head': head, 'base': base, 'status': 'running', 'steps': [],
     'native_result_format': 'Original C++ UnitTest logs, not JUnit XML'}


def sha(content):
    return hashlib.sha256(content).hexdigest()


def save():
    (e / 'receipt.json').write_text(json.dumps(r, indent=2) + '\n')


def git_bytes(ref, path):
    return subprocess.check_output(['git', 'show', ref + ':' + path])


def run(label, args, **kwargs):
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with (e / (label + '.log')).open('w') as output:
        result = subprocess.run(args, stdout=output, stderr=subprocess.STDOUT,
                                timeout=3600, **kwargs)
    r['steps'].append({'label': label, 'args': args, 'exit_code': result.returncode,
                      'started_at': started,
                      'ended_at': datetime.datetime.now(datetime.timezone.utc).isoformat()})
    save()
    return result.returncode


def clean():
    paths = subprocess.check_output(['git', 'diff', '--name-only', 'HEAD'],
                                    text=True).splitlines()
    r['final_dirty_paths'] = paths
    save()
    assert not paths


def preserve_xml_parser():
    path = 'Ghidra/Features/Decompiler/src/decompile/cpp/xml.cc'
    original = git_bytes(base, path)
    assert (p / path).read_bytes() == original
    os.utime(p / path, None)
    assert (p / path).stat().st_mtime >= (cpp / 'xml.y').stat().st_mtime
    return original


def build(label, unit=True):
    parser = preserve_xml_parser()
    assert run(label + '-console-build', ['make', '-j2', 'decomp_opt'], cwd=cpp) == 0
    if unit:
        assert run(label + '-unit-build', ['make', '-j2', 'decomp_test_dbg'], cwd=cpp) == 0
    assert (cpp / 'xml.cc').read_bytes() == parser
    r[label + '_xml_parser_sha256'] = sha(parser)
    r[label + '_console_sha256'] = sha((cpp / 'decomp_opt').read_bytes())
    save()


def unit_phase(label, expected_failures):
    code = run(label + '-native-units', [str(cpp / 'decomp_test_dbg'),
               '-sleighpath', str(p), 'unittests'], cwd=cpp)
    text = (e / (label + '-native-units.log')).read_text()
    rows = []
    for chunk in re.split(r'^testing : ', text, flags=re.MULTILINE)[1:]:
        name, body = chunk.split(' ...\n', 1)
        failed = re.search(r'^  fail(?:\n|:)', body, re.MULTILINE) is not None
        passed = re.search(r'^  passed\.$', body, re.MULTILINE) is not None
        assert failed != passed
        if failed:
            assert name in expected_failures
            assert 'ERROR: Invalid command' in body
            assert 'INTERFACE_DISPATCH executed=0 command=' in body
            assert 'asserting "0 == 1"' in body
        rows.append({'name': name, 'failed': failed})
    r[label + '_native_units'] = {'exit_code': code, 'cases': rows}
    save()
    assert len(rows) == 223 and len({row['name'] for row in rows}) == 223
    assert {row['name'] for row in rows} == original_cases | new_cases
    assert {row['name'] for row in rows if row['failed']} == expected_failures
    assert code == len(expected_failures)
    assert str(223 - len(expected_failures)) + '/223 tests passed.' in text
    for path, content in original_sources.items():
        assert (p / path).read_bytes() == content


def console(label, commands):
    (e / (label + '-input.txt')).write_text(commands)
    code = run(label, [str(cpp / 'decomp_opt')], input=commands, text=True,
               cwd=e, env=dict(os.environ, SLEIGHHOME=str(p)))
    output = (e / (label + '.log')).read_text()
    assert code == 0
    return output


def check_main(output, count):
    assert output.count('Decompiling main') == count
    assert output.count('Decompilation complete') == count
    assert len(re.findall(r'return\s+(?:42|0x2a)\s*;', output, re.IGNORECASE)) == count
    addresses = re.findall(r'Function main: 0x([0-9a-fA-F]+)', output)
    assert len(addresses) == count and all(int(address, 16) == main_address for address in addresses)


def valid_state(path):
    assert path.is_file() and path.stat().st_size > 0
    assert ET.parse(path).getroot().tag == 'bfd_savefile'
    return sha(path.read_bytes())


def legacy(label):
    # An authentic fixed public save supplies the seed; no XML is manufactured.
    # The unchanged original console then exercises its existing restore syntax.
    before = (e / 'state').stat().st_mtime_ns
    cycle = 'load function main\ndecompile\nprint C\n'
    commands = ('restore state ignored.xml\n' + cycle +
                'restore state\n' + cycle + 'restore\n' + cycle + 'save\nquit\n')
    output = console(label, commands)
    assert output.count('successfully loaded:') == 3
    assert not re.search(r'ERROR|error:', output)
    check_main(output, 3)
    assert not (e / 'ignored.xml').exists()
    assert (e / 'state').stat().st_mtime_ns > before
    r[label + '_state_sha256'] = valid_state(e / 'state')
    r[label + '_verified'] = True
    save()


try:
    assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() == head
    assert set(subprocess.check_output(['git', 'diff', '--name-only', base, head],
                                      text=True).splitlines()) == {production, fixture}
    clean()
    original_sources = {}
    original_cases = set()
    for path in subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', base,
                'Ghidra/Features/Decompiler/src/decompile/unittests'], text=True).splitlines():
        if path.endswith('.cc'):
            content = git_bytes(base, path)
            assert (p / path).read_bytes() == content
            names = re.findall(r'^TEST\((\w+)\)', content.decode(), re.MULTILINE)
            assert not original_cases.intersection(names)
            original_cases.update(names)
            original_sources[path] = content
    assert len(original_sources) == 7 and len(original_cases) == 205
    assert set(re.findall(r'^TEST\((\w+)\)', (p / fixture).read_text(), re.MULTILINE)) == new_cases
    r['original_source_sha256'] = {path: sha(content) for path, content in original_sources.items()}
    original = git_bytes(base, production)
    fixed = git_bytes(head, production)
    assert (p / production).read_bytes() == fixed and fixed != original
    g = ['./gradlew', '--no-daemon', '--max-workers=2',
         '-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
    assert run('bfd-package-version', ['dpkg-query', '-W', 'binutils-dev']) == 0
    assert run('fetch', g + ['-I', 'gradle/support/fetchDependencies.gradle',
                            '-DhideDownloadProgress', '-DnoEclipse']) == 0
    assert run('prep', g + ['prepDev']) == 0
    assert run('actual-original-unit-languages', g + [':x86:sleighCompile', ':Toy:sleighCompile',
               ':PowerPC:sleighCompile', ':MIPS:sleighCompile', ':AARCH64:sleighCompile']) == 0
    (e / 'fixture.c').write_text('int main(void) { return 42; }\n')
    binary = e / 'fixture'
    assert run('fixture-compile', ['gcc', '-O0', '-fno-pie', '-no-pie', '-o',
                                 str(binary), str(e / 'fixture.c')]) == 0
    assert run('fixture-symbols', ['nm', str(binary)]) == 0
    symbol = re.search(r'^([0-9a-fA-F]+) T main$', (e / 'fixture-symbols.log').read_text(), re.MULTILINE)
    assert symbol is not None
    main_address = int(symbol.group(1), 16)
    r['elf_sha256'] = sha(binary.read_bytes())
    prefix = ('load file ' + str(binary) + '\nread symbols\nload function main\n'
              'decompile\nprint C\n')
    (p / production).write_bytes(original)
    assert (p / production).read_bytes() == original
    r['baseline_production_sha256'] = sha((p / production).read_bytes())
    build('baseline')
    unit_phase('baseline', failures)
    baseline_state = e / 'baseline-state.xml'
    assert not baseline_state.exists()
    output = console('baseline-save', prefix + 'save ' + str(baseline_state) + '\nquit\n')
    check_main(output, 1)
    assert output.count('ERROR: Invalid command') == 1 and not baseline_state.exists()
    r['baseline_public_save_failed_as_expected'] = True
    assert (p / production).read_bytes() == original
    (p / production).write_bytes(fixed)
    r['fixed_production_sha256'] = sha((p / production).read_bytes())
    build('fixed')
    assert r['baseline_console_sha256'] != r['fixed_console_sha256']
    unit_phase('fixed', set())
    state = e / 'state.xml'
    cycle = 'load function main\ndecompile\nprint C\n'
    commands = (prefix + 'save ' + str(state) + '\nrestore ' + str(state) + '\n' +
                cycle + 'save\nrestore\n' + cycle + 'save\nquit\n')
    output = console('fixed-public-roundtrip', commands)
    assert output.count('successfully loaded:') == 3 and not re.search(r'ERROR|error:', output)
    check_main(output, 3)
    r['fixed_public_state_sha256'] = valid_state(state)
    r['fixed_public_roundtrip_verified'] = True
    assert not (e / 'ignored.xml').exists()
    shutil.copyfile(state, e / 'state')
    legacy('fixed-legacy')
    (p / production).write_bytes(original)
    build('original-legacy', unit=False)
    assert (p / production).read_bytes() == original
    legacy('original-legacy')
    (p / production).write_bytes(fixed)
    build('final-fixed', unit=False)
    assert (p / production).read_bytes() == fixed
    for path, content in original_sources.items():
        assert (p / path).read_bytes() == content
    clean()
    assert run('full-build', g + ['buildGhidra']) == 0
    assert 'BUILD SUCCESSFUL' in (e / 'full-build.log').read_text()
    assert (p / production).read_bytes() == fixed
    clean()
    r['status'] = 'passed'
except Exception as error:
    r['status'] = 'failed'
    r['error'] = str(error)
    r['traceback'] = traceback.format_exc()
    raise
finally:
    save()
