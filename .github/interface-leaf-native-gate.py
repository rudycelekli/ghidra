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
codec = 'Ghidra/Features/Decompiler/src/decompile/cpp/database.cc'
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


def local_symbols(path, function, empty):
    valid_state(path)
    functions = [node for node in ET.parse(path).getroot().iter('function')
                 if node.get('name') == function]
    assert len(functions) == 1
    scope = functions[0].find('localdb/scope')
    assert scope is not None
    symbols = scope.find('symbollist')
    if empty:
        assert symbols is None
    else:
        assert symbols is not None and len(symbols.findall('mapsym')) > 0
        assert any(node.get('name') == 'mapped_value' for node in symbols.iter('symbol'))


def helper_body(output):
    assert output.count('Decompiling helper') == 1
    assert output.count('Decompilation complete') == 1
    address = re.search(r'Function helper: 0x([0-9a-fA-F]+)', output)
    assert address is not None and int(address.group(1), 16) == helper_address
    body = re.search(r'(?ms)^[^\n]*\bhelper\([^\n]*\)\s*\n\s*\{\n.*?^\}', output)
    assert body is not None and re.search(r'\b(?:0x2a|42)\b', body.group(0), re.IGNORECASE)
    return body.group(0)


def set_sources(label, parser_fixed, codec_fixed):
    for path, use_fixed in [(production, parser_fixed), (codec, codec_fixed)]:
        content = fixed_sources[path] if use_fixed else original_sources_production[path]
        (p / path).write_bytes(content)
        assert (p / path).read_bytes() == content
    r[label + '_production_sha256'] = {path: sha((p / path).read_bytes())
                                      for path in original_sources_production}
    save()


def legacy(label, seed):
    # An authentic public read-symbols-only save supplies function shells.  This
    # isolates established restore syntax from the separately reproduced empty
    # local-scope decoder defect.  Both consoles decompile the real main body.
    shutil.copyfile(seed, e / 'state')
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
                                      text=True).splitlines()) == {production, codec, fixture}
    clean()
    for name in ('com_opt', 'test_dbg', 'decomp_opt', 'decomp_test_dbg'):
        assert not (cpp / name).exists(), 'Standalone outputs must originate in this harness'
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
    original_sources_production = {path: git_bytes(base, path) for path in [production, codec]}
    fixed_sources = {path: git_bytes(head, path) for path in [production, codec]}
    for path in original_sources_production:
        assert (p / path).read_bytes() == fixed_sources[path]
        assert fixed_sources[path] != original_sources_production[path]
    g = ['./gradlew', '--no-daemon', '--max-workers=2',
         '-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
    assert run('bfd-package-version', ['dpkg-query', '-W', 'binutils-dev']) == 0
    assert run('fetch', g + ['-I', 'gradle/support/fetchDependencies.gradle',
                            '-DhideDownloadProgress', '-DnoEclipse']) == 0
    assert run('prep', g + ['prepDev']) == 0
    assert run('actual-original-unit-languages', g + [':x86:sleighCompile', ':Toy:sleighCompile',
               ':PowerPC:sleighCompile', ':MIPS:sleighCompile', ':AARCH64:sleighCompile']) == 0
    (e / 'fixture.c').write_text(
        'int helper(void) { volatile int value = 42; return value; }\n'
        'int main(void) { return 42; }\n')
    binary = e / 'fixture'
    assert run('fixture-compile', ['gcc', '-O0', '-fno-pie', '-no-pie', '-o',
                                 str(binary), str(e / 'fixture.c')]) == 0
    assert run('fixture-symbols', ['nm', str(binary)]) == 0
    symbol = re.search(r'^([0-9a-fA-F]+) T main$', (e / 'fixture-symbols.log').read_text(), re.MULTILINE)
    assert symbol is not None
    main_address = int(symbol.group(1), 16)
    helper_symbol = re.search(r'^([0-9a-fA-F]+) T helper$',
                             (e / 'fixture-symbols.log').read_text(), re.MULTILINE)
    assert helper_symbol is not None
    helper_address = int(helper_symbol.group(1), 16)
    r['elf_sha256'] = sha(binary.read_bytes())
    prefix = ('load file ' + str(binary) + '\nread symbols\nload function main\n'
              'decompile\nprint C\n')
    set_sources('baseline', False, False)
    build('baseline')
    unit_phase('baseline', failures)
    baseline_state = e / 'baseline-state.xml'
    assert not baseline_state.exists()
    output = console('baseline-save', prefix + 'save ' + str(baseline_state) + '\nquit\n')
    check_main(output, 1)
    assert output.count('ERROR: Invalid command') == 1 and not baseline_state.exists()
    r['baseline_public_save_failed_as_expected'] = True
    set_sources('parser-only-save-producer', True, False)
    build('parser-only-save-producer', unit=False)
    first_state = e / 'first-state.xml'
    output = console('first-public-save', prefix + 'save ' + str(first_state) + '\nquit\n')
    check_main(output, 1)
    assert output.count('successfully loaded:') == 1 and not re.search(r'ERROR|error:', output)
    local_symbols(first_state, 'main', True)
    first_hash = valid_state(first_state)
    r['first_public_save_sha256'] = first_hash
    r['first_public_save_producer'] = 'Fixed parser and unchanged original encoder/decoder'

    helper_state = e / 'nonempty-helper-state.xml'
    helper_cycle = 'load function helper\ndecompile\nprint C\n'
    output = console('first-nonempty-public-save', 'load file ' + str(binary) +
                     '\nread symbols\nload function helper\n' +
                     'map address [stack,0xfffffffffffffff4] int4 mapped_value\n' +
                     'decompile\nprint C\nsave ' + str(helper_state) + '\nquit\n')
    assert output.count('successfully loaded:') == 1 and not re.search(r'ERROR|error:', output)
    original_helper_body = helper_body(output)
    local_symbols(helper_state, 'helper', False)
    helper_hash = valid_state(helper_state)

    legacy_seed = e / 'legacy-functionshell-seed.xml'
    output = console('public-legacy-seed-save', 'load file ' + str(binary) +
                     '\nread symbols\nsave ' + str(legacy_seed) + '\nquit\n')
    assert output.count('successfully loaded:') == 1 and not re.search(r'ERROR|error:', output)
    valid_state(legacy_seed)
    seed_root = ET.parse(legacy_seed).getroot()
    assert not list(seed_root.iter('function'))
    assert any(node.get('name') == 'main' for node in seed_root.iter('functionshell'))
    r['legacy_seed_sha256'] = valid_state(legacy_seed)
    r['legacy_seed_producer'] = 'Public native load/read symbols/save; no functions decompiled'
    save()

    set_sources('original-decoder-controls', False, False)
    build('original-decoder-controls', unit=False)
    output = console('original-empty-scope-restore', 'restore ' + str(first_state) + '\nquit\n')
    assert output.count('Execution error: Expecting <symbollist> but no remaining children in current element') == 1
    assert output.count('Execution error:') == 1 and 'successfully loaded:' not in output
    assert valid_state(first_state) == first_hash
    r['original_empty_scope_restore_defect_verified'] = True
    output = console('original-nonempty-scope-restore', 'restore ' + str(helper_state) + '\n' +
                     helper_cycle + 'quit\n')
    assert output.count('successfully loaded:') == 1 and not re.search(r'ERROR|error:', output)
    assert helper_body(output) == original_helper_body
    assert valid_state(helper_state) == helper_hash
    r['original_nonempty_scope_restore_verified'] = True
    legacy('original-legacy', legacy_seed)

    set_sources('fixed', True, True)
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
    output = console('fixed-nonempty-scope-restore', 'restore ' + str(helper_state) + '\n' +
                     helper_cycle + 'quit\n')
    assert output.count('successfully loaded:') == 1 and not re.search(r'ERROR|error:', output)
    assert helper_body(output) == original_helper_body
    assert valid_state(helper_state) == helper_hash
    r['fixed_nonempty_scope_restore_verified'] = True
    assert not (e / 'ignored.xml').exists()
    legacy('fixed-legacy', legacy_seed)
    assert valid_state(first_state) == first_hash
    for path, content in fixed_sources.items():
        assert (p / path).read_bytes() == content
    for path, content in original_sources.items():
        assert (p / path).read_bytes() == content
    clean()
    # Standalone Makefile outputs live in the module source tree, whereas Gradle's IP
    # scan excludes only build/**. Remove only our generated outputs after saving proof.
    generated = [cpp / name for name in ('com_opt', 'test_dbg', 'decomp_opt', 'decomp_test_dbg')]
    r['standalone_generated_cleanup'] = []
    for path in generated:
        relative = str(path.relative_to(p))
        assert not subprocess.check_output(['git', 'ls-files', '--', relative], text=True).strip()
        assert path.exists() and not path.is_symlink()
        files = sorted(path.rglob('*')) if path.is_dir() else [path]
        records = []
        for file in files:
            if file.is_file():
                assert not file.is_symlink()
                records.append({'path': str(file.relative_to(p)), 'bytes': file.stat().st_size,
                                'sha256': sha(file.read_bytes())})
        r['standalone_generated_cleanup'].append({'path': relative, 'files': records})
        save()
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
        assert not path.exists()
    for path, content in fixed_sources.items():
        assert (p / path).read_bytes() == content
    for path, content in original_sources.items():
        assert (p / path).read_bytes() == content
    clean()
    assert run('full-build', g + ['buildGhidra']) == 0
    assert 'BUILD SUCCESSFUL' in (e / 'full-build.log').read_text()
    r['full_build_passed'] = True
    for path, content in fixed_sources.items():
        assert (p / path).read_bytes() == content
    clean()
    r['status'] = 'passed'
except Exception as error:
    r['status'] = 'failed'
    r['error'] = str(error)
    r['traceback'] = traceback.format_exc()
    raise
finally:
    save()
