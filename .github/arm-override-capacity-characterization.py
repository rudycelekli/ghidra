import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import traceback
import xml.etree.ElementTree as ET

p = pathlib.Path.cwd()
e = p / 'native-evidence'
e.mkdir(exist_ok=True)
head, base = os.environ['HEAD_SHA'], os.environ['BASE_SHA']
klass = 'ghidra.app.plugin.core.decompile.ArmOverrideCapacityCharacterizationTest'
targets = {'test130Override': 'Actual override must decompile', 'test185Override': 'Actual override must decompile'}
controls = {'test129OverrideControl'}
r = {'head': head, 'base': base, 'status': 'INCONCLUSIVE', 'steps': [],
     'production_unchanged': True, 'publication_gate': False, 'full_build_passed': False}

def save():
    (e / 'receipt.json').write_text(json.dumps(r, indent=2))

def run(label, args):
    with (e / (label + '.log')).open('w') as output:
        result = subprocess.run(args, stdout=output, stderr=subprocess.STDOUT, timeout=1800)
    r['steps'].append({'label': label, 'args': args, 'exit_code': result.returncode})
    save()
    return result.returncode

try:
    assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() == head
    assert subprocess.check_output(['git', 'diff', '--name-only', base, head], text=True).splitlines() == [
        'Ghidra/Features/Decompiler/src/test/java/ghidra/app/plugin/core/decompile/ArmOverrideCapacityCharacterizationTest.java']
    production = 'Ghidra/Processors/ARM/data/languages/ARM.cspec'
    original = subprocess.check_output(['git', 'show', base + ':' + production])
    assert (p / production).read_bytes() == original
    r['production_sha256'] = hashlib.sha256(original).hexdigest()
    g = ['./gradlew', '--no-daemon', '--max-workers=2',
         '-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
    assert run('fetch', g + ['-I', 'gradle/support/fetchDependencies.gradle',
                            '-DhideDownloadProgress', '-DnoEclipse']) == 0
    assert run('prep', g + ['prepDev']) == 0
    assert run('actual-native-and-arm-language', g + [':Decompiler:buildNatives', ':ARM:sleighCompile']) == 0
    native = p / 'Ghidra/Features/Decompiler/build/os/linux_x86_64/decompile'
    assert native.is_file()
    r['built_native_sha256'] = hashlib.sha256(native.read_bytes()).hexdigest()
    save()
    result = p / 'Ghidra/Features/Decompiler/build/test-results/test'
    shutil.rmtree(result, ignore_errors=True)
    code = run('characterization', g + [':Decompiler:test', '--tests', klass])
    assert code in (0, 1)
    shutil.copytree(result, e / 'characterization-xml')
    cases = {}
    output = ''
    for path in (e / 'characterization-xml').glob('*.xml'):
        xml = ET.parse(path).getroot()
        assert xml.get('errors') == '0' and xml.get('skipped') == '0'
        output += xml.findtext('system-out', '')
        for case in xml.iter('testcase'):
            assert case.get('classname') == klass and case.get('name') not in cases
            failure = case.find('failure')
            cases[case.get('name')] = {'failed': failure is not None,
                'message': failure.get('message', '') if failure is not None else ''}
            assert case.find('error') is None and case.find('skipped') is None
            if failure is not None:
                assert case.get('name') in targets
                assert failure.get('type') == 'java.lang.AssertionError'
                assert failure.get('message') == 'java.lang.AssertionError: ' + targets[case.get('name')]
    assert set(cases) == set(targets) | controls
    failed = {name for name, case in cases.items() if case['failed']}
    assert failed in (set(), set(targets))
    for count in (129, 130, 185):
        producer = f'ARM_OVERRIDE_PRODUCER count={count} persisted=1 callsite=00001004 native='
        assert producer + str(native) in output
        completed = count == 129 or not failed
        assert f'ARM_OVERRIDE_OUTCOME count={count} completed={str(completed).lower()} error=' in output
        if not completed:
            lines = [line for line in output.splitlines() if line.startswith(f'ARM_OVERRIDE_OUTCOME count={count} ')]
            assert len(lines) == 1 and 'Cannot assign parameter address' in lines[0]
    r['cases'] = cases
    r['status'] = 'REPRODUCED_NATIVE_ARM_CALLSITE_OVERRIDE_BOUNDARY' if failed else 'NOT_REPRODUCED'
    r['failures'] = len(failed)
    assert not subprocess.check_output(['git', 'diff', '--name-only', 'HEAD'], text=True).strip()
except Exception as error:
    r['status'] = 'INCONCLUSIVE'
    r['error'] = str(error)
    r['traceback'] = traceback.format_exc()
    raise
finally:
    save()
