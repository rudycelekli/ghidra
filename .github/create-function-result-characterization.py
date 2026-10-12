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
klass = 'ghidra.app.cmd.function.CreateFunctionResultCharacterizationTest'
targets = {
    'testUndisassembledFindEntryReportsFailure': 'No function must not report success',
    'testNewExternalFunctionReportsSuccess': 'Successful external command must report success',
    'testExistingExternalFunctionReportsSuccess': 'Successful external command must report success',
    'testMixedInternalExternalReportsSuccess': 'Both real function operations succeeded',
}
controls = {'testDisassembledInternalControl', 'testMissingExternalControl', 'testCanceledControl'}
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
        'Ghidra/Features/Base/src/test/java/ghidra/app/cmd/function/CreateFunctionResultCharacterizationTest.java']
    production = 'Ghidra/Features/Base/src/main/java/ghidra/app/cmd/function/CreateFunctionCmd.java'
    original = subprocess.check_output(['git', 'show', base + ':' + production])
    assert (p / production).read_bytes() == original
    r['production_sha256'] = hashlib.sha256(original).hexdigest()
    g = ['./gradlew', '--no-daemon', '--max-workers=2',
         '-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
    assert run('fetch', g + ['-I', 'gradle/support/fetchDependencies.gradle',
                            '-DhideDownloadProgress', '-DnoEclipse']) == 0
    assert run('prep', g + ['prepDev']) == 0
    assert run('actual-x86-language', g + [':x86:sleighCompile']) == 0
    result = p / 'Ghidra/Features/Base/build/test-results/test'
    shutil.rmtree(result, ignore_errors=True)
    code = run('characterization', g + [':Base:test', '--tests', klass])
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
    for fixture, baseline, fixed, effect in [
        ('undisassembled', True, False, False), ('new-external', False, True, True),
        ('existing-external', False, True, True), ('mixed', False, True, True),
        ('internal-control', True, True, True), ('missing-external-control', False, False, False),
        ('canceled-control', False, False, False)]:
        actual = baseline if failed else fixed
        assert f'CREATE_FUNCTION_RESULT fixture={fixture} result={str(actual).lower()} effect={str(effect).lower()}' in output
    r['cases'] = cases
    r['status'] = 'REPRODUCED_PUBLIC_COMMAND_RESULT_MISMATCH' if failed else 'NOT_REPRODUCED'
    r['failures'] = len(failed)
    assert not subprocess.check_output(['git', 'diff', '--name-only', 'HEAD'], text=True).strip()
except Exception as error:
    r['status'] = 'INCONCLUSIVE'
    r['error'] = str(error)
    r['traceback'] = traceback.format_exc()
    raise
finally:
    save()
