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
head, base = os.environ['HEAD_SHA'], os.environ['BASE_SHA']
klass = 'ghidra.app.plugin.core.datamgr.editor.EnumOpenEditorMutationCharacterizationTest'
target = 'testOpenEditorWhileReplacingEntries'
control = 'testClosedEditorMutationControl'
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
        'Ghidra/Features/Base/src/test.slow/java/ghidra/app/plugin/core/datamgr/editor/EnumOpenEditorMutationCharacterizationTest.java']
    production = {}
    for path in ['Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/database/data/EnumDB.java',
                 'Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/datamgr/editor/EnumEditorProvider.java']:
        original = subprocess.check_output(['git', 'show', base + ':' + path])
        assert (p / path).read_bytes() == original
        production[path] = original
    r['production_sha256'] = {path: hashlib.sha256(data).hexdigest() for path, data in production.items()}
    g = ['./gradlew', '--no-daemon', '--max-workers=2',
         '-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
    assert run('fetch', g + ['-I', 'gradle/support/fetchDependencies.gradle',
                            '-DhideDownloadProgress', '-DnoEclipse']) == 0
    assert run('prep', g + ['prepDev']) == 0
    assert run('actual-toy-language', g + [':Toy:sleighCompile']) == 0
    result = p / 'Ghidra/Features/Base/build/test-results/integrationTest'
    shutil.rmtree(result, ignore_errors=True)
    code = run('characterization', ['xvfb-run', '-a', '-s', '-screen 0 1600x1200x24'] +
               g + [':Base:integrationTest', '--tests', klass])
    assert code in (0, 1)
    shutil.copytree(result, e / 'characterization-xml')
    cases = {}
    output = ''
    errors = ''
    for path in (e / 'characterization-xml').glob('*.xml'):
        xml = ET.parse(path).getroot()
        assert xml.get('errors') == '0' and xml.get('skipped') == '0'
        output += xml.findtext('system-out', '')
        errors += xml.findtext('system-err', '')
        for case in xml.iter('testcase'):
            assert case.get('classname') == klass and case.get('name') not in cases
            failure = case.find('failure')
            cases[case.get('name')] = {'failed': failure is not None,
                'message': failure.get('message', '') if failure is not None else ''}
            assert case.find('error') is None and case.find('skipped') is None
            if failure is not None:
                assert case.get('name') == target
                assert failure.get('type') == 'java.lang.AssertionError'
                assert failure.get('message') == 'java.lang.AssertionError: Reported open-editor EnumDB copy failure'
    assert set(cases) == {target, control} and not cases[control]['failed']
    assert 'ENUM_EDITOR_MUTATION open=false rounds=16 first=706 second=706 reported=0' in output
    match = re.findall(r'ENUM_EDITOR_MUTATION open=true rounds=16 first=706 second=706 reported=(\d+)', output)
    assert len(match) == 1
    reported = int(match[0])
    assert bool(reported) == cases[target]['failed']
    if reported:
        assert 'ENUM_EDITOR_CAPTURE thread=AWT-EventQueue-' in errors
        assert 'java.util.NoSuchElementException' in errors
        for frame in ['ghidra.program.database.data.EnumDB.getValue',
                      'ghidra.program.model.data.EnumDataType.replaceWith',
                      'ghidra.program.database.data.EnumDB.copy',
                      'ghidra.app.plugin.core.datamgr.editor.EnumEditorProvider$MyDataTypeManagerChangeListener.dataTypeChanged']:
            assert frame in errors
    r['cases'] = cases
    r['reported_exceptions'] = reported
    r['status'] = 'REPRODUCED_ACTUAL_OPEN_EDITOR_ENUM_COPY_EXCEPTION' if reported else 'NOT_REPRODUCED'
    r['bounded_observation'] = '16 actual script transaction rounds; green does not prove absence of a race'
    for path, original in production.items():
        assert (p / path).read_bytes() == original
    assert not subprocess.check_output(['git', 'diff', '--name-only', 'HEAD'], text=True).strip()
except Exception as error:
    r['status'] = 'INCONCLUSIVE'
    r['error'] = str(error)
    r['traceback'] = traceback.format_exc()
    raise
finally:
    save()
