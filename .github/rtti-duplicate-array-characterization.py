import hashlib
import io
import json
import os
import pathlib
import re
import stat
import subprocess
import traceback
import urllib.request
import zipfile

p = pathlib.Path.cwd()
e = p / 'native-evidence'
e.mkdir(exist_ok=True)
base = os.environ['BASE_SHA']
r = {'base': base, 'status': 'INCONCLUSIVE', 'production_unchanged': True,
     'publication_gate': False, 'steps': []}

def save():
    (e / 'receipt.json').write_text(json.dumps(r, indent=2))

def run(label, args, timeout=1800, **kwargs):
    with (e / (label + '.log')).open('w') as output:
        result = subprocess.run(args, stdout=output, stderr=subprocess.STDOUT,
                                timeout=timeout, **kwargs)
    r['steps'].append({'label': label, 'args': args, 'exit_code': result.returncode})
    save()
    return result.returncode

try:
    assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() == base
    assert not subprocess.check_output(['git', 'status', '--porcelain'], text=True).strip()
    fixture_bytes = urllib.request.urlopen(
        'https://github.com/user-attachments/files/33204431/camelotunchained_dump.zip',
        timeout=60).read()
    r['fixture_zip_sha256'] = hashlib.sha256(fixture_bytes).hexdigest()
    assert r['fixture_zip_sha256'] == 'd5398298d3c06e18ec86bfcc2f8b1698a0410a9f9e5abb04f675e684e012d8af'
    fixture_zip = zipfile.ZipFile(io.BytesIO(fixture_bytes))
    assert fixture_zip.namelist() == ['camelotunchained_dump.exe']
    executable_bytes = fixture_zip.read('camelotunchained_dump.exe')
    r['fixture_pe_sha256'] = hashlib.sha256(executable_bytes).hexdigest()
    assert r['fixture_pe_sha256'] == 'e76f1b55d151f3ba5bf416bb34ea0de83deadc27d493ed91a8511f887eaea4d9'
    fixture = pathlib.Path('/tmp/rtti-public-fixture.exe')
    fixture.write_bytes(executable_bytes)
    # The imported PE is data only; never execute the reporter's binary.
    g = ['./gradlew', '--no-daemon', '--max-workers=2',
         '-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
    assert run('fetch', g + ['-I', 'gradle/support/fetchDependencies.gradle',
                            '-DhideDownloadProgress', '-DnoEclipse']) == 0
    assert run('prep', g + ['prepDev']) == 0
    assert run('actual-native-x86', g + [':Decompiler:buildNatives', ':x86:sleighCompile']) == 0
    native = p / 'Ghidra/Features/Decompiler/build/os/linux_x86_64/decompile'
    assert native.is_file()
    r['built_native_sha256'] = hashlib.sha256(native.read_bytes()).hexdigest()
    assert run('actual-distribution-build', g + ['buildGhidra']) == 0
    distributions = list((p / 'build/dist').glob('ghidra*.zip'))
    assert len(distributions) == 1
    distribution = distributions[0]
    r['distribution_sha256'] = hashlib.sha256(distribution.read_bytes()).hexdigest()
    with zipfile.ZipFile(distribution) as archive:
        archive.extractall('/tmp/rtti-distribution')
        for member in archive.infolist():
            mode = stat.S_IMODE(member.external_attr >> 16)
            if mode:
                pathlib.Path('/tmp/rtti-distribution', member.filename).chmod(mode)
    launches = list(pathlib.Path('/tmp/rtti-distribution').glob('*/support/analyzeHeadless'))
    assert len(launches) == 1
    install = launches[0].parent.parent
    assert run('headless-script-permissions', ['chmod', '+x', str(launches[0]),
                                              str(launches[0].parent / 'launch.sh')]) == 0
    scripts = install / 'Ghidra/Features/Decompiler/ghidra_scripts'
    assert (scripts / 'RecoverClassesFromRTTIScript.java').is_file()
    installed_native = install / 'Ghidra/Features/Decompiler/os/linux_x86_64/decompile'
    r['installed_native_sha256'] = hashlib.sha256(installed_native.read_bytes()).hexdigest()
    assert r['installed_native_sha256'] == r['built_native_sha256']
    r['production_script_sha256'] = {}
    for relative in ('RecoverClassesFromRTTIScript.java', 'classrecovery/RTTIWindowsClassRecoverer.java'):
        original = subprocess.check_output(['git', 'show', base +
            ':Ghidra/Features/Decompiler/ghidra_scripts/' + relative])
        assert (scripts / relative).read_bytes() == original
        r['production_script_sha256'][relative] = hashlib.sha256(original).hexdigest()
    assert run('actual-public-rtti-script', [str(launches[0]), '/tmp/rtti-project', 'PublicRtti',
               '-import', str(fixture), '-analysisTimeoutPerFile', '1200', '-max-cpu', '2',
               '-scriptPath', '/tmp', '-postScript', 'RttiDuplicateArrayCharacterization.java',
               '-deleteProject'], timeout=2400) == 0
    log = (e / 'actual-public-rtti-script.log').read_text()
    assert 'REPORT: Analysis timed out at' not in log
    assert 'RTTI_PUBLIC_PE_READY' in log and 'pointerSize=8 analyzed=true' in log
    assert 'Recovering classes using RTTI...' in log
    assert 'RTTI_CHARACTERIZATION_OUTCOME=INCONCLUSIVE' not in log
    outcomes = [name for name in ('REPRODUCED', 'NOT_REPRODUCED')
                if 'RTTI_CHARACTERIZATION_OUTCOME=' + name in log]
    assert len(outcomes) == 1
    if outcomes[0] == 'REPRODUCED':
        assert 'RTTI_CHARACTERIZATION_EXPECTED_EXCEPTION=More than one Base Class Array for ' in log
    else:
        assert re.search(r'Identified [1-9][0-9]* classes to process and ', log)
    r['status'] = outcomes[0]
    assert not subprocess.check_output(['git', 'diff', '--name-only', 'HEAD'], text=True).strip()
except Exception as error:
    r['status'] = 'INCONCLUSIVE'
    r['error'] = str(error)
    r['traceback'] = traceback.format_exc()
    raise
finally:
    save()
