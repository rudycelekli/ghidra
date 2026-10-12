import gzip
import threading
import signal
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

def shutil_copy_stream(source, destination):
    while chunk := source.read(1024 * 1024):
        destination.write(chunk)


def scan_rtti_log(path, marker_path):
    full_hash = hashlib.sha256()
    full_bytes = 0
    marker_bytes = 0
    bounded_exceeded = False
    continuation = False
    flags = {'timeout': False, 'ready': False, 'recovering': False,
             'identified': False, 'expected_exception': False,
             'inventory_complete': False, 'inventory_chd': False, 'inventory_bcd': False}
    outcomes = {'REPRODUCED': 0, 'NOT_REPRODUCED': 0, 'INCONCLUSIVE': 0}
    with gzip.open(path, 'rb') as stream, marker_path.open('wb') as compact:
        while line := stream.readline(1024 * 1024):
            full_hash.update(line)
            full_bytes += len(line)
            too_long = len(line) == 1024 * 1024 and not line.endswith(b'\n')
            bounded_exceeded |= too_long
            if not continuation and not too_long:
                flags['timeout'] |= b'REPORT: Analysis timed out at' in line
                flags['recovering'] |= b'Recovering classes using RTTI...' in line
                flags['identified'] |= bool(re.search(rb'Identified [1-9][0-9]* classes to process and ', line))
                prefix = b'RttiDuplicateArrayCharacterization.java> '
                if prefix in line:
                    message = line.split(prefix, 1)[1]
                    if message.startswith((b'RTTI_PUBLIC_PE_READY ', b'RTTI_CHARACTERIZATION_', b'RTTI_INVENTORY_')):
                        flags['ready'] |= message.startswith(b'RTTI_PUBLIC_PE_READY ') and b'pointerSize=8 analyzed=true' in message
                        flags['expected_exception'] |= message.startswith(b'RTTI_CHARACTERIZATION_EXPECTED_EXCEPTION=More than one Base Class Array for ')
                        flags['inventory_complete'] |= message.startswith(b'RTTI_INVENTORY_COMPLETE class=')
                        flags['inventory_chd'] |= message.startswith(b'RTTI_INVENTORY_CHD address=')
                        flags['inventory_bcd'] |= message.startswith(b'RTTI_INVENTORY_BCD chd=')
                        for outcome in outcomes:
                            outcomes[outcome] += message.startswith(('RTTI_CHARACTERIZATION_OUTCOME=' + outcome + ' ').encode()) or message.rstrip().endswith(('RTTI_CHARACTERIZATION_OUTCOME=' + outcome).encode())
                        if marker_bytes + len(line) <= 16 * 1024 * 1024:
                            compact.write(line)
                            marker_bytes += len(line)
                        else:
                            bounded_exceeded = True
            continuation = not line.endswith(b'\n')
    return {'full_raw_log_sha256': full_hash.hexdigest(), 'full_raw_log_bytes': full_bytes,
            'full_raw_log_preserved_gzip': True, 'compact_marker_bytes': marker_bytes,
            'bounded_exceeded': bounded_exceeded, 'marker_flags': flags, 'outcome_counts': outcomes}


def run(label, args, timeout=1800, **kwargs):
    if label == 'actual-public-rtti-script':
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   start_new_session=True, **kwargs)
        errors = []
        def pump():
            try:
                with gzip.open(e / (label + '.log.gz'), 'wb') as output:
                    shutil_copy_stream(process.stdout, output)
            except BaseException as error:
                errors.append(error)
        thread = threading.Thread(target=pump, daemon=True)
        thread.start()
        try:
            exit_code = process.wait(timeout=timeout)
        finally:
            # analyzeHeadless -> launch.sh -> Java: terminate the session group, including
            # descendants which could retain stdout after the shell exits or times out.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=30)
            thread.join(timeout=30)
            if thread.is_alive():
                raise RuntimeError("RTTI log pump did not terminate after process-group cleanup")
        if errors:
            raise errors[0]
    else:
        with (e / (label + '.log')).open('w') as output:
            exit_code = subprocess.run(args, stdout=output, stderr=subprocess.STDOUT,
                                       timeout=timeout, **kwargs).returncode
    r['steps'].append({'label': label, 'args': args, 'exit_code': exit_code})
    save()
    return exit_code

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
    r['headless_heap'] = os.environ['GHIDRA_HEADLESS_MAXMEM']
    assert r['headless_heap'] == '4G'
    r['host_meminfo'] = pathlib.Path('/proc/meminfo').read_text()
    save()
    pathlib.Path('/tmp/rtti-project').mkdir()
    assert run('actual-public-rtti-script', [str(launches[0]), '/tmp/rtti-project', 'PublicRtti',
               '-import', str(fixture), '-analysisTimeoutPerFile', '1200', '-max-cpu', '2',
               '-scriptPath', '/tmp', '-postScript', 'RttiDuplicateArrayCharacterization.java',
               '-deleteProject'], timeout=2400) == 0
    observation = scan_rtti_log(e / 'actual-public-rtti-script.log.gz',
                                e / 'actual-public-rtti-markers.log')
    r.update(observation)
    save()
    assert not observation['bounded_exceeded'], 'Bounded log observation exceeded; full raw gzip retained'
    flags = observation['marker_flags']
    outcomes = observation['outcome_counts']
    assert not flags['timeout'] and flags['ready'] and flags['recovering']
    assert outcomes['INCONCLUSIVE'] == 0
    assert outcomes['REPRODUCED'] + outcomes['NOT_REPRODUCED'] == 1
    if outcomes['REPRODUCED']:
        assert flags['expected_exception'] and flags['inventory_complete']
        assert flags['inventory_chd'] and flags['inventory_bcd']
        r['status'] = 'REPRODUCED'
    else:
        assert flags['identified']
        r['status'] = 'NOT_REPRODUCED'
    assert not subprocess.check_output(['git', 'diff', '--name-only', 'HEAD'], text=True).strip()
except Exception as error:
    r['status'] = 'INCONCLUSIVE'
    r['error'] = str(error)
    r['traceback'] = traceback.format_exc()
    raise
finally:
    save()
