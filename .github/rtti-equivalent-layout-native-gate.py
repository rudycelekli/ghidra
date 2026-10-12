import gzip
import datetime
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
head = os.environ['CANDIDATE_SHA']
r = {'base': base, 'candidate': head, 'status': 'INCONCLUSIVE',
     'publication_gate': False, 'steps': []}

def save():
    (e / 'receipt.json').write_text(json.dumps(r, indent=2))

def shutil_copy_stream(source, destination):
    while chunk := source.read(1024 * 1024):
        destination.write(chunk)


def run(label, args, timeout=1800, **kwargs):
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if label.startswith('actual-'):
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   start_new_session=True, **kwargs)
        errors = []
        raw_hash = hashlib.sha256()
        raw_bytes = 0
        def pump():
            nonlocal raw_bytes
            try:
                with gzip.open(e / (label + '.log.gz'), 'wb') as output:
                    while chunk := process.stdout.read(1024 * 1024):
                        raw_hash.update(chunk)
                        raw_bytes += len(chunk)
                        output.write(chunk)
            except BaseException as error:
                errors.append(error)
        thread = threading.Thread(target=pump, daemon=True)
        thread.start()
        try:
            exit_code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            exit_code = 'TIMEOUT'
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
        r.setdefault('raw_logs', {})[label] = {'sha256': raw_hash.hexdigest(), 'bytes': raw_bytes, 'gzip_preserved': True}
        save()
        if errors:
            raise errors[0]
    else:
        with (e / (label + '.log')).open('w') as output:
            try:
                exit_code = subprocess.run(args, stdout=output, stderr=subprocess.STDOUT,
                                           timeout=timeout, **kwargs).returncode
            except subprocess.TimeoutExpired:
                exit_code = 'TIMEOUT'
    r['steps'].append({'label': label, 'args': args, 'exit_code': exit_code, 'started_at': started, 'ended_at': datetime.datetime.now(datetime.timezone.utc).isoformat()})
    save()
    return exit_code


def inspect(label, prefix):
    raw_hash = hashlib.sha256()
    raw_bytes = 0
    messages = []
    marker_bytes = 0
    bad = False
    continuation = False
    with gzip.open(e / (label + '.log.gz'), 'rb') as stream:
        while line := stream.readline(1024 * 1024):
            raw_hash.update(line)
            raw_bytes += len(line)
            too_long = len(line) == 1024 * 1024 and not line.endswith(b'\n')
            bad |= too_long or b'REPORT: Analysis timed out at' in line
            if not continuation and not too_long and prefix in line:
                message = line.split(prefix, 1)[1].decode('utf-8').strip()
                if message.startswith('RTTI_'):
                    if len(messages) >= 10000 or marker_bytes + len(line) > 16 * 1024 * 1024:
                        bad = True
                    else:
                        messages.append(message.split(' (GhidraScript)', 1)[0].strip())
                        marker_bytes += len(line)
            continuation = not line.endswith(b'\n')
    (e / (label + '-markers.json')).write_text(json.dumps(messages, indent=2))
    r.setdefault('observations', {})[label] = {'raw_sha256': raw_hash.hexdigest(), 'raw_bytes': raw_bytes, 'messages': messages, 'bounded_exceeded_or_timeout': bad, 'marker_bytes': marker_bytes}
    save()
    assert not bad, 'Incomplete or bounded observation; full raw gzip and hash preserved'
    return messages

try:
    assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() == head
    assert not subprocess.check_output(['git', 'status', '--porcelain'], text=True).strip()
    production = 'Ghidra/Features/Decompiler/ghidra_scripts/classrecovery/RTTIWindowsClassRecoverer.java'
    changed = subprocess.check_output(['git', 'diff', '--name-only', base, head], text=True).splitlines()
    assert changed == [production]
    original = subprocess.check_output(['git', 'show', base + ':' + production])
    fixed = subprocess.check_output(['git', 'show', head + ':' + production])
    assert hashlib.sha256(original).hexdigest() == '252387f152cb4d8c6cab10c7ebff57e17d2d7c3fea64136e481fa24d336a83fa'
    assert hashlib.sha256(fixed).hexdigest() == '184a8b3dbe1dc5d3058a1d3270c081a12caf20ffa7d8b9ee008d3de73de17ab1'
    r['production_hashes'] = {'baseline': hashlib.sha256(original).hexdigest(), 'fixed': hashlib.sha256(fixed).hexdigest()}
    fixture_bytes = urllib.request.urlopen('https://github.com/user-attachments/files/33204431/camelotunchained_dump.zip', timeout=60).read()
    assert hashlib.sha256(fixture_bytes).hexdigest() == 'd5398298d3c06e18ec86bfcc2f8b1698a0410a9f9e5abb04f675e684e012d8af'
    fixture_zip = zipfile.ZipFile(io.BytesIO(fixture_bytes))
    assert fixture_zip.namelist() == ['camelotunchained_dump.exe']
    pe = fixture_zip.read('camelotunchained_dump.exe')
    assert hashlib.sha256(pe).hexdigest() == 'e76f1b55d151f3ba5bf416bb34ea0de83deadc27d493ed91a8511f887eaea4d9'
    fixture = pathlib.Path('/tmp/rtti-public-fixture.exe')
    fixture.write_bytes(pe) # Data only: NEVER execute reporter binary.
    g = ['./gradlew', '--no-daemon', '--max-workers=2', '-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
    assert run('fetch', g + ['-I', 'gradle/support/fetchDependencies.gradle', '-DhideDownloadProgress', '-DnoEclipse']) == 0
    assert run('prep', g + ['prepDev']) == 0
    assert run('actual-native-x86', g + [':Decompiler:buildNatives', ':x86:sleighCompile']) == 0
    native = p / 'Ghidra/Features/Decompiler/build/os/linux_x86_64/decompile'
    assert native.is_file()
    r['native_sha256'] = hashlib.sha256(native.read_bytes()).hexdigest()
    assert os.environ['GHIDRA_HEADLESS_MAXMEM'] == '4G'
    r['fixture_hashes'] = {}
    for name, expected in [('RttiEquivalentLayoutNativeTest.java', 'e6858f7dbd819b9ce313c65c4e166f94f66c4ae349b27ea83b5b70d8e62bcf7e'), ('RttiEquivalentLayoutPublicPeTest.java', '2a0796635facd9ef309700955746d460feaa606cd8e62d42d5405540b80df45f')]:
        digest = hashlib.sha256(pathlib.Path('/tmp', name).read_bytes()).hexdigest()
        assert digest == expected
        r['fixture_hashes'][name] = digest
    cases = ['unique-x86', 'unique-x64', 'zero-arrays', 'equivalent-x86', 'equivalent-x64', 'equivalent-no-vftable', 'equivalent-raw-only-meta', 'flags', 'count', 'order', 'name', 'contained', 'mdisp', 'pdisp', 'vdisp', 'attributes', 'namespace', 'orphan', 'missing-bcd', 'malformed-chd', 'relative-reference-conflict', 'record-reference-conflict-x86', 'absolute-reference-conflict', 'col-type-conflict', 'missing-meta', 'cancel']
    for phase, source in [('baseline', original), ('fixed', fixed)]:
        pathlib.Path(production).write_bytes(source)
        assert run(phase + '-complete-distribution-build', g + ['buildGhidra']) == 0
        log = (e / (phase + '-complete-distribution-build.log')).read_text()
        assert 'BUILD SUCCESSFUL' in log and 'BUILD FAILED' not in log
        distributions = list((p / 'build/dist').glob('ghidra*.zip'))
        assert len(distributions) == 1
        distribution = distributions[0]
        r.setdefault('distribution_hashes', {})[phase] = hashlib.sha256(distribution.read_bytes()).hexdigest()
        install_root = pathlib.Path('/tmp', 'rtti-install-' + phase)
        with zipfile.ZipFile(distribution) as archive:
            archive.extractall(install_root)
            for member in archive.infolist():
                mode = stat.S_IMODE(member.external_attr >> 16)
                if mode:
                    (install_root / member.filename).chmod(mode)
        launches = list(install_root.glob('*/support/analyzeHeadless'))
        assert len(launches) == 1
        launch = launches[0]
        scripts = launch.parent.parent / 'Ghidra/Features/Decompiler/ghidra_scripts'
        assert (scripts / 'classrecovery/RTTIWindowsClassRecoverer.java').read_bytes() == source
        original_public = subprocess.check_output(['git', 'show', base + ':Ghidra/Features/Decompiler/ghidra_scripts/RecoverClassesFromRTTIScript.java'])
        assert (scripts / 'RecoverClassesFromRTTIScript.java').read_bytes() == original_public
        assert hashlib.sha256((launch.parent.parent / 'Ghidra/Features/Decompiler/os/linux_x86_64/decompile').read_bytes()).hexdigest() == r['native_sha256']
        project = pathlib.Path('/tmp', 'rtti-project-' + phase)
        project.mkdir()
        label = 'actual-native-cases-' + phase
        assert run(label, [str(launch), str(project), 'NativeCases', '-scriptPath', '/tmp', '-preScript', 'RttiEquivalentLayoutNativeTest.java', phase, '-deleteProject'], timeout=600) == 0
        messages = inspect(label, b'RttiEquivalentLayoutNativeTest.java> ')
        outcome_rows = [m for m in messages if m.startswith('RTTI_RESOLVER_CASE ')]
        assert len(outcome_rows) == len(cases)
        parsed = {}
        for row in outcome_rows:
            match = re.fullmatch(r'RTTI_RESOLVER_CASE phase=(baseline|fixed) name=(\S+) outcome=(\S+)(?: .*)?', row)
            assert match and match[1] == phase and match[2] not in parsed
            parsed[match[2]] = match[3]
        assert set(parsed) == set(cases)
        for name in cases:
            expected = 'CANCELLED' if name == 'cancel' else 'PASS' if name.startswith('unique') or name == 'zero-arrays' else 'EXPECTED_REGRESSION_FAILURE' if name.startswith('equivalent') and phase == 'baseline' else 'PASS' if name.startswith('equivalent') else 'REJECTED_INVALID'
            assert parsed[name] == expected, (phase, name, parsed[name], expected)
        complete = f'RTTI_RESOLVER_COMPLETE phase={phase} cases=26 passes={22 if phase == "baseline" else 26} failures={4 if phase == "baseline" else 0}'
        assert messages.count(complete) == 1
        label = 'actual-public-pe-' + phase
        assert run(label, [str(launch), str(project), 'PublicPe', '-import', str(fixture), '-analysisTimeoutPerFile', '1200', '-max-cpu', '2', '-scriptPath', '/tmp', '-postScript', 'RttiEquivalentLayoutPublicPeTest.java', phase, '-deleteProject'], timeout=2400) == 0
        messages = inspect(label, b'RttiEquivalentLayoutPublicPeTest.java> ')
        outcomes = [m for m in messages if m.startswith('RTTI_PUBLIC_PE_OUTCOME ')]
        assert len(outcomes) == 1
        if phase == 'baseline':
            assert outcomes[0] == 'RTTI_PUBLIC_PE_OUTCOME phase=baseline outcome=EXPECTED_REGRESSION_FAILURE message=More than one Base Class Array for std::_Func_impl_no_alloc<ConfigValidation::<lambda_6>,bool,int>'
        else:
            assert re.fullmatch(r'RTTI_PUBLIC_PE_OUTCOME phase=fixed outcome=COMPLETE_RECOVERY hierarchy=std::_Func_impl_no_alloc<ConfigValidation::<lambda_6>,bool,int>,std::_Func_base<bool,int> arrays=107 descriptors=107 parentOffset=0 virtual=false structureLength=[1-9][0-9]*', outcomes[0])
        save()
    assert pathlib.Path(production).read_bytes() == fixed
    assert not subprocess.check_output(['git', 'status', '--porcelain'], text=True).strip()
    r['status'] = 'NATIVE_BASELINE_FIXED_COMPLETE_PUBLIC_RECOVERY_PASS'
    r['publication_gate'] = True
except Exception as error:
    r['status'] = 'INCONCLUSIVE'
    r['error'] = str(error)
    r['traceback'] = traceback.format_exc()
    raise
finally:
    save()
