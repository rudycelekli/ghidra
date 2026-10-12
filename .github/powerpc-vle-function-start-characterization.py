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
r = {'base': base, 'status': 'INCONCLUSIVE', 'discovery_only': True,
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
                if message.startswith('VLE_NATIVE_'):
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
    assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() == base
    assert not subprocess.check_output(['git', 'status', '--porcelain'], text=True).strip()
    assert hashlib.sha256(pathlib.Path('/tmp/PowerPcVleFunctionStartCharacterization.java').read_bytes()).hexdigest() == 'd7ce6fef9dd08fdb448657b0e0aa8486726a2aa7f72a8124f0a7b6ebf250abd8'
    g = ['./gradlew', '--no-daemon', '--max-workers=2', '-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
    assert run('fetch', g + ['-I', 'gradle/support/fetchDependencies.gradle', '-DhideDownloadProgress', '-DnoEclipse']) == 0
    assert run('prep', g + ['prepDev']) == 0
    assert run('actual-powerpc-decoder', g + [':PowerPC:sleighCompile']) == 0
    decoder_path = 'Ghidra/Processors/PowerPC/data/languages/ppc_64_isa_vle_be.sla'
    decoder = p / decoder_path
    assert decoder.is_file()
    r['current_decoder_sha256'] = hashlib.sha256(decoder.read_bytes()).hexdigest()
    assert run('complete-original-distribution-build', g + ['buildGhidra']) == 0
    assert 'BUILD SUCCESSFUL' in (e / 'complete-original-distribution-build.log').read_text()
    distributions = list((p / 'build/dist').glob('ghidra*.zip'))
    assert len(distributions) == 1
    r['distribution_sha256'] = hashlib.sha256(distributions[0].read_bytes()).hexdigest()
    install_root = pathlib.Path('/tmp/vle-distribution')
    with zipfile.ZipFile(distributions[0]) as archive:
        archive.extractall(install_root)
        for member in archive.infolist():
            mode = stat.S_IMODE(member.external_attr >> 16)
            if mode:
                (install_root / member.filename).chmod(mode)
    launches = list(install_root.glob('*/support/analyzeHeadless'))
    assert len(launches) == 1
    launch = launches[0]
    install = launch.parent.parent
    assert hashlib.sha256((install / decoder_path).read_bytes()).hexdigest() == r['current_decoder_sha256']
    r['original_pattern_hashes'] = {}
    for relative in ['Ghidra/Processors/PowerPC/data/patterns/PPC_BE_patterns.xml', 'Ghidra/Processors/PowerPC/data/patterns/patternconstraints.xml']:
        original = subprocess.check_output(['git', 'show', base + ':' + relative])
        assert (install / relative).read_bytes() == original
        r['original_pattern_hashes'][relative] = hashlib.sha256(original).hexdigest()
    project = pathlib.Path('/tmp/vle-project')
    project.mkdir()
    assert os.environ['GHIDRA_HEADLESS_MAXMEM'] == '4G'
    label = 'actual-public-vle-analyzer'
    assert run(label, [str(launch), str(project), 'VleDiscovery', '-scriptPath', '/tmp', '-preScript', 'PowerPcVleFunctionStartCharacterization.java', '-deleteProject'], timeout=900) == 0
    messages = inspect(label, b'PowerPcVleFunctionStartCharacterization.java> ')
    # inspect's owned prefix below is VLE_NATIVE_, not RTTI_ (same bounded evaluator).
    cases = ['direct-stack', 'padded-stack', 'direct-lr-stack', 'padded-lr-stack', 'standard-control', 'disabled-vle-control', 'existing-control', 'padding-only-control', 'mixed-mode-control', 'nonexecutable-control', 'defined-data-control']
    inputs = {}
    effects = {}
    for row in messages:
        if row.startswith('VLE_NATIVE_INPUT '):
            match = re.fullmatch(r'VLE_NATIVE_INPUT name=(\S+) hex=([0-9a-f]+) execute=(true|false) controlledVle=([01]) targetMnemonic=(\S+) targetLength=([0-9]+) targetDefinedData=(true|false)', row)
            assert match and match[1] not in inputs
            inputs[match[1]] = match.groups()[1:]
        if row.startswith('VLE_NATIVE_CASE '):
            match = re.fullmatch(r'VLE_NATIVE_CASE name=(\S+) target=([0-9a-f]+) vle=([01]) functionBefore=(true|false) functionAfter=(true|false) bodyAddresses=([0-9]+) messageLog=(.*)', row)
            assert match and match[1] not in effects
            effects[match[1]] = match.groups()[1:]
    assert set(inputs) == set(effects) == set(cases)
    missing = 0
    for name in cases:
        inp, effect = inputs[name], effects[name]
        mode = '0' if name in ['standard-control', 'disabled-vle-control', 'nonexecutable-control', 'defined-data-control'] else '1'
        assert inp[2] == effect[1] == mode
        assert inp[1] == ('false' if name == 'nonexecutable-control' else 'true')
        assert inp[5] == ('true' if name == 'defined-data-control' else 'false')
        expected_mnemonic = 'NONE' if name in ['defined-data-control', 'disabled-vle-control'] else 'stwu' if name in ['standard-control', 'nonexecutable-control'] else 'se_or' if name == 'padding-only-control' else 'se_mflr' if name in ['direct-lr-stack', 'padded-lr-stack'] else 'e_stwu'
        expected_length = '0' if expected_mnemonic == 'NONE' else '2' if expected_mnemonic in ['se_or', 'se_mflr'] else '4'
        assert inp[3].lower() == expected_mnemonic and inp[4] == expected_length
        expected_target = '1004' if name in ['padded-stack', 'padded-lr-stack', 'standard-control', 'padding-only-control', 'nonexecutable-control', 'defined-data-control'] else '1002'
        assert effect[0] == expected_target
        assert effect[2] == ('true' if name == 'existing-control' else 'false')
        if name in ['standard-control', 'existing-control']:
            assert effect[3] == 'true' and int(effect[4]) > 0
        elif name in ['disabled-vle-control', 'padding-only-control', 'nonexecutable-control', 'defined-data-control']:
            assert effect[3] == 'false' and int(effect[4]) == 0
        else:
            missing += effect[3] == 'false'
            assert (int(effect[4]) > 0) == (effect[3] == 'true')
    mixed = [m for m in messages if m.startswith('VLE_NATIVE_MIXED ')]
    assert mixed == ['VLE_NATIVE_MIXED standardTarget=1084 vle=0 function=true']
    outcomes = [m for m in messages if m.startswith('VLE_NATIVE_OUTCOME ')]
    expected = 'REPRODUCED' if missing == 5 else 'NOT_REPRODUCED' if missing == 0 else 'PARTIAL'
    assert outcomes == [f'VLE_NATIVE_OUTCOME cases=11 missingCandidates={missing} outcome={expected}']
    assert not subprocess.check_output(['git', 'status', '--porcelain'], text=True).strip()
    r['status'] = expected
    r['actual_missing_functions'] = missing
    r['publication_gate'] = False
except Exception as error:
    r['status'] = 'INCONCLUSIVE'
    r['error'] = str(error)
    r['traceback'] = traceback.format_exc()
    raise
finally:
    save()
