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
base = os.environ['BASE_SHA']
r = {'base': base, 'status': 'INCONCLUSIVE', 'publication_gate': False,
     'production_unchanged': True, 'full_build_passed': False, 'steps': []}


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
    assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() == base
    assert not subprocess.check_output(['git', 'diff', '--name-only', 'HEAD'], text=True).strip()
    assert pathlib.Path('/usr/include/bfd.h').is_file()
    assert run('bfd-package-version', ['dpkg-query', '-W', 'binutils-dev']) == 0
    cpp = p / 'Ghidra/Features/Decompiler/src/decompile/cpp'
    assert run('actual-console-build', ['make', '-j2', 'decomp_opt'], cwd=cpp) == 0
    g = ['./gradlew', '--no-daemon', '--max-workers=2',
         '-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
    assert run('fetch', g + ['-I', 'gradle/support/fetchDependencies.gradle',
                             '-DhideDownloadProgress', '-DnoEclipse']) == 0
    assert run('prep', g + ['prepDev']) == 0
    assert run('actual-x86-compile', g + [':x86:sleighCompile']) == 0
    sla = p / 'Ghidra/Processors/x86/data/languages/x86-64.sla'
    assert sla.is_file()
    fixture = e / 'fixture.c'
    fixture.write_text('int main(void) { return 42; }\n')
    binary = e / 'fixture'
    assert run('fixture-compile', ['gcc', '-O0', '-fno-pie', '-no-pie',
                                 '-o', str(binary), str(fixture)]) == 0
    assert run('fixture-symbols', ['nm', str(binary)]) == 0
    assert re.search(r'\bT main\b', (e / 'fixture-symbols.log').read_text())
    console = cpp / 'decomp_opt'
    for label, path in [('console', console), ('fixture', binary), ('sla', sla)]:
        r[label + '_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
    state = e / 'state.xml'
    assert not state.exists()
    commands = '\n'.join(['load file ' + str(binary), 'read symbols',
                          'load function main', 'decompile', 'print C',
                          'save ' + str(state), 'quit', ''])
    (e / 'console-input.txt').write_text(commands)
    env = dict(os.environ, SLEIGHHOME=str(p))
    code = run('actual-console', [str(console)], input=commands, text=True, env=env)
    output = (e / 'actual-console.log').read_text()
    assert code in (0, 1)
    assert 'successfully loaded:' in output
    assert 'Decompiling main' in output and 'Decompilation complete' in output
    assert re.search(r'return\s+(?:42|0x2a)\s*;', output, re.IGNORECASE)
    assert output.count('ERROR: Invalid command') == 1
    assert not state.exists()
    assert not subprocess.check_output(['git', 'diff', '--name-only'], text=True).strip()
    r['status'] = 'REPRODUCED_PUBLIC_CONSOLE_SAVE_PREFIX_COLLISION'
    r['restore_roundtrip_verified'] = False
except Exception as error:
    r['error'] = str(error)
    r['traceback'] = traceback.format_exc()
    raise
finally:
    save()
