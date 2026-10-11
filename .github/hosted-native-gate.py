import pathlib,subprocess,os,json,xml.etree.ElementTree as ET
p=pathlib.Path.cwd(); e=p/'native-evidence'; e.mkdir(exist_ok=True)
kind=os.environ['CANDIDATE_KIND'];head=os.environ['CANDIDATE_HEAD'];base='918d44ebc2962a53d23eeee52b8f44c7816e7815'
assert subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()==head
r={'base':base,'head':head,'kind':kind,'steps':[],'status':'running'}
def save(): (e/'receipt.json').write_text(json.dumps(r,indent=2))
def run(name,args):
 with (e/(name+'.log')).open('w') as f: x=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT)
 r['steps'].append({'name':name,'command':args,'exit_code':x.returncode});save()
 print(name,x.returncode,flush=True)
 if x.returncode: print((e/(name+'.log')).read_text()[-6000:],flush=True)
 return x.returncode
def cs(directory):
 return [{'name':c.get('name'),'class':c.get('classname'),'failed':c.find('failure') is not None,'error':c.find('error') is not None,'skipped':c.find('skipped') is not None} for f in directory.glob('*.xml') for c in ET.parse(f).getroot().iter('testcase')]
g=['./gradlew','--no-daemon','--max-workers=2','-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
try:
 assert run('fetch',g+['-I','gradle/support/fetchDependencies.gradle','-DhideDownloadProgress','-DnoEclipse'])==0
 assert run('prep',g+['prepDev'])==0
 if kind=='float':
  prod='Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/pcode/floatformat/FloatFormat.java'; cmd=g+[':SoftwareModeling:test','--tests','ghidra.pcode.floatformat.FloatFormatTest','--tests','ghidra.pcode.floatformat.BigFloatTest']; total=82; failures=6; result=p/'Ghidra/Framework/SoftwareModeling/build/test-results/test'
 else:
  assert run('runtime',g+[':PyGhidra:jar',':LaunchSupport:jar',':JVM:jar',':JVM:sleighCompile',':PyGhidra:prepPyGhidra'])==0
  python=str(p/'build/venv/bin/python3');assert run('pytest-install',[python,'-m','pip','install','pytest','pytest-datadir'])==0
  os.environ['GHIDRA_INSTALL_DIR']=str(p)
  prod='Ghidra/Features/PyGhidra/src/main/py/src/pyghidra/'+('script.py' if kind=='script' else 'api.py')
  pattern='script_path_cleanup_preserves_script_changes' if kind=='script' else 'analyze_completion_and_listener_cleanup';total=10 if kind=='script' else 2;failures=7 if kind=='script' else 2
  cmd=[python,'-m','pytest','Ghidra/Features/PyGhidra/src/main/py/tests/test_core.py','-k',pattern];result=e/'pytest';result.mkdir()
 fixed=(p/prod).read_bytes();(p/prod).write_bytes(subprocess.check_output(['git','show',base+':'+prod]))
 for phase in ['baseline','fixed']:
  if phase=='fixed':(p/prod).write_bytes(fixed)
  args=cmd if kind=='float' else cmd+['--junitxml='+str(result/'result.xml')]
  rc=run(phase,args);cases=cs(result);r[phase]={'exit_code':rc,'cases':cases};save()
  import shutil
  shutil.copytree(result,e/(phase+'-xml'))
  assert len(cases)==total,(phase,len(cases),total)
  assert not any(c['error']or c['skipped']for c in cases)
  if phase=='baseline':assert rc!=0 and sum(c['failed']for c in cases)==failures
  else:assert rc==0 and not any(c['failed']for c in cases)
 if kind!='float':assert run('full-core',[python,'-m','pytest','Ghidra/Features/PyGhidra/src/main/py/tests/test_core.py','--junitxml='+str(e/'full-core.xml')])==0
 assert run('full-build',g+['buildGhidra'])==0
 assert not subprocess.check_output(['git','diff','--name-only'],text=True).strip()
 r['status']='passed'
except Exception as ex:
 import traceback
 r['status']='failed';r['error']=str(ex);r['traceback']=traceback.format_exc();raise
finally:save()
