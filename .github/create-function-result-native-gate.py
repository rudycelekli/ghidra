import hashlib, json, os, pathlib, re, shutil, subprocess, traceback
import xml.etree.ElementTree as ET
p=pathlib.Path.cwd(); e=p/'native-evidence'; e.mkdir()
base=os.environ['BASE_SHA']; head=os.environ['HEAD_SHA']
assert base=='918d44ebc2962a53d23eeee52b8f44c7816e7815'
prod='Ghidra/Features/Base/src/main/java/ghidra/app/cmd/function/CreateFunctionCmd.java'
new='Ghidra/Features/Base/src/test/java/ghidra/app/cmd/function/CreateFunctionCmdResultTest.java'
classes=['ghidra.app.cmd.function.CreateFunctionCmdResultTest','ghidra.app.cmd.function.CreateFunctionCmdTest','ghidra.app.cmd.function.CreateFunctionCmdWithFlowTest']
paths=[new]+['Ghidra/Features/Base/src/test/java/'+c.replace('.','/')+'.java' for c in classes[1:]]
targets={'testUndisassembledFindEntryReportsFailure':'No function must not report success','testNewExternalFunctionReportsSuccess':'Successful external command must report success','testExistingExternalFunctionReportsSuccess':'Successful external command must report success','testMixedInternalExternalReportsSuccess':'Both real function operations succeeded'}
markers=[('undisassembled',True,False,False),('new-external',False,True,True),('existing-external',False,True,True),('mixed',False,True,True),('internal-control',True,True,True),('missing-external-control',False,False,False),('canceled-control',False,False,False),('undefined-explicit-control',True,True,True),('existing-undefined-control',True,True,True),('null-instruction-fixup-control',True,True,False)]
r={'base':base,'head':head,'status':'running','steps':[],'full_build_passed':False}
def save():(e/'receipt.json').write_text(json.dumps(r,indent=2)+'\n')
def sha(b):return hashlib.sha256(b).hexdigest()
def git(*args):return subprocess.check_output(['git',*args])
def run(label,args):
 with(e/(label+'.log')).open('w') as f:x=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT,timeout=3600)
 r['steps'].append({'label':label,'args':args,'exit_code':x.returncode});save();print(label,x.returncode,flush=True);return x.returncode
try:
 assert git('rev-parse','HEAD').decode().strip()==head
 assert set(git('diff','--name-only',base,head).decode().splitlines())=={prod,new}
 expected=set(); originals={}
 for c,path,count in zip(classes,paths,[10,9,3]):
  b=(p/path).read_bytes(); names=re.findall(r'@Test\s+public void (test\w+)\(',b.decode());assert len(names)==count
  expected.update((c,n) for n in names)
  if c!=classes[0]:assert b==git('show',base+':'+path);originals[path]=sha(b)
 r['original_test_source_sha256']=originals
 fixed=(p/prod).read_bytes(); original=git('show',base+':'+prod)
 r['baseline_production_sha256']=sha(original);r['fixed_production_sha256']=sha(fixed);assert original!=fixed
 g=['./gradlew','--no-daemon','--max-workers=2','-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
 assert run('fetch',g+['-I','gradle/support/fetchDependencies.gradle','-DhideDownloadProgress','-DnoEclipse'])==0
 assert run('prep',g+['prepDev'])==0
 assert run('actual-native-and-languages',g+[':Decompiler:buildNatives',':x86:sleighCompile',':PowerPC:sleighCompile',':Toy:sleighCompile'])==0
 native=p/'Ghidra/Features/Decompiler/build/os/linux_x86_64/decompile';assert native.is_file();r['native_executable_sha256']=sha(native.read_bytes())
 cmd=['xvfb-run','-a','-s','-screen 0 1600x1200x24']+g+[':Base:test']
 for c in classes:cmd+=['--tests',c]
 for phase,b in [('baseline',original),('fixed',fixed)]:
  (p/prod).write_bytes(b); assert sha((p/prod).read_bytes())==r[phase+'_production_sha256']
  results=p/'Ghidra/Features/Base/build/test-results/test';shutil.rmtree(results,ignore_errors=True)
  code=run(phase,cmd);assert code in (0,1)
  dest=e/(phase+'-xml');shutil.copytree(results,dest);cases={};out='';hashes={}
  for f in dest.glob('*.xml'):
   hashes[f.name]=sha(f.read_bytes());root=ET.parse(f).getroot();assert root.get('errors')=='0' and root.get('skipped')=='0';out+=root.findtext('system-out','')
   for t in root.iter('testcase'):
    key=(t.get('classname'),t.get('name'));assert key not in cases and t.find('error') is None and t.find('skipped') is None
    failure=t.find('failure');cases[key]={'failed':failure is not None,'message':failure.get('message') if failure is not None else ''}
    if failure is not None:assert phase=='baseline' and key[0]==classes[0] and key[1] in targets and failure.get('type')=='java.lang.AssertionError' and failure.get('message')=='java.lang.AssertionError: '+targets[key[1]]
  assert set(cases)==expected and len(cases)==22
  failed={k for k,v in cases.items() if v['failed']};assert failed==({(classes[0],n) for n in targets} if phase=='baseline' else set())
  if phase=='fixed':assert code==0
  for name,bresult,fresult,effect in markers:
   actual=bresult if phase=='baseline' else fresult
   assert f'CREATE_FUNCTION_RESULT fixture={name} result={str(actual).lower()} effect={str(effect).lower()}' in out
  for path,h in originals.items():assert sha((p/path).read_bytes())==h
  r[phase]={'exit_code':code,'cases':[{'class':k[0],'name':k[1],**v} for k,v in sorted(cases.items())],'xml_sha256':hashes};save()
 assert all(not c['failed'] for phase in ['baseline','fixed'] for c in r[phase]['cases'] if c['class']!=classes[0])
 assert run('full-build',g+['buildGhidra'])==0
 assert 'BUILD SUCCESSFUL' in (e/'full-build.log').read_text()
 assert not git('diff','--name-only','HEAD').decode().strip()
 assert (p/prod).read_bytes()==fixed
 r['status']='passed';r['full_build_passed']=True
except Exception as ex:
 r['status']='failed';r['error']=str(ex);r['traceback']=traceback.format_exc();raise
finally:save()
