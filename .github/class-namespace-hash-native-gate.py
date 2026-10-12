import datetime,hashlib,json,os,pathlib,re,shutil,signal,subprocess,traceback
import xml.etree.ElementTree as ET
p=pathlib.Path.cwd().resolve();e=pathlib.Path(os.environ['EVIDENCE_DIR']).resolve()
assert e != p and p not in e.parents
e.mkdir(parents=True,exist_ok=True)
head=os.environ['HEAD_SHA'];base=os.environ['BASE_SHA']
klass='ghidra.program.database.symbol.ClassNamespaceHashTest'
original='ghidra.program.database.symbol.NamespaceManagerTest'
fixture='Ghidra/Features/Base/src/test.slow/java/'+klass.replace('.','/')+'.java'
original_path='Ghidra/Features/Base/src/test.slow/java/'+original.replace('.','/')+'.java'
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def digest(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
 return h.hexdigest()
def git(*args):return subprocess.check_output(['git',*args])
r={'started_at':utc(),'head':head,'base':base,'purpose':'Actual class namespace hash baseline/fixed qualification','status':'INCONCLUSIVE','publication_gate':False,'full_build_passed':False,'steps':[]}
def save():(e/'receipt.json').write_text(json.dumps(r,indent=2)+'\n')
def run(label,args):
 started=utc();log=e/(label+'.log');proc=None;code='TIMEOUT'
 try:
  with log.open('wb') as out:
   proc=subprocess.Popen(args,stdout=out,stderr=subprocess.STDOUT,start_new_session=True)
   try:code=proc.wait(timeout=3600)
   except subprocess.TimeoutExpired:
    os.killpg(proc.pid,signal.SIGKILL);proc.wait(timeout=10)
 finally:
  if proc is not None and proc.poll() is None:
   os.killpg(proc.pid,signal.SIGKILL);proc.wait(timeout=10)
  r['steps'].append({'label':label,'args':args,'exit_code':code,'started_at':started,'finished_at':utc(),'log_sha256':digest(log)});save()
 return code
def read_results(label,expected):
 result=p/'Ghidra/Features/Base/build/test-results/integrationTest';dest=e/(label+'-xml');shutil.copytree(result,dest)
 cases={};metadata={}
 for file in dest.glob('*.xml'):
  root=ET.parse(file).getroot();name=root.get('name');assert name in expected and root.get('timestamp')
  counts={k:int(root.get(k,'0')) for k in ['tests','failures','errors','skipped']};items=root.findall('testcase')
  observed={k:sum(x.find(tag) is not None for x in items) for k,tag in [('failures','failure'),('errors','error'),('skipped','skipped')]}
  assert counts['tests']==len(items) and all(counts[k]==v for k,v in observed.items())
  metadata[file.name]={'class':name,'timestamp':root.get('timestamp'),'counts':counts,'sha256':digest(file)}
  for item in items:
   key=(item.get('classname'),item.get('name'));assert key[0]==name and key not in cases
   children=[x for x in item if x.tag in ['failure','error','skipped']];assert len(children)<=1
   cases[key]={'kind':children[0].tag,'type':children[0].get('type'),'message':children[0].get('message')} if children else {'kind':'PASS'}
 assert set(cases)=={(c,n) for c,names in expected.items() for n in names}
 r[label]={'observed_at':utc(),'cases':[{'class':c,'name':n,**v} for (c,n),v in sorted(cases.items())],'xml':metadata};save();return cases
try:
 assert base=='918d44ebc2962a53d23eeee52b8f44c7816e7815' and git('rev-parse','HEAD').decode().strip()==head
 production='Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/database/symbol/GhidraClassDB.java'
 assert set(git('diff','--name-only',base,head).decode().splitlines())=={fixture,production}
 assert (p/original_path).read_bytes()==git('show',base+':'+original_path)
 originals=set(re.findall(r'@Test\s+public void (\w+)\(', (p/original_path).read_text()));assert len(originals)==11
 targets={'testEquivalentClassMapLookup','testEquivalentClassSetRemoval'};control='testOrdinaryNamespaceAndLibraryControls'
 assert set(re.findall(r'@Test\s+public void (\w+)\(', (p/fixture).read_text()))==targets|{control}
 fixed=(p/production).read_bytes();baseline=git('show',base+':'+production);assert fixed!=baseline
 r['production']={'path':production,'baseline_sha256':hashlib.sha256(baseline).hexdigest(),'fixed_sha256':hashlib.sha256(fixed).hexdigest()}
 r['fixture_sha256']=digest(p/fixture);r['original_sha256']=digest(p/original_path);save()
 for name in ['ClassSymbol','NamespaceDB','LibraryDB','SymbolManager']:
  path='Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/database/symbol/'+name+'.java';assert (p/path).read_bytes()==git('show',base+':'+path)
 g=['./gradlew','--no-daemon','--max-workers=2','-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
 assert run('fetch',g+['-I','gradle/support/fetchDependencies.gradle','-DhideDownloadProgress','-DnoEclipse'])==0
 assert run('prep',g+['prepDev'])==0
 assert run('actual-native-and-toy',g+[':Decompiler:buildNatives',':Toy:sleighCompile'])==0
 native=p/'Ghidra/Features/Decompiler/build/os/linux_x86_64/decompile';assert native.is_file();slas=list((p/'Ghidra/Processors/Toy/data/languages').glob('*.sla'));assert slas
 r['actual_native']={'path':str(native.relative_to(p)),'sha256':digest(native)};r['actual_toy']=[{'path':str(x.relative_to(p)),'sha256':digest(x)} for x in sorted(slas)];save()
 def invoke(label,classes):
  shutil.rmtree(p/'Ghidra/Features/Base/build/test-results/integrationTest',ignore_errors=True)
  args=['xvfb-run','-a','-s','-screen 0 1600x1200x24']+g+[':Base:integrationTest']
  for c in classes:args+=['--tests',c]
  code=run(label,args);assert code in (0,1);return code
 expected={'testEquivalentClassMapLookup':'Equivalent class must find its existing recovery entry expected:<existing recovered class> but was:<null>','testEquivalentClassSetRemoval':'Equivalent class must remove its pending entry'}
 old_outcomes={}
 for phase,data in [('baseline',baseline),('fixed',fixed)]:
  (p/production).write_bytes(data);assert (p/production).read_bytes()==data
  r[phase+'-source']={'production_sha256':digest(p/production),'fixture_sha256':digest(p/fixture),'original_sha256':digest(p/original_path),'observed_at':utc()};save()
  label=phase+'-public-collections';code=invoke(label,[klass]);cases=read_results(label,{klass:targets|{control}})
  assert cases[(klass,control)]=={'kind':'PASS'}
  if phase=='fixed':assert code==0 and all(v=={'kind':'PASS'} for v in cases.values())
  else:
   assert {n for (c,n),v in cases.items() if v['kind']=='failure'}==targets
   for name in targets:
    x=cases[(klass,name)];assert x['kind']=='failure' and x['type']=='java.lang.AssertionError';message=x['message'] or '';prefix='java.lang.AssertionError: '
    if message.startswith(prefix):message=message[len(prefix):]
    assert message==expected[name],(name,message)
  label=phase+'-unchanged-namespace-tests';code=invoke(label,[original]);old_outcomes[phase]=read_results(label,{original:originals})
  assert code==0 and all(v=={'kind':'PASS'} for v in old_outcomes[phase].values())
 assert old_outcomes['baseline']==old_outcomes['fixed']
 assert (p/production).read_bytes()==fixed
 assert run('full-build',g+['buildGhidra'])==0
 assert 'BUILD SUCCESSFUL' in (e/'full-build.log').read_text()
 status=git('status','--porcelain').decode();(e/'final-git-status.txt').write_text(status)
 r['final_status']={'porcelain':status,'sha256':digest(e/'final-git-status.txt')};save();assert not status.strip()
 r.update(status='PASSED_CLASS_HASH_14_CASES_BASELINE_FIXED_FULL_BUILD',full_build_passed=True,publication_gate=True)
except Exception as ex:
 r.update(status='INCONCLUSIVE',error=str(ex),traceback=traceback.format_exc());raise
finally:
 if 'fixed' in globals():(p/production).write_bytes(fixed)
 r['finished_at']=utc();save()
