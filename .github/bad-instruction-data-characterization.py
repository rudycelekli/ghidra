import datetime,hashlib,json,os,pathlib,re,shutil,signal,subprocess,traceback
import xml.etree.ElementTree as ET
p=pathlib.Path.cwd().resolve();e=pathlib.Path(os.environ['EVIDENCE_DIR']).resolve()
assert e != p and p not in e.parents
e.mkdir(parents=True,exist_ok=True)
head=os.environ['HEAD_SHA'];base=os.environ['BASE_SHA']
klass='ghidra.app.cmd.data.BadInstructionDataCharacterizationTest'
original='ghidra.app.cmd.data.CreateDataCmdTest'
fixture='Ghidra/Features/Base/src/test/java/'+klass.replace('.','/')+'.java'
original_path='Ghidra/Features/Base/src/test/java/'+original.replace('.','/')+'.java'
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def digest(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
 return h.hexdigest()
def git(*args):return subprocess.check_output(['git',*args])
r={'started_at':utc(),'head':head,'base':base,'purpose':'Actual disassembly diagnostics after public data creation characterization','status':'INCONCLUSIVE','publication_gate':False,'full_build_passed':False,'steps':[]}
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
 result=p/'Ghidra/Features/Base/build/test-results/test';dest=e/(label+'-xml');shutil.copytree(result,dest)
 cases={};metadata={};markers=[]
 for file in dest.glob('*.xml'):
  root=ET.parse(file).getroot();name=root.get('name');assert name in expected and root.get('timestamp')
  counts={k:int(root.get(k,'0')) for k in ['tests','failures','errors','skipped']};items=root.findall('testcase')
  observed={k:sum(x.find(tag) is not None for x in items) for k,tag in [('failures','failure'),('errors','error'),('skipped','skipped')]}
  assert counts['tests']==len(items) and all(counts[k]==v for k,v in observed.items())
  metadata[file.name]={'class':name,'timestamp':root.get('timestamp'),'counts':counts,'sha256':digest(file)}
  markers += re.findall(r'^BAD_DATA_OBSERVATION .+$',root.findtext('system-out',''),re.MULTILINE)
  for item in items:
   key=(item.get('classname'),item.get('name'));assert key[0]==name and key not in cases
   children=[x for x in item if x.tag in ['failure','error','skipped']];assert len(children)<=1
   cases[key]={'kind':children[0].tag,'type':children[0].get('type'),'message':children[0].get('message')} if children else {'kind':'PASS'}
 assert set(cases)=={(c,n) for c,names in expected.items() for n in names}
 r[label]={'observed_at':utc(),'cases':[{'class':c,'name':n,**v} for (c,n),v in sorted(cases.items())],'xml':metadata,'markers':markers};save();return cases
try:
 assert base=='918d44ebc2962a53d23eeee52b8f44c7816e7815' and git('rev-parse','HEAD').decode().strip()==head
 assert git('diff','--name-only',base,head).decode().splitlines()==[fixture]
 assert (p/original_path).read_bytes()==git('show',base+':'+original_path)
 originals=set(re.findall(r'@Test\s+public void (\w+)\(', (p/original_path).read_text()));assert len(originals)==24
 targets={'testAppliedDataRemovesObsoleteParseError'}
 controls={'testCustomNoteSurvivesDataCreation','testIndependentErrorSurvivesDataCreation','testActualCallToDataConflictSurvivesDataReplacement','testFailedDataCreationPreservesInstructionAndBookmark'}
 assert set(re.findall(r'@Test\s+public void (\w+)\(', (p/fixture).read_text()))==targets|controls
 paths=['Ghidra/Features/Base/src/main/java/ghidra/app/cmd/data/CreateDataCmd.java','Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/disassemble/Disassembler.java','Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/data/DataUtilities.java']
 r['production_sha256']={}
 for path in paths:
  assert (p/path).read_bytes()==git('show',base+':'+path);r['production_sha256'][path]=digest(p/path)
 r['fixture_sha256']=digest(p/fixture);r['original_sha256']=digest(p/original_path);save()
 g=['./gradlew','--no-daemon','--max-workers=2','-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
 assert run('fetch',g+['-I','gradle/support/fetchDependencies.gradle','-DhideDownloadProgress','-DnoEclipse'])==0
 assert run('prep',g+['prepDev'])==0
 assert run('actual-native-and-toy',g+[':Decompiler:buildNatives',':Toy:sleighCompile'])==0
 native=p/'Ghidra/Features/Decompiler/build/os/linux_x86_64/decompile';assert native.is_file();slas=list((p/'Ghidra/Processors/Toy/data/languages').glob('*.sla'));assert slas
 r['actual_native']={'path':str(native.relative_to(p)),'sha256':digest(native)};r['actual_toy']=[{'path':str(x.relative_to(p)),'sha256':digest(x)} for x in sorted(slas)];save()
 def invoke(label,classes):
  shutil.rmtree(p/'Ghidra/Features/Base/build/test-results/test',ignore_errors=True)
  args=['xvfb-run','-a','-s','-screen 0 1600x1200x24']+g+[':Base:test']
  for c in classes:args+=['--tests',c]
  code=run(label,args);assert code in (0,1);return code
 code=invoke('public-data-producers',[klass]);cases=read_results('public-data-producers',{klass:targets|controls})
 assert all(cases[(klass,c)]=={'kind':'PASS'} for c in controls)
 assert all(v['kind'] in ['PASS','failure'] for v in cases.values())
 failures={n for (c,n),v in cases.items() if v['kind']=='failure'};assert failures in (set(),targets)
 for name in failures:
  x=cases[(klass,name)];assert x['type']=='java.lang.AssertionError';message=x['message'] or '';prefix='java.lang.AssertionError: '
  if message.startswith(prefix):message=message[len(prefix):]
  assert message=='Obsolete parse-error bookmark must be removed after data creation',message
 if not failures:assert code==0
 markers=r['public-data-producers']['markers']
 expected_markers={'BAD_DATA_OBSERVATION case=parse-error dataLength=2 obsoleteBookmark='+('true' if failures else 'false'),'BAD_DATA_OBSERVATION case=call-conflict dataLength=2 conflictPreserved=true','BAD_DATA_OBSERVATION case=rejected-data instructionPreserved=true bookmarkPreserved=true','BAD_DATA_OBSERVATION case=custom-note dataLength=2 bookmarkPreserved=true','BAD_DATA_OBSERVATION case=independent-error dataLength=2 bookmarkPreserved=true'}
 assert len(markers)==5 and set(markers)==expected_markers
 code=invoke('unchanged-create-data-tests',[original]);old=read_results('unchanged-create-data-tests',{original:originals})
 r['original_all_passed']=all(v=={'kind':'PASS'} for v in old.values())
 if r['original_all_passed']:assert code==0
 status=git('status','--porcelain').decode()
 (e/'final-git-status.txt').write_text(status)
 r['final_status']={'porcelain':status,'sha256':digest(e/'final-git-status.txt')};save()
 assert not status.strip()
 r['status']='REPRODUCED_OBSOLETE_PARSE_DIAGNOSTIC_AFTER_PUBLIC_DATA_CREATION' if failures else 'NOT_REPRODUCED'
except Exception as ex:
 r.update(status='INCONCLUSIVE',error=str(ex),traceback=traceback.format_exc());raise
finally:r['finished_at']=utc();save()
