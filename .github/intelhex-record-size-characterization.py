import datetime,hashlib,json,os,pathlib,re,shutil,signal,subprocess,traceback
import xml.etree.ElementTree as ET
p=pathlib.Path.cwd().resolve();e=pathlib.Path(os.environ['EVIDENCE_DIR']).resolve()
assert e != p and p not in e.parents
e.mkdir(parents=True,exist_ok=True)
head=os.environ['HEAD_SHA'];base=os.environ['BASE_SHA']
klass='ghidra.app.util.exporter.IntelHexRecordSizeCharacterizationTest'
fixture='Ghidra/Features/Base/src/test.slow/java/'+klass.replace('.','/')+'.java'
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def digest(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
 return h.hexdigest()
def git(*args):return subprocess.check_output(['git',*args])
r={'started_at':utc(),'head':head,'base':base,'purpose':'Actual IntelHex accepted record-size public editor/export characterization','status':'INCONCLUSIVE','publication_gate':False,'full_build_passed':False,'steps':[]}
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
def read_results(label,expected,module="Ghidra/Features/Base",task="integrationTest"):

 result=p/(module+'/build/test-results/'+task);dest=e/(label+'-xml');shutil.copytree(result,dest)
 cases={};metadata={}
 for file in dest.glob('*.xml'):
  root=ET.parse(file).getroot();name=root.get('name');assert name in expected and root.get('timestamp')
  step=next(x for x in reversed(r['steps']) if x['label']==label)
  begin=datetime.datetime.fromisoformat(step['started_at']);end=datetime.datetime.fromisoformat(step['finished_at']);stamp=datetime.datetime.fromisoformat(root.get('timestamp'));stamp=stamp.replace(tzinfo=datetime.timezone.utc) if stamp.tzinfo is None else stamp
  assert begin-datetime.timedelta(seconds=2)<=stamp<=end+datetime.timedelta(seconds=2) and file.stat().st_mtime>=begin.timestamp()-2
  counts={k:int(root.get(k,'0')) for k in ['tests','failures','errors','skipped']};items=root.findall('testcase')
  observed={k:sum(x.find(tag) is not None for x in items) for k,tag in [('failures','failure'),('errors','error'),('skipped','skipped')]}
  assert counts['tests']==len(items) and all(counts[k]==v for k,v in observed.items())
  metadata[file.name]={'class':name,'timestamp':root.get('timestamp'),'counts':counts,'sha256':digest(file)}
  for item in items:
   key=(item.get('classname'),item.get('name'));assert key[0]==name and key not in cases
   children=[x for x in item if x.tag in ['failure','error','skipped']];assert len(children)<=1
   cases[key]={'kind':children[0].tag,'type':children[0].get('type'),'message':children[0].get('message')} if children else {'kind':'PASS'}
 assert set(cases)=={(c,n) for c,names in expected.items() for n in names}
 r[label]={'observed_at':utc(),'cases':[{'class':c,'name':n,**v} for (c,n),v in sorted(cases.items())],'xml':metadata,'markers':[line for file in dest.glob('*.xml') for line in ET.parse(file).getroot().findtext('system-out','').splitlines() if line.startswith('INTELHEX_SIZE_')]};save();return cases
try:
 assert base=='918d44ebc2962a53d23eeee52b8f44c7816e7815' and git('rev-parse','HEAD').decode().strip()==head
 assert git('diff','--name-only',base,head).decode().splitlines()==[fixture]
 targets={'testHexPrefix','testHashHexPrefix','testAcceptedOctalPrefix'}
 controls={'testDecimalControl','testEmptyDefaultControl','testInvalidTooLargeDefaultControl'}
 assert set(re.findall(r'@Test\s+public void (\w+)\(', (p/fixture).read_text()))==targets|controls
 originals={};r['original_hashes']={}
 for name,count in [('IntelHexRecordTest',2),('IntelHexRecordReaderTest',1)]:
  path='Ghidra/Features/Base/src/test/java/ghidra/app/util/opinion/'+name+'.java';assert (p/path).read_bytes()==git('show',base+':'+path)
  methods=set(re.findall(r'@Test\s+public void (\w+)\(', (p/path).read_text()));assert len(methods)==count
  originals['ghidra.app.util.opinion.'+name]=methods;r['original_hashes'][path]=digest(p/path)
 r['production_sha256']={}
 for path in ['Ghidra/Features/Base/src/main/java/ghidra/app/util/exporter/IntelHexExporter.java','Ghidra/Features/Base/src/main/java/ghidra/app/util/opinion/IntelHexRecordWriter.java','Ghidra/Framework/Docking/src/main/java/docking/widgets/textfield/HintTextField.java']:
  assert (p/path).read_bytes()==git('show',base+':'+path);r['production_sha256'][path]=digest(p/path)
 r['fixture_sha256']=digest(p/fixture);save()
 g=['./gradlew','--no-daemon','--max-workers=2','-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
 assert run('fetch',g+['-I','gradle/support/fetchDependencies.gradle','-DhideDownloadProgress','-DnoEclipse'])==0
 assert run('prep',g+['prepDev'])==0
 assert run('actual-native-and-toy',g+[':Decompiler:buildNatives',':Toy:sleighCompile'])==0
 native=p/'Ghidra/Features/Decompiler/build/os/linux_x86_64/decompile';assert native.is_file();slas=list((p/'Ghidra/Processors/Toy/data/languages').glob('*.sla'));assert slas
 r['actual_native']={'path':str(native.relative_to(p)),'sha256':digest(native)};r['actual_toy']=[{'path':str(x.relative_to(p)),'sha256':digest(x)} for x in sorted(slas)];save()
 def invoke(label,classes,module='Ghidra/Features/Base',task='integrationTest'):
  shutil.rmtree(p/(module+'/build/test-results/'+task),ignore_errors=True)
  args=['xvfb-run','-a','-s','-screen 0 1600x1200x24']+g+[':'+module.split('/')[-1]+':'+task]
  for c in classes:args+=['--tests',c]
  code=run(label,args);assert code in (0,1);return code
 code=invoke('actual-editor-export',[klass]);cases=read_results('actual-editor-export',{klass:targets|controls})
 assert all(cases[(klass,n)]=={'kind':'PASS'} for n in controls)
 assert all(v['kind'] in ['PASS','failure'] for v in cases.values())
 failures={n for (c,n),v in cases.items() if v['kind']=='failure'};assert failures in (targets,set())
 def validate_failures(rows):
  for name in failures:
   x=rows[(klass,name)];assert x['type']=='java.lang.AssertionError'
   expected='Actual accepted record-size data lengths expected:<[8, 8, 4]> but was:<[10, 10]>' if name=='testAcceptedOctalPrefix' else 'Actual valid record-size option must export expected:<true> but was:<false>'
   assert (x['message'] or '').removeprefix('java.lang.AssertionError: ')==expected
 validate_failures(cases)
 if not failures:assert code==0
 markers=r['actual-editor-export']['markers'];expected=[]
 for text,valid,size in [('0x10',True,16),('#10',True,16),('010',True,8),('16',True,16),('EMPTY',False,16),('256',False,16)]:
  broken=bool(failures) and text in ['0x10','#10'];expected.append(f'INTELHEX_SIZE_INPUT text={text} valid={str(valid).lower()} expectedSize={size} exported={str(not broken).lower()} error={"java.lang.NumberFormatException" if broken else "NONE"}')
  if not broken:
   lengths='[10, 10]' if failures and text=='010' else '[8, 8, 4]' if text=='010' else '[16, 4]'
   expected.append(f'INTELHEX_SIZE_OUTPUT text={text} lengths={lengths} bytes=20 eof=1')
 assert sorted(markers)==sorted(expected)
 code=invoke('original-record-tests',sorted(originals),'Ghidra/Features/Base','test');old=read_results('original-record-tests',originals,'Ghidra/Features/Base','test');r['original_all_passed']=all(v=={'kind':'PASS'} for v in old.values())
 if r['original_all_passed']:assert code==0
 for path,sha in r['production_sha256'].items():assert digest(p/path)==sha
 for path,sha in r['original_hashes'].items():assert digest(p/path)==sha
 assert digest(p/fixture)==r['fixture_sha256']
 status=git('status','--porcelain');(e/'final-git-status.bin').write_bytes(status);r['final_status']={'bytes':len(status),'sha256':hashlib.sha256(status).hexdigest()};save();assert status==b''
 r['status']='REPRODUCED_ACCEPTED_RECORD_SIZE_MISMATCH' if failures else 'NOT_REPRODUCED'
except Exception as ex:
 r.update(status='INCONCLUSIVE',error=str(ex),traceback=traceback.format_exc());raise
finally:r['finished_at']=utc();save()
