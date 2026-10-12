import datetime,hashlib,json,os,pathlib,re,shutil,signal,subprocess,traceback
import xml.etree.ElementTree as ET
p=pathlib.Path.cwd().resolve();e=pathlib.Path(os.environ['EVIDENCE_DIR']).resolve();assert e!=p and p not in e.parents;e.mkdir(parents=True,exist_ok=True)
head=os.environ['HEAD_SHA'];base=os.environ['BASE_SHA'];klass='ghidra.app.util.exporter.OriginalFileRelocationCharacterizationTest'
fixture='Ghidra/Features/Base/src/test.slow/java/'+klass.replace('.','/')+'.java'
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sha(b):return hashlib.sha256(b).hexdigest()
def git(*a):return subprocess.check_output(['git',*a])
r={'utc':utc(),'head':head,'base':base,'status':'INCONCLUSIVE','discovery_only':True,'publication_gate':False,'full_build_passed':False,'steps':[]}
def save():(e/'receipt.json').write_text(json.dumps(r,indent=2)+'\n')
def run(label,args):
 start=utc();proc=None;code='TIMEOUT'
 try:
  with (e/(label+'.log')).open('wb') as f:
   proc=subprocess.Popen(args,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
   try:code=proc.wait(timeout=3600)
   except subprocess.TimeoutExpired:
    os.killpg(proc.pid,signal.SIGKILL);proc.wait(timeout=10)
 finally:
  if proc is not None and proc.poll() is None:
   os.killpg(proc.pid,signal.SIGKILL);proc.wait(timeout=10)
  r['steps'].append({'label':label,'args':args,'exit_code':code,'started_at':start,'ended_at':utc(),'log_sha256':sha((e/(label+'.log')).read_bytes())});save()
 return code
def parse_xml(label,results,expected):
 dest=e/(label+'-xml');shutil.copytree(results,dest);files=list(dest.glob('*.xml'));assert len(files)==len(expected)
 step=r['steps'][-1];start=datetime.datetime.fromisoformat(step['started_at']).timestamp();end=datetime.datetime.fromisoformat(step['ended_at']).timestamp()
 cases={};metadata={};stdout=''
 for file in files:
  rr=ET.parse(file).getroot();name=rr.get('name');assert name in expected and name not in metadata
  stamp=datetime.datetime.fromisoformat(rr.get('timestamp').replace('Z','+00:00'));assert stamp.tzinfo is not None
  mtime=file.stat().st_mtime;assert start-1<=stamp.timestamp()<=end+1 and start-1<=mtime<=end+1
  items=rr.findall('testcase');counts={k:int(rr.get(k)) for k in ['tests','failures','errors','skipped']};assert counts['tests']==len(items)
  observed={k:0 for k in ['failures','errors','skipped']}
  for t in items:
   key=(t.get('classname'),t.get('name'));assert key[0]==name and key not in cases
   children=[x for x in t if x.tag in ['failure','error','skipped']];assert len(children)<=1
   if children:
    x=children[0];observed[{'failure':'failures','error':'errors','skipped':'skipped'}[x.tag]]+=1
    cases[key]={'kind':x.tag,'type':x.get('type'),'message':x.get('message'),'trace':x.text}
   else:cases[key]={'kind':'PASS'}
  assert all(counts[k]==v for k,v in observed.items())
  stdout+=rr.findtext('system-out','')+'\n';metadata[file.name]={'class':name,'counts':counts,'timestamp':rr.get('timestamp'),'mtime_utc':datetime.datetime.fromtimestamp(mtime,datetime.timezone.utc).isoformat(),'sha256':sha(file.read_bytes())}
 assert set(cases)=={(c,n) for c,names in expected.items() for n in names}
 r[label]={'cases':[{'class':c,'name':n,**v} for (c,n),v in sorted(cases.items())],'xml':metadata,'producer_interval':{'start':step['started_at'],'end':step['ended_at']}};save();return cases,stdout
try:
 assert base=='918d44ebc2962a53d23eeee52b8f44c7816e7815' and git('rev-parse','HEAD').decode().strip()==head
 assert git('rev-parse',head+'^').decode().strip()==base
 assert git('diff','--name-only',base,head).decode().splitlines()==[fixture]
 targets={'testDirectoryExportDoesNotUndoOtherSourceRelocation':"Secondary source must not receive another source's relocation bytes",'testPrimaryExportDoesNotUndoSecondarySourceRelocation':"Primary source must not receive another source's relocation bytes",'testNonzeroOriginalOffsetUsesRelativeOutputPosition':'FileBytes original offset must not shift or extend exported bytes'}
 methods=set(re.findall(r'@Test public void (\w+)\(', (p/fixture).read_text()));assert methods=={'testSkippedRelocationRetainsModifiedBytes', 'testModificationsDisabledExportsOriginalBytes', 'testOwnRelocationPreservesIndependentUserEdit', 'testPrimaryExportDoesNotUndoSecondarySourceRelocation', 'testByteMappedRelocationStillUndoesOwnSource', 'testDirectoryExportDoesNotUndoOtherSourceRelocation', 'testUnbackedRelocationDoesNotChangeFileBytes', 'testNonzeroOriginalOffsetUsesRelativeOutputPosition'} and set(targets)<=methods
 original_class='ghidra.program.database.mem.FileBytesTest';original_path='Ghidra/Framework/SoftwareModeling/src/test/java/'+original_class.replace('.','/')+'.java'
 assert (p/original_path).read_bytes()==git('show',base+':'+original_path)
 original_methods=set(re.findall(r'@Test\s+public void (\w+)\(', (p/original_path).read_text()));assert len(original_methods)==10
 products=['Ghidra/Features/Base/src/main/java/ghidra/app/util/exporter/OriginalFileExporter.java','Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/database/mem/AddressSourceInfo.java','Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/database/mem/FileBytes.java','Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/database/reloc/RelocationManager.java']
 for path in products:assert (p/path).read_bytes()==git('show',base+':'+path)
 r['purpose']='Actual inert-byte public original-file export relocation characterization';r['production_sha256']={x:sha((p/x).read_bytes()) for x in products};r['fixture_sha256']=sha((p/fixture).read_bytes());r['original']={'path':original_path,'sha256':sha((p/original_path).read_bytes()),'class':original_class,'methods':sorted(original_methods)};save()
 g=['./gradlew','--no-daemon','--max-workers=2','-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
 assert run('fetch',g+['-I','gradle/support/fetchDependencies.gradle','-DhideDownloadProgress','-DnoEclipse'])==0
 assert run('prep',g+['prepDev'])==0
 assert run('actual-toy-language',g+[':Toy:sleighCompile'])==0
 r['toy_sha256']={str(x.relative_to(p)):sha(x.read_bytes()) for x in (p/'Ghidra/Processors/Toy/data/languages').glob('*.sla')};assert r['toy_sha256'];save()
 results=p/'Ghidra/Features/Base/build/test-results/integrationTest';shutil.rmtree(results,ignore_errors=True)
 code=run('actual-public-original-export',g+[':Base:integrationTest','--tests',klass]);assert code in (0,1)
 cases,stdout=parse_xml('actual-public-original-export',results,{klass:methods})
 failures={n for (c,n),x in cases.items() if x['kind']!='PASS'};assert failures==set(targets) or failures==set()
 for c,n in cases:
  x=cases[(c,n)]
  if n in failures:assert x['kind']=='failure' and x['type']=='java.lang.AssertionError' and (x['message'] or '').removeprefix('java.lang.AssertionError: ')==targets[n]
  else:assert x=={'kind':'PASS'}
 if not failures:assert code==0
 expected={'directory-foreign':(2,1,True,['0102030405060708','2122232425262728']),'primary-foreign':(2,1,True,['0102030405060708']),'nonzero-offset':(1,1,True,['0102030405060708']),'own-source':(1,1,True,['010203040506074d']),'mapped-own':(1,1,True,['0102030405060708']),'skipped':(1,1,True,['0102636205060708']),'unmodified':(2,1,False,['0102030405060708','2122232425262728']),'unbacked':(1,1,True,['0102030405060708'])}
 if failures:
  expected['directory-foreign']=(2,1,True,['0102030405060708','2122030425262728'])
  expected['primary-foreign']=(2,1,True,['0102232405060708'])
  expected['nonzero-offset']=(1,1,True,['0102636205060708'+'00'*58+'0304'])
 markers=[l for l in stdout.splitlines() if l.startswith('ORIGINAL_FILE_RELOCATION ')];assert len(markers)==8;observed={}
 for line in markers:
  m=re.fullmatch(r'ORIGINAL_FILE_RELOCATION case=(\S+) sources=(\d+) relocations=(\d+) modifications=(true|false) output=([0-9a-f,]+)',line);assert m
  name=m[1];assert name in expected and name not in observed;outputs=m[5].split(',');assert all(len(x)%2==0 for x in outputs)
  result=(int(m[2]),int(m[3]),m[4]=='true',outputs);assert result==expected[name]
  observed[name]={'sources':result[0],'relocations':result[1],'modifications':result[2],'output_hex':outputs,'output_lengths':[len(x)//2 for x in outputs]}
 assert set(observed)==set(expected);r['observations']=observed;r['target_failure_names']=sorted(failures);save()
 oldresults=p/'Ghidra/Framework/SoftwareModeling/build/test-results/test';shutil.rmtree(oldresults,ignore_errors=True)
 code=run('original-filebytes-tests',g+[':SoftwareModeling:test','--tests',original_class]);assert code in (0,1)
 old,_=parse_xml('original-filebytes-tests',oldresults,{original_class:original_methods});r['original_all_passed']=all(x['kind']=='PASS' for x in old.values())
 if r['original_all_passed']:assert code==0
 for path,h in r['production_sha256'].items():assert sha((p/path).read_bytes())==h
 assert sha((p/fixture).read_bytes())==r['fixture_sha256'] and sha((p/original_path).read_bytes())==r['original']['sha256']
 status=git('status','--porcelain');(e/'final-git-status.bin').write_bytes(status);r['final_status_sha256']=sha(status);save();assert status==b''
 r['status']='REPRODUCED_ORIGINAL_FILE_RELOCATION_SOURCE_OFFSET_MISMATCH' if failures else 'NOT_REPRODUCED'
except Exception as ex:r.update(status='INCONCLUSIVE',error=str(ex),traceback=traceback.format_exc());raise
finally:r['finished_at']=utc();save()
