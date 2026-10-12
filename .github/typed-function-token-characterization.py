import datetime,hashlib,json,os,pathlib,re,shutil,signal,subprocess,traceback
import xml.etree.ElementTree as ET
p=pathlib.Path.cwd();e=pathlib.Path(os.environ['EVIDENCE_DIR']).resolve();assert e!=p and p not in e.parents;e.mkdir(parents=True,exist_ok=True)
head=os.environ['HEAD_SHA'];base=os.environ['BASE_SHA'];klass='ghidra.app.plugin.core.decompile.TypedFunctionPointerTokenCharacterizationTest'
fixture='Ghidra/Features/Decompiler/src/test.slow/java/'+klass.replace('.','/')+'.java'
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
try:
 assert base=='918d44ebc2962a53d23eeee52b8f44c7816e7815' and git('rev-parse','HEAD').decode().strip()==head
 assert git('diff','--name-only',base,head).decode().splitlines()==[fixture]
 targets={'testTypedPointerStoreResolvesActualTarget':'Typed function-pointer store token must resolve its target','testTypedCallbackArgumentResolvesActualTarget':'Typed callback argument token must resolve callback rather than dispatcher'}
 controls={'testIntegerAddressCoincidenceRetainsInteger','testDirectCallResolvesActualTarget','testPrototypeResolvesContainingFunction','testUnknownTypedPointerDoesNotInventFunction'}
 assert set(re.findall(r'@Test public void (\w+)\(', (p/fixture).read_text()))==set(targets)|controls
 paths=['Ghidra/Features/Decompiler/src/decompile/cpp/printc.cc','Ghidra/Features/Decompiler/src/decompile/cpp/prettyprint.cc','Ghidra/Features/Decompiler/src/main/java/ghidra/app/decompiler/ClangFuncNameToken.java','Ghidra/Features/Decompiler/src/main/java/ghidra/app/decompiler/component/DecompilerUtils.java']
 for path in paths:assert (p/path).read_bytes()==git('show',base+':'+path)
 r['production_sha256']={path:sha((p/path).read_bytes()) for path in paths};r['fixture_sha256']=sha((p/fixture).read_bytes());save()
 g=['./gradlew','--no-daemon','--max-workers=2','-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
 assert run('fetch',g+['-I','gradle/support/fetchDependencies.gradle','-DhideDownloadProgress','-DnoEclipse'])==0
 assert run('prep',g+['prepDev'])==0
 assert run('actual-native-and-x86',g+[':Decompiler:buildNatives',':x86:sleighCompile'])==0
 native=p/'Ghidra/Features/Decompiler/build/os/linux_x86_64/decompile';assert native.is_file()
 r['actual_native_sha256']=sha(native.read_bytes());r['actual_x86_sha256']={str(f.relative_to(p)):sha(f.read_bytes()) for f in (p/'Ghidra/Processors/x86/data/languages').glob('*.sla')};assert r['actual_x86_sha256'];save()
 results=p/'Ghidra/Features/Decompiler/build/test-results/integrationTest';shutil.rmtree(results,ignore_errors=True)
 code=run('actual-public-typed-pointer-producers',['xvfb-run','-a']+g+[':Decompiler:integrationTest','--tests',klass]);assert code in (0,1)
 dest=e/'xml';shutil.copytree(results,dest);files=list(dest.glob('*.xml'));assert len(files)==1
 rr=ET.parse(files[0]).getroot();items=rr.findall('testcase');assert rr.get('name')==klass and rr.get('timestamp');assert int(rr.get('tests'))==len(items)==6 and int(rr.get('errors'))==int(rr.get('skipped'))==0
 step=r['steps'][-1];start=datetime.datetime.fromisoformat(step['started_at']).timestamp();end=datetime.datetime.fromisoformat(step['ended_at']).timestamp()
 stamp=datetime.datetime.fromisoformat(rr.get('timestamp').replace('Z','+00:00'));assert stamp.tzinfo is not None
 xml_time=stamp.timestamp();mtime=files[0].stat().st_mtime
 assert start-1 <= xml_time <= end+1 and start-1 <= mtime <= end+1,(start,xml_time,mtime,end)
 cases={};failures=[]
 for t in items:
  name=t.get('name');assert t.get('classname')==klass and name not in cases;children=[x for x in t if x.tag in ['failure','error','skipped']];assert len(children)<=1
  if children:
   x=children[0];assert name in targets and x.tag=='failure' and x.get('type')=='java.lang.AssertionError' and (x.get('message') or '').startswith('java.lang.AssertionError: '+targets[name]);failures.append(name);cases[name]={'kind':'failure','type':x.get('type'),'message':x.get('message'),'trace':x.text}
  else:cases[name]={'kind':'PASS'}
 assert set(cases)==set(targets)|controls and int(rr.get('failures'))==len(failures)
 if not failures:assert code==0
 stdout=rr.findtext('system-out','');observations=re.findall(r'^TYPED_FN_OBSERVATION .+$',stdout,re.MULTILINE);controlmarkers=re.findall(r'^TYPED_FN_CONTROL .+$',stdout,re.MULTILINE)
 assert len(observations)==4 and len(controlmarkers)==2
 assert set(controlmarkers)=={'TYPED_FN_CONTROL case=integer preserved=true','TYPED_FN_CONTROL case=unknown preserved=true'}
 names={re.search(r'case=([^ ]+)',x)[1] for x in observations};assert names=={'typed-store','typed-argument','direct-call','prototype'}
 for case in ['typed-store','typed-argument']:
  target_observations=[x for x in observations if x.startswith('TYPED_FN_OBSERVATION case='+case+' ')]
  assert len(target_observations)==1 and re.fullmatch(r'TYPED_FN_OBSERVATION case='+case+r' text=ActualCallback op=\S+ resolved=\S+',target_observations[0])
 assert 'TYPED_FN_OBSERVATION case=direct-call text=ActualCallback op=CALL resolved=ActualCallback' in observations
 assert 'TYPED_FN_OBSERVATION case=prototype text=PrototypeControl op=NONE resolved=PrototypeControl' in observations
 r.update(cases=cases,observations=observations,controlmarkers=controlmarkers,xml_sha256=sha(files[0].read_bytes()),xml_counts={k:int(rr.get(k)) for k in ['tests','failures','errors','skipped']},xml_timestamp=rr.get('timestamp'),xml_mtime_utc=datetime.datetime.fromtimestamp(mtime,datetime.timezone.utc).isoformat(),xml_producer_interval={'start':step['started_at'],'end':step['ended_at']});save()
 status=git('status','--porcelain');(e/'git-status.raw').write_bytes(status);r['git_status_sha256']=sha(status);assert not status
 r['status']='REPRODUCED_TYPED_FUNCTION_TOKEN_TARGET_RESOLUTION' if failures else 'NOT_REPRODUCED';r['target_failure_names']=failures
except Exception as ex:r.update(error=str(ex),traceback=traceback.format_exc());raise
finally:r['finished_at']=utc();save()
