import datetime,hashlib,json,os,pathlib,re,shutil,subprocess,traceback
import xml.etree.ElementTree as ET
p=pathlib.Path.cwd(); e=p/'native-evidence';e.mkdir();head=os.environ['HEAD_SHA'];base=os.environ['BASE_SHA'];baseline_head=os.environ['BASELINE_SHA']
klass='ghidra.feature.vt.db.VTAssociationCacheCharacterizationTest'
fixture='Ghidra/Features/VersionTracking/src/test.slow/java/'+klass.replace('.','/')+'.java'
originals=['ghidra.feature.vt.db.VTAssociationDBTest','ghidra.feature.vt.db.VTMatchSetDBTest']
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
r={'started_at':utc(),'head':head,'base':base,'baseline_head':baseline_head,'status':'INCONCLUSIVE','steps':[],'full_build_passed':False,'publication_gate':False}
def sha(b):return hashlib.sha256(b).hexdigest()
def git(*args):return subprocess.check_output(['git',*args])
def save():(e/'receipt.json').write_text(json.dumps(r,indent=2)+'\n')
def run(label,args):
 started=utc()
 with (e/(label+'.log')).open('w') as f:x=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT,timeout=5400)
 r['steps'].append({'label':label,'args':args,'exit_code':x.returncode,'started_at':started,'finished_at':utc(),'log_sha256':sha((e/(label+'.log')).read_bytes())});save();print(label,x.returncode,flush=True);return x.returncode
def read_results(task,label,expected):
 result=p/('Ghidra/Features/VersionTracking/build/test-results/'+task);dest=e/(label+'-xml');shutil.copytree(result,dest);cases={};stdout='';metadata={}
 for file in dest.glob('*.xml'):
  rr=ET.parse(file).getroot();name=rr.get('name');assert name in expected and rr.get('timestamp')
  counts={k:int(rr.get(k,'0')) for k in ['tests','failures','errors','skipped']}
  assert counts['tests']==len(rr.findall('testcase')),(name,counts)
  if name==klass:assert counts['errors']==0 and counts['skipped']==0,(name,counts)
  observed={tag:sum(1 for t in rr.findall('testcase') if t.find(tag) is not None) for tag in ['failure','error','skipped']}
  assert counts['failures']==observed['failure'] and counts['errors']==observed['error'] and counts['skipped']==observed['skipped'],(name,counts,observed)
  traces={t.get('name'):t.find('failure').text for t in rr.findall('testcase') if t.find('failure') is not None}
  metadata[file.name]={'failure_traces':traces,'class':name,'timestamp':rr.get('timestamp'),'counts':counts,'sha256':sha(file.read_bytes())}
  stdout+=rr.findtext('system-out','')
  for t in rr.findall('testcase'):
   key=(t.get('classname'),t.get('name'));assert key[0]==name and key not in cases
   children=[c for c in t if c.tag in ['failure','error','skipped']];assert len(children)<=1
   cases[key]={'kind':children[0].tag,'type':children[0].get('type'),'message':children[0].get('message')} if children else {'kind':'PASS'}
 assert set(cases)=={(c,n) for c,names in expected.items() for n in names}
 r[label]={'cases':[{'class':c,'name':n,**v} for (c,n),v in sorted(cases.items())],'markers':re.findall(r'^VT_CACHE .+$',stdout,re.MULTILINE),'xml':metadata,'observed_at':utc()};save();return cases
try:
 assert base=='918d44ebc2962a53d23eeee52b8f44c7816e7815' and git('rev-parse','HEAD').decode().strip()==head
 manager='Ghidra/Features/VersionTracking/src/main/java/ghidra/feature/vt/api/db/AssociationDatabaseManager.java'
 assert set(git('diff','--name-only',base,head).decode().splitlines())=={fixture,manager}
 assert git('diff','--name-only',base,baseline_head).decode().splitlines()==[fixture]
 assert (p/fixture).read_bytes()==git('show',baseline_head+':'+fixture)
 expected=set(re.findall(r'@Test public void (\w+)\(', (p/fixture).read_text()));assert len(expected)==16
 originalnames={};r['original_sha256']={}
 for c in originals:
  path='Ghidra/Features/VersionTracking/src/test/java/'+c.replace('.','/')+'.java';data=(p/path).read_bytes();assert data==git('show',base+':'+path)
  originalnames[c]=set(re.findall(r'@Test\s+public void (\w+)\(',data.decode()));r['original_sha256'][path]=sha(data)
 assert [len(originalnames[c]) for c in originals]==[19,4]
 fixed=(p/manager).read_bytes();baseline=git('show',base+':'+manager)
 assert fixed!=baseline
 r['production']={'path':manager,'fixed_sha256':sha(fixed),'base_sha256':sha(baseline)}
 r['fixture_sha256']=sha((p/fixture).read_bytes());save()
 g=['./gradlew','--no-daemon','--max-workers=2','-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
 assert run('fetch',g+['-I','gradle/support/fetchDependencies.gradle','-DhideDownloadProgress','-DnoEclipse'])==0
 assert run('prep',g+['prepDev'])==0
 assert run('actual-native-and-language',g+[':Decompiler:buildNatives',':x86:sleighCompile'])==0
 native=p/'Ghidra/Features/Decompiler/build/os/linux_x86_64/decompile';assert native.is_file()
 sla=list((p/'Ghidra/Processors/x86/data/languages').glob('*.sla'));assert sla
 r['actual_native_binary']={'path':str(native.relative_to(p)),'sha256':sha(native.read_bytes())}
 r['actual_x86_languages']=[{'path':str(f.relative_to(p)),'sha256':sha(f.read_bytes())} for f in sorted(sla)];save()
 controls={'testNormalSource','testNormalDestination','testUnrelatedSource','testUnrelatedDestination','testPreexistingSource','testPreexistingDestination','testClearSource','testClearDestination'}
 outcomes={}
 for phase,production in [('baseline',baseline),('fixed',fixed)]:
  (p/manager).write_bytes(production)
  shutil.rmtree(p/'Ghidra/Features/VersionTracking/build/test-results/integrationTest',ignore_errors=True)
  code=run(phase+'-public-cache-producers',['xvfb-run','-a','-s','-screen 0 1600x1200x24']+g+[':VersionTracking:integrationTest','--tests',klass]);assert code in (0,1)
  label=phase+'-public-cache-producers';cases=read_results('integrationTest',label,{klass:expected})
  for name in expected:
   outcome=cases[(klass,name)]
   if phase=='fixed' or name in controls:assert outcome=={'kind':'PASS'},(phase,name,outcome)
   elif name.startswith('testClearAfterVote'):assert outcome['kind']=='failure' and outcome['type']=='ghidra.util.exception.AssertException' and 'Attempted to unblock a non-blocked association!' in outcome['message'],(name,outcome)
   elif name.startswith('testReload'):
    assert outcome['kind']=='failure' and outcome['type']=='junit.framework.AssertionFailedError' and 'Test locked-up--aborting!' in outcome['message'],(name,outcome)
    traces=[meta['failure_traces'].get(name,'') for meta in r[label]['xml'].values()];assert len(traces)==1
    for frame in ['ReentrantReadWriteLock$WriteLock.lock','AcceptedStatusCache.add','AcceptedStatusCache.doLoadAcceptedAssociations','AcceptedStatusCache.isBlocked','VTMatchSetDB.addMatch']:assert frame in traces[0],(name,frame)
   else:assert outcome['kind']=='failure' and outcome['type']=='java.lang.AssertionError' and 'expected:<BLOCKED> but was:<AVAILABLE>' in outcome['message'],(name,outcome)
  if phase=='fixed':assert code==0
  actions=[('after-block','BLOCKED'),('before-clear','BLOCKED'),('after-vote','AVAILABLE' if phase=='baseline' else 'BLOCKED'),('after-reject','AVAILABLE' if phase=='baseline' else 'BLOCKED'),('clear-after-vote','AVAILABLE' if phase=='baseline' else 'BLOCKED'),('normal-control','BLOCKED'),('unrelated-control','BLOCKED')]
  if phase=='fixed':actions.append(('after-undo','BLOCKED'))
  required={f'VT_CACHE side={side} action={action} status={status}' for side in ['source','destination'] for action,status in actions};markers=r[label]['markers']
  assert len(markers)==len(required) and set(markers)==required,(phase,markers,required)
  shutil.rmtree(p/'Ghidra/Features/VersionTracking/build/test-results/test',ignore_errors=True)
  code=run(phase+'-unchanged-original-db-tests',['xvfb-run','-a']+g+[':VersionTracking:test','--tests',originals[0],'--tests',originals[1]]);assert code in (0,1)
  outcomes[phase]=read_results('test',phase+'-unchanged-original-db-tests',originalnames)
  if all(outcome=={'kind':'PASS'} for outcome in outcomes[phase].values()):assert code==0
 assert outcomes['baseline']==outcomes['fixed']
 assert (p/manager).read_bytes()==fixed
 assert run('full-build',g+['buildGhidra'])==0
 assert 'BUILD SUCCESSFUL' in (e/'full-build.log').read_text()
 assert not git('diff','--name-only','HEAD').decode().strip()
 r.update(status='PASSED_PUBLIC_CACHE_REGRESSIONS_16_ORIGINAL_OUTCOMES_23_UNCHANGED_FULL_BUILD',full_build_passed=True,publication_gate=True)
except Exception as ex:r.update(status='INCONCLUSIVE',error=str(ex),traceback=traceback.format_exc());raise
finally:
 if 'fixed' in globals():(p/manager).write_bytes(fixed)
 r['finished_at']=utc();save()
