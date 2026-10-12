import datetime,hashlib,json,os,pathlib,re,shutil,subprocess,traceback
import xml.etree.ElementTree as ET
p=pathlib.Path.cwd(); e=p/'native-evidence';e.mkdir();head=os.environ['HEAD_SHA'];base=os.environ['BASE_SHA']
klass='ghidra.feature.vt.db.VTAssociationCacheCharacterizationTest'
fixture='Ghidra/Features/VersionTracking/src/test.slow/java/'+klass.replace('.','/')+'.java'
originals=['ghidra.feature.vt.db.VTAssociationDBTest','ghidra.feature.vt.db.VTMatchSetDBTest']
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
r={'started_at':utc(),'head':head,'base':base,'status':'INCONCLUSIVE','steps':[],'full_build_passed':False,'publication_gate':False}
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
  metadata[file.name]={'class':name,'timestamp':rr.get('timestamp'),'counts':counts,'sha256':sha(file.read_bytes())}
  stdout+=rr.findtext('system-out','')
  for t in rr.findall('testcase'):
   key=(t.get('classname'),t.get('name'));assert key[0]==name and key not in cases
   children=[c for c in t if c.tag in ['failure','error','skipped']];assert len(children)<=1
   cases[key]={'kind':children[0].tag,'type':children[0].get('type'),'message':children[0].get('message')} if children else {'kind':'PASS'}
 assert set(cases)=={(c,n) for c,names in expected.items() for n in names}
 r[label]={'cases':[{'class':c,'name':n,**v} for (c,n),v in sorted(cases.items())],'markers':re.findall(r'^VT_CACHE .+$',stdout,re.MULTILINE),'xml':metadata,'observed_at':utc()};save();return cases
try:
 assert base=='918d44ebc2962a53d23eeee52b8f44c7816e7815' and git('rev-parse','HEAD').decode().strip()==head
 assert git('diff','--name-only',base,head).decode().splitlines()==[fixture]
 expected=set(re.findall(r'@Test public void (\w+)\(', (p/fixture).read_text()));assert len(expected)==14
 originalnames={};r['original_sha256']={}
 for c in originals:
  path='Ghidra/Features/VersionTracking/src/test/java/'+c.replace('.','/')+'.java';data=(p/path).read_bytes();assert data==git('show',base+':'+path)
  originalnames[c]=set(re.findall(r'@Test\s+public void (\w+)\(',data.decode()));r['original_sha256'][path]=sha(data)
 assert [len(originalnames[c]) for c in originals]==[19,4]
 manager='Ghidra/Features/VersionTracking/src/main/java/ghidra/feature/vt/api/db/AssociationDatabaseManager.java'
 managerbytes=(p/manager).read_bytes();assert managerbytes==git('show',base+':'+manager)
 r['production']={'path':manager,'sha256':sha(managerbytes),'unchanged_from_base':True}
 r['fixture_sha256']=sha((p/fixture).read_bytes());save()
 g=['./gradlew','--no-daemon','--max-workers=2','-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
 assert run('fetch',g+['-I','gradle/support/fetchDependencies.gradle','-DhideDownloadProgress','-DnoEclipse'])==0
 assert run('prep',g+['prepDev'])==0
 assert run('actual-native-and-language',g+[':Decompiler:buildNatives',':x86:sleighCompile'])==0
 native=p/'Ghidra/Features/Decompiler/build/os/linux_x86_64/decompile';assert native.is_file()
 sla=list((p/'Ghidra/Processors/x86/data/languages').glob('*.sla'));assert sla
 r['actual_native_binary']={'path':str(native.relative_to(p)),'sha256':sha(native.read_bytes())}
 r['actual_x86_languages']=[{'path':str(f.relative_to(p)),'sha256':sha(f.read_bytes())} for f in sorted(sla)];save()
 shutil.rmtree(p/'Ghidra/Features/VersionTracking/build/test-results/integrationTest',ignore_errors=True)
 code=run('public-cache-producers',['xvfb-run','-a','-s','-screen 0 1600x1200x24']+g+[':VersionTracking:integrationTest','--tests',klass]);assert code in (0,1)
 cases=read_results('integrationTest','public-cache-producers',{klass:expected})
 controls={'testNormalSource','testNormalDestination','testUnrelatedSource','testUnrelatedDestination'}
 for name in expected:
  outcome=cases[(klass,name)]
  if name in controls:assert outcome=={'kind':'PASS'},(name,outcome)
  elif name.startswith('testClear'):assert outcome['kind']=='failure' and outcome['type']=='ghidra.util.exception.AssertException' and 'Attempted to unblock a non-blocked association!' in outcome['message'],(name,outcome)
  else:assert outcome['kind']=='failure' and outcome['type']=='java.lang.AssertionError' and 'expected:<BLOCKED> but was:<AVAILABLE>' in outcome['message'],(name,outcome)
 markers=r['public-cache-producers']['markers'];required={f'VT_CACHE side={side} action={action} status={status}' for side in ['source','destination'] for action,status in [('after-block','AVAILABLE'),('before-clear','AVAILABLE'),('after-vote','AVAILABLE'),('after-reject','AVAILABLE'),('after-undo','AVAILABLE'),('normal-control','BLOCKED'),('unrelated-control','BLOCKED')]}
 assert len(markers)==14 and set(markers)==required,(markers,required)
 shutil.rmtree(p/'Ghidra/Features/VersionTracking/build/test-results/test',ignore_errors=True)
 code=run('unchanged-original-db-tests',['xvfb-run','-a']+g+[':VersionTracking:test','--tests',originals[0],'--tests',originals[1]]);assert code in (0,1)
 originalcases=read_results('test','unchanged-original-db-tests',originalnames)
 if all(outcome=={'kind':'PASS'} for outcome in originalcases.values()):assert code==0
 assert (p/manager).read_bytes()==managerbytes
 assert not git('diff','--name-only','HEAD').decode().strip()
 r['status']='REPRODUCED_PUBLIC_DB_ASSOCIATION_CACHE_10_FAILURES_4_CONTROLS_ORIGINALS_RETAINED_NO_PRODUCTION_FIX'
except Exception as ex:r.update(status='INCONCLUSIVE',error=str(ex),traceback=traceback.format_exc());raise
finally:r['finished_at']=utc();save()
