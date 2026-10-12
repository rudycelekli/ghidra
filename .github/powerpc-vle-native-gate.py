import datetime,hashlib,json,os,pathlib,re,shutil,signal,subprocess,traceback
import xml.etree.ElementTree as ET
p=pathlib.Path.cwd().resolve();e=pathlib.Path(os.environ['EVIDENCE_DIR']).resolve()
assert e != p and p not in e.parents
e.mkdir(parents=True,exist_ok=True)
head=os.environ['HEAD_SHA'];base=os.environ['BASE_SHA']
module='Ghidra/Features/BytePatterns'
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def digest(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
 return h.hexdigest()
def git(*args):return subprocess.check_output(['git',*args])
r={'started_at':utc(),'head':head,'base':base,'purpose':'Actual context-qualified VLE function discovery baseline/fixed qualification','status':'INCONCLUSIVE','publication_gate':False,'full_build_passed':False,'steps':[]}
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
 result=p/(module+'/build/test-results/test');dest=e/(label+'-xml');shutil.copytree(result,dest)
 cases={};metadata={};markers=[]
 for file in dest.glob('*.xml'):
  root=ET.parse(file).getroot();name=root.get('name');assert name in expected and root.get('timestamp')
  step=next(x for x in reversed(r['steps']) if x['label']==label)
  started=datetime.datetime.fromisoformat(step['started_at']);ended=datetime.datetime.fromisoformat(step['finished_at'])
  stamp=datetime.datetime.fromisoformat(root.get('timestamp'));stamp=stamp.replace(tzinfo=datetime.timezone.utc) if stamp.tzinfo is None else stamp
  assert started-datetime.timedelta(seconds=2)<=stamp<=ended+datetime.timedelta(seconds=2)
  assert file.stat().st_mtime>=started.timestamp()-2
  counts={k:int(root.get(k,'0')) for k in ['tests','failures','errors','skipped']};items=root.findall('testcase')
  observed={k:sum(x.find(tag) is not None for x in items) for k,tag in [('failures','failure'),('errors','error'),('skipped','skipped')]}
  assert counts['tests']==len(items) and all(counts[k]==v for k,v in observed.items())
  markers += [line for line in root.findtext('system-out','').splitlines() if line.startswith(('VLE_NATIVE_','VLE_PADDING_'))]
  metadata[file.name]={'class':name,'timestamp':root.get('timestamp'),'counts':counts,'sha256':digest(file)}
  for item in items:
   key=(item.get('classname'),item.get('name'));assert key[0]==name and key not in cases
   children=[x for x in item if x.tag in ['failure','error','skipped']];assert len(children)<=1
   cases[key]={'kind':children[0].tag,'type':children[0].get('type'),'message':children[0].get('message')} if children else {'kind':'PASS'}
 assert set(cases)=={(c,n) for c,names in expected.items() for n in names}
 r[label]={'observed_at':utc(),'cases':[{'class':c,'name':n,**v} for (c,n),v in sorted(cases.items())],'xml':metadata,'markers':markers};save();return cases
fixed={}
try:
 assert base=='918d44ebc2962a53d23eeee52b8f44c7816e7815' and git('rev-parse','HEAD').decode().strip()==head
 prod=[module+'/src/main/java/ghidra/app/analyzers/FunctionStartAnalyzer.java','Ghidra/Processors/PowerPC/data/patterns/PPC_BE_patterns.xml']
 newclasses=['ghidra.app.analyzers.FunctionStartContextPrerequisiteTest','ghidra.app.analyzers.PowerPcVleFunctionStartTest']
 fixtures={module+'/src/test/java/'+c.replace('.','/')+'.java':c for c in newclasses}
 assert set(git('diff','--name-only',base,head).decode().splitlines())==set(prod)|set(fixtures)
 for path in prod:fixed[path]=(p/path).read_bytes()
 baseline={path:git('show',base+':'+path) for path in prod};assert all(fixed[x]!=baseline[x] for x in prod)
 manifest=json.loads(pathlib.Path('/tmp/powerpc-vle-original-test-manifest.json').read_text());assert len(manifest)==18 and sum(len(x['methods']) for x in manifest.values())==99
 originals={}
 for path,item in manifest.items():
  data=(p/path).read_bytes();assert data==git('show',base+':'+path) and hashlib.sha256(data).hexdigest()==item['sha256'];originals[item['class']]=set(item['methods'])
 expected={c:set(re.findall(r'@Test\s+public void (\w+)\(', (p/path).read_text())) for path,c in fixtures.items()}
 assert sum(len(v) for v in expected.values())==13 and len(expected[newclasses[0]])==12 and len(expected[newclasses[1]])==1
 fixture_bytes={path:(p/path).read_bytes() for path in fixtures}
 r['production']={path:{'base_sha256':hashlib.sha256(baseline[path]).hexdigest(),'fixed_sha256':hashlib.sha256(fixed[path]).hexdigest()} for path in prod}
 r['fixtures']={path:digest(p/path) for path in fixtures};r['original_manifest']=manifest;save()
 g=['./gradlew','--no-daemon','--max-workers=2','-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
 assert run('fetch',g+['-I','gradle/support/fetchDependencies.gradle','-DhideDownloadProgress','-DnoEclipse'])==0
 assert run('prep',g+['prepDev'])==0
 assert run('actual-native-and-languages',g+[':Decompiler:buildNatives',':PowerPC:sleighCompile',':Toy:sleighCompile'])==0
 native=p/'Ghidra/Features/Decompiler/build/os/linux_x86_64/decompile';assert native.is_file();r['actual_native']={'sha256':digest(native)}
 r['languages']={}
 for processor in ['PowerPC','Toy']:
  paths=list((p/('Ghidra/Processors/'+processor+'/data/languages')).glob('*.sla'));assert paths;r['languages'][processor]={str(x.relative_to(p)):digest(x) for x in paths}
 save()
 def invoke(label,classes):
  shutil.rmtree(p/(module+'/build/test-results/test'),ignore_errors=True)
  args=['xvfb-run','-a','-s','-screen 0 1600x1200x24']+g+[':BytePatterns:test']
  for c in classes:args+=['--tests',c]
  code=run(label,args);assert code in (0,1);return code
 targets={'testKnownDifferentContextRejected','testIncompletePairsRejected','testMalformedValueRejected','testUnknownRegisterRejected','testNonContextRegisterRejected','testNegativeAndOversizedValuesRejected','testCaseDistinctDuplicateAttributesRejected','testReusedActionRequirementReset'}
 public=newclasses[1];public_method='testRealVleAndStandardModeFunctionStarts';controls=expected[newclasses[0]]-targets;assert len(targets)==8 and len(controls)==4
 names=['direct-stack','padded-stack','direct-lr-stack','padded-lr-stack','undefined-padded-stack','undefined-padded-lr-stack','standard-control','disabled-vle-control','existing-control','padding-only-control','mixed-mode-control','nonexecutable-control','defined-data-control','minus4-stack','minus32-stack','minus128-stack','zero-frame-control','positive-frame-control','unaligned-frame-control']
 def inspect_markers(label,phase):
  lines=r[label]['markers'];groups={prefix:[x for x in lines if x.startswith(prefix+' ')] for prefix in ['VLE_NATIVE_INPUT','VLE_NATIVE_DISPLACEMENT','VLE_NATIVE_CASE','VLE_NATIVE_MIXED','VLE_NATIVE_OUTCOME','VLE_PADDING_STATE','VLE_PADDING_DECODER']}
  assert len(lines)==65 and all(len(groups[x])==19 for x in ['VLE_NATIVE_INPUT','VLE_NATIVE_DISPLACEMENT','VLE_NATIVE_CASE']) and len(groups['VLE_NATIVE_MIXED'])==len(groups['VLE_NATIVE_OUTCOME'])==1
  indexed={}
  for prefix in ['VLE_NATIVE_INPUT','VLE_NATIVE_DISPLACEMENT','VLE_NATIVE_CASE']:
   rows={}
   for line in groups[prefix]:
    name=re.search(r' name=(\S+)',line).group(1);assert name not in rows;rows[name]=line
   assert set(rows)==set(names);indexed[prefix]=rows
  for name in names:
   standard=name in ['standard-control','nonexecutable-control','defined-data-control'];enabled=not standard and name!='disabled-vle-control';decoded_padding=name.startswith('padded');padding=decoded_padding or name.startswith('undefined-padded') or name=='padding-only-control';lr='lr-stack' in name
   displacement={'minus4-stack':-4,'minus32-stack':-32,'minus128-stack':-128,'zero-frame-control':0,'positive-frame-control':16,'unaligned-frame-control':-3}.get(name,-16)
   hexbytes='4e8000209421fff07c0802a6382100104e800020' if standard else '0004'+('4444' if padding else '')+('0080' if lr else '')+('4444' if name=='padding-only-control' else '182106'+format(displacement&255,'02x'))+'0004'
   mnemonic='NONE' if name in ['defined-data-control','disabled-vle-control'] else 'stwu' if standard else 'se_mflr' if lr else 'se_or' if name=='padding-only-control' else 'e_stwu';length=0 if mnemonic=='NONE' else 2 if mnemonic in ['se_mflr','se_or'] else 4
   assert indexed['VLE_NATIVE_INPUT'][name]==f'VLE_NATIVE_INPUT name={name} hex={hexbytes} execute={str(name!="nonexecutable-control").lower()} controlledVle={int(enabled)} targetMnemonic={mnemonic} targetLength={length} targetDefinedData={str(name=="defined-data-control").lower()}'
   assert indexed['VLE_NATIVE_DISPLACEMENT'][name]==f'VLE_NATIVE_DISPLACEMENT name={name} displacement={displacement}'
   case=indexed['VLE_NATIVE_CASE'][name];match=re.fullmatch(r'VLE_NATIVE_CASE name=(\S+) target=(\S+) vle=(\d+) functionBefore=(true|false) functionAfter=(true|false) bodyAddresses=(\d+) messageLog=(.*)',case);assert match
   candidate=(name.endswith('stack') and not decoded_padding) or name=='mixed-mode-control';after=name in ['existing-control','standard-control'] or (phase=='fixed' and candidate)
   assert match[2]==('00001004' if standard or padding else '00001002') and int(match[3])==int(enabled) and match[4]==str(name=='existing-control').lower() and match[5]==str(after).lower()
   assert (int(match[6])>0)==after
  assert groups['VLE_PADDING_DECODER']==['VLE_PADDING_DECODER hex=4444 mnemonic=se_or length=2 left=r4 right=r4 fallthrough=00003002']
  expected_padding={f'VLE_PADDING_STATE name={name} instructionBefore={str(not name.startswith("undefined-padded")).lower()} fallthroughToTarget={str(not name.startswith("undefined-padded")).lower()}' for name in ['padded-stack','padded-lr-stack','undefined-padded-stack','undefined-padded-lr-stack','padding-only-control']}
  assert len(groups['VLE_PADDING_STATE'])==5 and set(groups['VLE_PADDING_STATE'])==expected_padding
  assert groups['VLE_NATIVE_MIXED']==['VLE_NATIVE_MIXED standardTarget=00001084 vle=0 function=true']
  assert groups['VLE_NATIVE_OUTCOME']==[f'VLE_NATIVE_OUTCOME cases=19 missingCandidates={8 if phase=="baseline" else 0} outcome={"REPRODUCED" if phase=="baseline" else "NOT_REPRODUCED"}']
 old={}
 for phase,data in [('baseline',baseline),('fixed',fixed)]:
  for path,content in data.items():(p/path).write_bytes(content);assert (p/path).read_bytes()==content
  assert all((p/path).read_bytes()==content for path,content in fixture_bytes.items())
  code=invoke(phase+'-new',newclasses);cases=read_results(phase+'-new',expected);inspect_markers(phase+'-new',phase)
  if phase=='baseline':
   assert all(cases[(newclasses[0],name)]=={'kind':'PASS'} for name in controls)
   failures={(c,n) for (c,n),v in cases.items() if v['kind']=='failure'};assert failures=={(newclasses[0],n) for n in targets}|{(public,public_method)}
   assert all(v['kind'] in ['PASS','failure'] for v in cases.values())
   for name in targets:
    x=cases[(newclasses[0],name)];assert x['type']=='java.lang.AssertionError' and (x['message'] or '') in ['', 'java.lang.AssertionError']
   x=cases[(public,public_method)];assert x['type']=='java.lang.AssertionError' and (x['message'] or '').removeprefix('java.lang.AssertionError: ')=='All actual VLE stack prologues must produce functions expected:<0> but was:<8>'
  else:assert code==0 and all(v=={'kind':'PASS'} for v in cases.values())
  original_code=invoke(phase+'-original',sorted(originals));old[phase]=read_results(phase+'-original',originals)
  if all(v=={'kind':'PASS'} for v in old[phase].values()):assert original_code==0
 assert old['baseline']==old['fixed'];r['original_all_passed']=all(v=={'kind':'PASS'} for v in old['fixed'].values())
 assert run('full-build',g+['buildGhidra'])==0 and 'BUILD SUCCESSFUL' in (e/'full-build.log').read_text();r['full_build_passed']=True
 assert all((p/path).read_bytes()==content for path,content in fixed.items()) and all((p/path).read_bytes()==content for path,content in fixture_bytes.items())
 for path,item in manifest.items():assert digest(p/path)==item['sha256']
 status=git('status','--porcelain');(e/'final-git-status.bin').write_bytes(status);r['final_status']={'bytes':len(status),'sha256':hashlib.sha256(status).hexdigest()};save();assert status==b''
 r.update(status='QUALIFIED_NATIVE_VLE_BASELINE_FIXED',publication_gate=True)
except Exception as ex:r.update(status='INCONCLUSIVE',error=str(ex),traceback=traceback.format_exc());raise
finally:
 for path,content in fixed.items():(p/path).write_bytes(content)
 r['finished_at']=utc();save()
