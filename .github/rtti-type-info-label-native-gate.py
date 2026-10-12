import datetime,hashlib,json,os,pathlib,re,shutil,signal,subprocess,traceback
import xml.etree.ElementTree as ET
p=pathlib.Path.cwd().resolve();e=pathlib.Path(os.environ['EVIDENCE_DIR']).resolve()
assert e != p and p not in e.parents
e.mkdir(parents=True,exist_ok=True)
head=os.environ['HEAD_SHA'];base=os.environ['BASE_SHA']
klass='ghidra.app.cmd.data.rtti.RttiTypeInfoLabelTest'
fixture='Ghidra/Features/MicrosoftCodeAnalyzer/src/test/java/'+klass.replace('.','/')+'.java'
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def digest(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
 return h.hexdigest()
def git(*args):return subprocess.check_output(['git',*args])
r={'started_at':utc(),'head':head,'base':base,'purpose':'Actual Windows RTTI LABEL baseline/fixed production qualification','status':'INCONCLUSIVE','publication_gate':False,'full_build_passed':False,'steps':[]}
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
def read_results(label,expected,module="Ghidra/Features/MicrosoftCodeAnalyzer",task="test"):

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
 r[label]={'observed_at':utc(),'cases':[{'class':c,'name':n,**v} for (c,n),v in sorted(cases.items())],'xml':metadata,'markers':[line for file in dest.glob('*.xml') for line in ET.parse(file).getroot().findtext('system-out','').splitlines() if line.startswith(('RTTI_LABEL_OBSERVATION ','RTTI_LABEL_MODEL_RESULT '))]};save();return cases
def inspect_markers(label,reproduced):
 markers=r[label]['markers'];assert len(markers)==13
 expected={'created':('.rdata',1),'windows-model':('.rdata',1),'pdb':('.rdata',1),'legacy-label':('.rdata',1),'same-name-ambiguity':('.rdata',2),'alias-ambiguity':('.rdata',2),'wrong-namespace':('.rdata',0),'raw-data':('.data',0),'raw-nondata':('.rdata',0),'same-address-aliases':('.rdata',3),'global-existing-namespace':('.rdata',0),'function-symbol':('.rdata',0)}
 rows={};model=[]
 for line in markers:
  if line.startswith('RTTI_LABEL_MODEL_RESULT '):model.append(line);continue
  match=re.fullmatch(r'RTTI_LABEL_OBSERVATION case=([a-z-]+) block=(\.r?data) labelRecords=(\d+) rawPointer=10000800 result=(NULL|10000800|MODEL_INPUT)',line)
  assert match and match[1] not in rows;rows[match[1]]=(match[2],int(match[3]),match[4])
 assert set(rows)==set(expected)
 for name,(block,labels) in expected.items():
  wanted='MODEL_INPUT' if name=='windows-model' else '10000800' if name=='raw-data' or (not reproduced and name in ['created','pdb','legacy-label','same-address-aliases']) else 'NULL'
  assert rows[name]==(block,labels,wanted),(name,rows[name],wanted)
 assert model==['RTTI_LABEL_MODEL_RESULT case=windows-model result='+('NO_VF_POINTER' if reproduced else '10000800')]
try:
 assert base=='918d44ebc2962a53d23eeee52b8f44c7816e7815' and git('rev-parse','HEAD').decode().strip()==head
 production='Ghidra/Features/MicrosoftCodeAnalyzer/src/main/java/ghidra/app/cmd/data/rtti/RttiUtil.java'
 assert set(git('diff','--name-only',base,head).decode().splitlines())=={fixture,production}
 fixed=(p/production).read_bytes();baseline=git('show',base+':'+production);assert fixed!=baseline
 r['changed_production']={'path':production,'baseline_sha256':hashlib.sha256(baseline).hexdigest(),'fixed_sha256':hashlib.sha256(fixed).hexdigest()}
 manifest=json.loads(pathlib.Path(os.environ['ORIGINAL_MANIFEST']).read_text());expected_old={v['class']:set(v['methods']) for v in manifest.values() if v['methods']}
 assert sum(map(len,expected_old.values()))==49 and len(expected_old)==2
 r['originals']={}
 for path,value in manifest.items():
  assert (p/path).read_bytes()==git('show',base+':'+path) and digest(p/path)==value['sha256'];r['originals'][path]=value
 r['production']={}
 for path in ['Ghidra/Features/MicrosoftCodeAnalyzer/src/main/java/ghidra/app/cmd/data/TypeDescriptorModel.java','Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/database/symbol/SymbolManager.java']:
  assert (p/path).read_bytes()==git('show',base+':'+path);r['production'][path]=digest(p/path)
 targets={'testPublicCreatedLabelRoundTripOutsideData','testActualWindowsTypeDescriptorCallerOutsideData','testPdbVftableLabelOutsideData','testLegacyTypeInfoLabelOutsideData','testSameAddressAliasesIdentifyOneTable'}
 controls={'testAmbiguousSameNameLabelsFailClosed','testConflictingLabelAliasesFailClosed','testWrongNamespaceLabelIsIgnored','testUnlabeledLegacyDataFallback','testUnlabeledNonDataIsNotGuessed','testGlobalLabelWithExistingTypeInfoIsIgnored','testFunctionSymbolIsNotATableLabel'}
 assert set(re.findall(r'@Test\s+public void (\w+)\(', (p/fixture).read_text()))==targets|controls
 r['fixture_sha256']=digest(p/fixture);save()
 g=['./gradlew','--no-daemon','--max-workers=2','-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
 assert run('fetch',g+['-I','gradle/support/fetchDependencies.gradle','-DhideDownloadProgress','-DnoEclipse'])==0
 assert run('prep',g+['prepDev'])==0
 assert run('actual-native-and-languages',g+[':Decompiler:buildNatives',':x86:sleighCompile',':Toy:sleighCompile'])==0
 native=p/'Ghidra/Features/Decompiler/build/os/linux_x86_64/decompile';assert native.is_file();r['actual_native']={'path':str(native.relative_to(p)),'sha256':digest(native)};r['languages']={}
 for language in ['x86','Toy']:
  slas=sorted((p/('Ghidra/Processors/'+language+'/data/languages')).glob('*.sla'));assert slas;r['languages'][language]=[{'path':str(x.relative_to(p)),'sha256':digest(x)} for x in slas]
 save()
 def invoke(label,classes):
  shutil.rmtree(p/'Ghidra/Features/MicrosoftCodeAnalyzer/build/test-results/test',ignore_errors=True)
  args=['xvfb-run','-a','-s','-screen 0 1600x1200x24']+g+[':MicrosoftCodeAnalyzer:test']
  for c in classes:args+=['--tests',c]
  code=run(label,args);assert code in (0,1);return code
 messages={'testPublicCreatedLabelRoundTripOutsideData':'Publicly created vftable label must be found outside .data expected:<10000800> but was:<null>','testActualWindowsTypeDescriptorCallerOutsideData':'Actual Windows descriptor lost its labeled vftable pointer','testPdbVftableLabelOutsideData':'Actual PDB vftable label must be found expected:<10000800> but was:<null>','testLegacyTypeInfoLabelOutsideData':'Actual legacy type_info label must be found expected:<10000800> but was:<null>','testSameAddressAliasesIdentifyOneTable':'Aliases at one actual address identify one table expected:<10000800> but was:<null>'}
 old_outcomes={}
 for phase,data in [('baseline',baseline),('fixed',fixed)]:
  (p/production).write_bytes(data);assert (p/production).read_bytes()==data
  assert digest(p/fixture)==r['fixture_sha256']
  r[phase+'-source']={'production_sha256':digest(p/production),'fixture_sha256':digest(p/fixture),'observed_at':utc()};save()
  label=phase+'-public-label-and-model';code=invoke(label,[klass]);cases=read_results(label,{klass:targets|controls})
  assert all(cases[(klass,n)]=={'kind':'PASS'} for n in controls)
  if phase=='fixed':assert code==0 and all(v=={'kind':'PASS'} for v in cases.values())
  else:
   assert {n for (c,n),v in cases.items() if v['kind']=='failure'}==targets
   for name in targets:
    value=cases[(klass,name)];assert value['kind']=='failure' and value['type']=='java.lang.AssertionError' and (value['message'] or '').removeprefix('java.lang.AssertionError: ')==messages[name],(name,value)
  inspect_markers(label,phase=='baseline')
  label=phase+'-unchanged-rtti-tests';code=invoke(label,sorted(expected_old));old_outcomes[phase]=read_results(label,expected_old)
  assert code==0 and all(v=={'kind':'PASS'} for v in old_outcomes[phase].values())
 assert old_outcomes['baseline']==old_outcomes['fixed']
 assert (p/production).read_bytes()==fixed
 assert run('full-build',g+['buildGhidra'])==0
 assert 'BUILD SUCCESSFUL' in (e/'full-build.log').read_text()
 for path,value in r['originals'].items():assert (p/path).read_bytes()==git('show',base+':'+path) and digest(p/path)==value['sha256']
 for path,value in r['production'].items():assert (p/path).read_bytes()==git('show',base+':'+path) and digest(p/path)==value
 assert digest(p/fixture)==r['fixture_sha256']
 status=git('status','--porcelain').decode();(e/'final-git-status.txt').write_text(status);r['final_status']={'porcelain':status,'sha256':digest(e/'final-git-status.txt')};save();assert not status.strip()
 r.update(status='PASSED_RTTI_LABEL_12_BASELINE_FIXED_49_ORIGINAL_FULL_BUILD',publication_gate=True,full_build_passed=True)
except Exception as ex:
 r.update(status='INCONCLUSIVE',error=str(ex),traceback=traceback.format_exc());raise
finally:
 if 'fixed' in globals():(p/production).write_bytes(fixed)
 r['finished_at']=utc();save()
