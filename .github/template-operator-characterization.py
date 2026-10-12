import datetime,hashlib,json,os,pathlib,re,shutil,signal,subprocess,traceback
import xml.etree.ElementTree as ET
p=pathlib.Path.cwd().resolve();e=pathlib.Path(os.environ['EVIDENCE_DIR']).resolve()
assert e != p and p not in e.parents
e.mkdir(parents=True,exist_ok=True)
head=os.environ['HEAD_SHA'];base=os.environ['BASE_SHA']
klass='ghidra.app.util.TemplateOperatorLookupCharacterizationTest'
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
r={'started_at':utc(),'head':head,'base':base,'purpose':'Actual template operator qualified symbol lookup characterization','status':'INCONCLUSIVE','publication_gate':False,'full_build_passed':False,'steps':[]}
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
 r[label]={'observed_at':utc(),'cases':[{'class':c,'name':n,**v} for (c,n),v in sorted(cases.items())],'xml':metadata,'markers':[line for file in dest.glob('*.xml') for line in ET.parse(file).getroot().findtext('system-out','').splitlines() if line.startswith('TEMPLATE_OPERATOR_LOOKUP ')]};save();return cases
try:
 assert base=='918d44ebc2962a53d23eeee52b8f44c7816e7815' and git('rev-parse','HEAD').decode().strip()==head
 assert git('diff','--name-only',base,head).decode().splitlines()==[fixture]
 assert (p/original_path).read_bytes()==git('show',base+':'+original_path)
 originals=set(re.findall(r'@Test\s+public void (\w+)\(', (p/original_path).read_text()));assert len(originals)==11
 targets={'testTemplateShiftLeft','testTemplateShiftRight','testTemplateLessEqual','testTemplateGreaterEqual'}
 controls={'testBalancedTemplateOrdinarySymbol','testOrdinaryNamespaceOperator','testMissingSymbolStaysMissing','testExistingUnbalancedFallbackLookup'}
 assert set(re.findall(r'@Test\s+public void (\w+)\(', (p/fixture).read_text()))==targets|controls
 parser_class='ghidra.app.util.SymbolPathParserTest';parser_path='Ghidra/Framework/SoftwareModeling/src/test/java/ghidra/app/util/SymbolPathParserTest.java'
 assert (p/parser_path).read_bytes()==git('show',base+':'+parser_path)
 parser_methods=set(re.findall(r'@Test\s+public void (\w+)\(', (p/parser_path).read_text()));assert len(parser_methods)==9
 r['production_sha256']={}
 for name in ['SymbolPathParser','SymbolPath','NamespaceUtils']:
  path='Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/app/util/'+name+'.java';assert (p/path).read_bytes()==git('show',base+':'+path);r['production_sha256'][path]=digest(p/path)
 r['parser_original_sha256']=digest(p/parser_path)
 r['fixture_sha256']=digest(p/fixture);r['original_sha256']=digest(p/original_path);save()
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
 code=invoke('public-qualified-lookup',[klass]);cases=read_results('public-qualified-lookup',{klass:targets|controls})
 assert all(cases[(klass,n)]=={'kind':'PASS'} for n in controls)
 assert all(v['kind'] in ['PASS','failure'] for v in cases.values())
 failures={n for (c,n),v in cases.items() if v['kind']=='failure'};assert failures in (set(),targets)
 operators={'testTemplateShiftLeft':'operator<<','testTemplateShiftRight':'operator>>','testTemplateLessEqual':'operator<=','testTemplateGreaterEqual':'operator>='}
 for name in failures:
  x=cases[(klass,name)];assert x['type']=='java.lang.AssertionError';message=(x['message'] or '').removeprefix('java.lang.AssertionError: ')
  assert message=='Qualified lookup must preserve template namespace before '+operators[name]+' expected:<1> but was:<0>',(name,message)
 if not failures:assert code==0
 markers=r['public-qualified-lookup']['markers'];assert len(markers)==8
 assert markers.count('TEMPLATE_OPERATOR_LOOKUP control=missing matches=0')==1
 rows=[]
 for line in markers:
  if 'control=missing' in line:continue
  match=re.fullmatch(r'TEMPLATE_OPERATOR_LOOKUP name=(.+) path=(.+) directId=(\d+) matches=(\d+)',line);assert match and int(match[3])>0;rows.append((match[1],match[2],int(match[4])))
 template='std::basic_ostream<char,std::char_traits<char>_>'
 for op in operators.values():assert rows.count((op,template+'::'+op,0 if failures else 1))==1
 for name,path in [('flush',template+'::flush'),('operator<<','ordinary::operator<<'),('E','A::operator<=::B<C<int>::<unnamed-tag>>::E')]:assert rows.count((name,path,1))==1
 code=invoke('unchanged-namespace-tests',[original]);old=read_results('unchanged-namespace-tests',{original:originals})
 r['namespace_original_all_passed']=all(v=={'kind':'PASS'} for v in old.values())
 if r['namespace_original_all_passed']:assert code==0
 code=invoke('unchanged-parser-tests',[parser_class],'Ghidra/Framework/SoftwareModeling','test');old=read_results('unchanged-parser-tests',{parser_class:parser_methods},'Ghidra/Framework/SoftwareModeling','test')
 r['parser_original_all_passed']=all(v=={'kind':'PASS'} for v in old.values())
 if r['parser_original_all_passed']:assert code==0
 status=git('status','--porcelain').decode()
 (e/'final-git-status.txt').write_text(status)
 r['final_status']={'porcelain':status,'sha256':digest(e/'final-git-status.txt')};save()
 assert not status.strip()
 r['status']='REPRODUCED_TEMPLATE_OPERATOR_QUALIFIED_LOOKUP' if failures else 'NOT_REPRODUCED'
except Exception as ex:
 r.update(status='INCONCLUSIVE',error=str(ex),traceback=traceback.format_exc());raise
finally:r['finished_at']=utc();save()
