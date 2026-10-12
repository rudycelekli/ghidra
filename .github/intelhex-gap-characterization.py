import datetime,hashlib,json,os,pathlib,re,shutil,signal,subprocess,traceback
import xml.etree.ElementTree as ET
p=pathlib.Path.cwd().resolve();e=pathlib.Path(os.environ['EVIDENCE_DIR']).resolve();assert e!=p and p not in e.parents;e.mkdir(parents=True,exist_ok=True)
head=os.environ['HEAD_SHA'];base=os.environ['BASE_SHA'];klass='ghidra.app.util.exporter.IntelHexExportGapCharacterizationTest'
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
 assert git('diff','--name-only',base,head).decode().splitlines()==[fixture]
 targets={'testSparseBlocksPreserveActualAddresses':'Sparse initialized block export must preserve actual address-byte map','testSelectionHolesPreserveActualAddresses':'Sparse selection export must preserve actual address-byte map'}
 controls={'testContiguousShortRecordPreserved','testAdjacentBlocksRemainContiguous','testFullRecordBeforeGapPreserved','testSegmentChangePreservesActualAddresses','testDeliberateTrailingDropPreserved','testEmptySelectionProducesOnlyEof'}
 assert set(re.findall(r'@Test public void (\w+)\(', (p/fixture).read_text()))==set(targets)|controls
 paths=['Ghidra/Features/Base/src/main/java/ghidra/app/util/exporter/IntelHexExporter.java','Ghidra/Features/Base/src/main/java/ghidra/app/util/opinion/IntelHexRecordWriter.java','Ghidra/Features/Base/src/main/java/ghidra/app/util/opinion/IntelHexRecordReader.java','Ghidra/Features/Base/src/main/java/ghidra/app/util/opinion/IntelHexRecord.java']
 for path in paths:assert (p/path).read_bytes()==git('show',base+':'+path)
 r['production_sha256']={path:sha((p/path).read_bytes()) for path in paths};r['fixture_sha256']=sha((p/fixture).read_bytes())
 original_classes={'ghidra.app.util.opinion.IntelHexRecordTest':{'testCtor','testChecksum'},'ghidra.app.util.opinion.IntelHexRecordReaderTest':{'testBasic'}}
 r['original_sha256']={}
 for c in original_classes:
  path='Ghidra/Features/Base/src/test/java/'+c.replace('.','/')+'.java';assert (p/path).read_bytes()==git('show',base+':'+path);r['original_sha256'][path]=sha((p/path).read_bytes())
 save();g=['./gradlew','--no-daemon','--max-workers=2','-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
 assert run('fetch',g+['-I','gradle/support/fetchDependencies.gradle','-DhideDownloadProgress','-DnoEclipse'])==0
 assert run('prep',g+['prepDev'])==0
 assert run('actual-toy-language',g+[':Toy:sleighCompile'])==0
 r['actual_toy_sha256']={str(f.relative_to(p)):sha(f.read_bytes()) for f in (p/'Ghidra/Processors/Toy/data/languages').glob('*.sla')};assert r['actual_toy_sha256'];save()
 results=p/'Ghidra/Features/Base/build/test-results/integrationTest';shutil.rmtree(results,ignore_errors=True)
 code=run('actual-public-intelhex-exporter',['xvfb-run','-a']+g+[':Base:integrationTest','--tests',klass]);assert code in (0,1)
 cases,stdout=parse_xml('actual-public-intelhex-exporter',results,{klass:set(targets)|controls});failures=[]
 for (c,name),x in cases.items():
  if x['kind']!='PASS':
   assert name in targets and x['kind']=='failure' and x['type']=='java.lang.AssertionError' and (x['message'] or '').startswith('java.lang.AssertionError: '+targets[name]);failures.append(name)
 if not failures:assert code==0
 def pairs(start,count,value):return {f'{start+i:08x}':f'{(value+i)&255:02x}' for i in range(count)}
 def read_pairs(text):
  if not text:return {}
  result={}
  for pair in text.split(','):
   address,value=pair.split(':');assert re.fullmatch('[0-9a-f]{8}',address) and re.fullmatch('[0-9a-f]{2}',value) and address not in result;result[address]=value
  return result
 input_maps={'sparse-blocks':pairs(0x1000,4,1)|pairs(0x1020,3,0xa1),'selection-holes':pairs(0x1000,4,1)|pairs(0x1008,4,9),'contiguous':pairs(0x1000,7,1),'adjacent-blocks':pairs(0x1000,7,1),'full-before-gap':pairs(0x1000,16,1)|pairs(0x1020,3,0xa1),'segment-change':pairs(0x1000,4,1)|pairs(0x10020,3,0xa1),'trailing-drop':pairs(0x1000,19,1),'empty-selection':{}}
 markers=re.findall(r'^INTEL_HEX_OBSERVATION .+$',stdout,re.MULTILINE);assert len(markers)==8;rows={}
 for line in markers:
  match=re.fullmatch(r'INTEL_HEX_OBSERVATION case=(\S+) input=(\S*) actual=(\S*) dataRecords=(\d+) extendedRecords=(\d+) eofRecords=(\d+) drop=(true|false)',line);assert match
  name=match[1];assert name in input_maps and name not in rows
  inp=read_pairs(match[2]);actual=read_pairs(match[3]);assert inp==input_maps[name] and int(match[6])==1 and (match[7]=='true')==(name=='trailing-drop')
  if name=='empty-selection':assert int(match[4])==int(match[5])==0
  else:assert int(match[4])>0 and int(match[5])==(2 if name=='segment-change' else 1)
  expected=pairs(0x1000,16,1) if name=='trailing-drop' else inp
  if name in ['sparse-blocks','selection-holes']:
   method={'sparse-blocks':'testSparseBlocksPreserveActualAddresses','selection-holes':'testSelectionHolesPreserveActualAddresses'}[name]
   assert (actual!=expected)==(method in failures)
   if method in failures:
    known=pairs(0x1000,4,1)|pairs(0x1004,3,0xa1) if name=='sparse-blocks' else pairs(0x1000,4,1)|pairs(0x1004,4,9)
    assert actual==known and int(match[4])==1
  else:assert actual==expected
  rows[name]={'input':inp,'actual':actual,'data_records':int(match[4]),'extended_records':int(match[5]),'eof_records':int(match[6]),'drop':match[7]=='true'}
 assert set(rows)==set(input_maps);r['observations']=rows;r['target_failure_names']=failures;save()
 original_results=p/'Ghidra/Features/Base/build/test-results/test';shutil.rmtree(original_results,ignore_errors=True)
 args=['xvfb-run','-a']+g+[':Base:test']
 for c in sorted(original_classes):args+=['--tests',c]
 original_code=run('original-record-reader-tests',args);assert original_code in (0,1)
 original_cases,_=parse_xml('original-record-reader-tests',original_results,original_classes)
 if all(x['kind']=='PASS' for x in original_cases.values()):assert original_code==0
 r['original_all_passed']=all(x['kind']=='PASS' for x in original_cases.values())
 for path,h in r['production_sha256'].items():assert sha((p/path).read_bytes())==h
 for path,h in r['original_sha256'].items():assert sha((p/path).read_bytes())==h
 assert sha((p/fixture).read_bytes())==r['fixture_sha256']
 status=git('status','--porcelain');(e/'git-status.raw').write_bytes(status);r['git_status_sha256']=sha(status);r['git_status_bytes']=len(status);save();assert status==b''
 r['status']='REPRODUCED_INTEL_HEX_ADDRESS_GAP_CORRUPTION' if failures else 'NOT_REPRODUCED'
except Exception as ex:r.update(error=str(ex),traceback=traceback.format_exc());raise
finally:r['finished_at']=utc();save()
