import datetime,hashlib,json,os,pathlib,re,shutil,signal,subprocess,traceback
import xml.etree.ElementTree as ET
p=pathlib.Path.cwd().resolve();e=pathlib.Path(os.environ['EVIDENCE_DIR']).resolve();assert e!=p and p not in e.parents;e.mkdir(parents=True,exist_ok=True)
head=os.environ['HEAD_SHA'];base=os.environ['BASE_SHA'];klass='ghidra.app.util.exporter.IntelHexExportGapTest'
fixture='Ghidra/Features/Base/src/test.slow/java/'+klass.replace('.','/')+'.java'
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sha(b):return hashlib.sha256(b).hexdigest()
def git(*a):return subprocess.check_output(['git',*a])
r={'utc':utc(),'head':head,'base':base,'status':'INCONCLUSIVE','discovery_only':False,'publication_gate':False,'full_build_passed':False,'steps':[]}
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
fixed={}
try:
 assert base=='918d44ebc2962a53d23eeee52b8f44c7816e7815' and git('rev-parse','HEAD').decode().strip()==head
 option='ghidra.app.util.exporter.IntelHexRecordSizeTest'
 fixtures={c:'Ghidra/Features/Base/src/test.slow/java/'+c.replace('.','/')+'.java' for c in [klass,option]}
 products=['Ghidra/Features/Base/src/main/java/ghidra/app/util/exporter/IntelHexExporter.java','Ghidra/Features/Base/src/main/java/ghidra/app/util/opinion/IntelHexRecordWriter.java']
 assert head=='b9d67d3473d1a8771cc92777c6eb4e5cee183dfc'
 assert set(git('diff','--name-only',base,head).decode().splitlines())==set(products)
 historical='71b6849b8cdb00da7cc5630db6867b936061a230'
 for x in products: assert (p/x).read_bytes()==git('show',historical+':'+x)
 for x in fixtures.values():
  assert not (p/x).exists()
  (p/x).parent.mkdir(parents=True,exist_ok=True)
  (p/x).write_bytes(git('show',historical+':'+x))
 fixed={x:(p/x).read_bytes() for x in products};baseline={x:git('show',base+':'+x) for x in products};assert all(fixed[x]!=baseline[x] for x in products)
 fixture_bytes={x:(p/x).read_bytes() for x in fixtures.values()}
 methods={c:set(re.findall(r'@Test public void (\w+)\(', (p/x).read_text())) for c,x in fixtures.items()};assert len(methods[klass])==13 and len(methods[option])==6
 originals={'ghidra.app.util.opinion.IntelHexRecordTest':{'testCtor','testChecksum'},'ghidra.app.util.opinion.IntelHexRecordReaderTest':{'testBasic'}}
 original_paths=['Ghidra/Features/Base/src/test/java/'+c.replace('.','/')+'.java' for c in originals]
 for x in original_paths:assert (p/x).read_bytes()==git('show',base+':'+x)
 original_hashes={x:sha((p/x).read_bytes()) for x in original_paths}
 r['inputs']={'production_base':{x:sha(v) for x,v in baseline.items()},'production_fixed':{x:sha(v) for x,v in fixed.items()},'fixtures':{x:sha(v) for x,v in fixture_bytes.items()},'originals':original_hashes};save()
 targets={option:{'testHexPrefix','testHashHexPrefix','testAcceptedOctalPrefix'},klass:{'testSparseBlocksPreserveActualAddresses','testSelectionHolesPreserveActualAddresses','testGapFlushesEarlierPartialButDropsTerminalPartial','testSegmentedGapAndSegmentBoundaryPreserveOffsets','testDescendingAddressesStartSeparateRecords','testSpaceMaximumDoesNotWrapBufferedRecord'}}
 g=['./gradlew','--no-daemon','--max-workers=2','-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
 assert run('fetch',g+['-I','gradle/support/fetchDependencies.gradle','-DhideDownloadProgress','-DnoEclipse'])==0
 assert run('prep',g+['prepDev'])==0
 assert run('actual-native-and-toy',g+[':Decompiler:buildNatives',':Toy:sleighCompile'])==0
 native=p/'Ghidra/Features/Decompiler/build/os/linux_x86_64/decompile';assert native.is_file()
 r['native_sha256']=sha(native.read_bytes());r['toy_sha256']={str(x.relative_to(p)):sha(x.read_bytes()) for x in (p/'Ghidra/Processors/Toy/data/languages').glob('*.sla')};assert r['toy_sha256'];save()
 def invoke(label,classes,task):
  results=p/('Ghidra/Features/Base/build/test-results/'+task);shutil.rmtree(results,ignore_errors=True)
  args=['xvfb-run','-a','-s','-screen 0 1600x1200x24']+g+[':Base:'+task]
  for c in classes:args+=['--tests',c]
  code=run(label,args);assert code in (0,1)
  rows,stdout=parse_xml(label,results,classes);return code,rows,stdout
 old={}
 for phase,data in [('baseline',baseline),('fixed',fixed)]:
  for x,v in data.items():(p/x).write_bytes(v)
  assert all((p/x).read_bytes()==v for x,v in data.items()) and all((p/x).read_bytes()==v for x,v in fixture_bytes.items())
  r[phase+'-inputs']={'products':{x:sha((p/x).read_bytes()) for x in products},'fixtures':{x:sha((p/x).read_bytes()) for x in fixture_bytes},'originals':{x:sha((p/x).read_bytes()) for x in original_paths}};save()
  code,rows,stdout=invoke(phase+'-export',methods,'integrationTest')
  failures={(c,n) for (c,n),v in rows.items() if v['kind']!='PASS'}
  assert failures==({(c,n) for c,names in targets.items() for n in names} if phase=='baseline' else set())
  if phase=='fixed':assert code==0
  for c,n in failures:
   x=rows[(c,n)];assert x['kind']=='failure' and x['type']=='java.lang.AssertionError'
   message=(x['message'] or '').removeprefix('java.lang.AssertionError: ')
   if c==option:
    expected='Actual accepted record-size data lengths expected:<[8, 8, 4]> but was:<[10, 10]>' if n=='testAcceptedOctalPrefix' else 'Actual valid record-size option must export expected:<true> but was:<false>'
    assert message==expected
   elif n=='testSegmentedGapAndSegmentBoundaryPreserveOffsets':assert message=='expected:<6> but was:<5>'
   elif n in ['testDescendingAddressesStartSeparateRecords','testSpaceMaximumDoesNotWrapBufferedRecord']:assert message=='expected:<2> but was:<1>'
   else:
    prefix={'testSparseBlocksPreserveActualAddresses':'Sparse initialized block export must preserve actual address-byte map','testSelectionHolesPreserveActualAddresses':'Sparse selection export must preserve actual address-byte map','testGapFlushesEarlierPartialButDropsTerminalPartial':'A gap flushes the earlier partial record; trailing drop applies at finish'}[n];assert message.startswith(prefix+' expected:<')
  markers=[x for x in stdout.splitlines() if x.startswith('INTELHEX_SIZE_')];expected=[]
  for text,valid,size in [('0x10',True,16),('#10',True,16),('010',True,8),('16',True,16),('EMPTY',False,16),('256',False,16)]:
   broken=phase=='baseline' and text in ['0x10','#10'];expected.append(f'INTELHEX_SIZE_INPUT text={text} valid={str(valid).lower()} expectedSize={size} exported={str(not broken).lower()} error={"java.lang.NumberFormatException" if broken else "NONE"}')
   if not broken:
    lengths='[10, 10]' if phase=='baseline' and text=='010' else '[8, 8, 4]' if text=='010' else '[16, 4]';expected.append(f'INTELHEX_SIZE_OUTPUT text={text} lengths={lengths} bytes=20 eof=1')
  assert sorted(markers)==sorted(expected)
  gapmarkers=[x for x in stdout.splitlines() if x.startswith('INTEL_HEX_OBSERVATION ')];assert len(gapmarkers)==10 and len(set(gapmarkers))==10
  def pairs(start,count,value):return {f'{start+i:08x}':f'{(value+i)&255:02x}' for i in range(count)}
  def read_pairs(text):
   result={}
   if text:
    for pair in text.split(','):
     address,value=pair.split(':');assert re.fullmatch('[0-9a-f]{8}',address) and re.fullmatch('[0-9a-f]{2}',value) and address not in result;result[address]=value
   return result
  inputs={'sparse-blocks':pairs(0x1000,4,1)|pairs(0x1020,3,0xa1),'selection-holes':pairs(0x1000,4,1)|pairs(0x1008,4,9),'contiguous':pairs(0x1000,7,1),'adjacent-blocks':pairs(0x1000,7,1),'full-before-gap':pairs(0x1000,16,1)|pairs(0x1020,3,0xa1),'segment-change':pairs(0x1000,4,1)|pairs(0x10020,3,0xa1),'trailing-drop':pairs(0x1000,19,1),'empty-selection':{},'gap-trailing-drop':pairs(0x1000,4,1)|pairs(0x1020,3,0xa1),'segment-trailing-drop':pairs(0x1000,4,1)|pairs(0x10020,3,0xa1)}
  observations={}
  for line in gapmarkers:
   m=re.fullmatch(r'INTEL_HEX_OBSERVATION case=(\S+) input=(\S*) actual=(\S*) dataRecords=(\d+) extendedRecords=(\d+) eofRecords=(\d+) drop=(true|false)',line);assert m
   name=m[1];assert name in inputs and name not in observations
   inp=read_pairs(m[2]);actual=read_pairs(m[3]);assert inp==inputs[name] and int(m[6])==1
   drop=name in ['trailing-drop','gap-trailing-drop','segment-trailing-drop'];assert (m[7]=='true')==drop
   expected=pairs(0x1000,16,1) if name=='trailing-drop' else pairs(0x1000,4,1) if name in ['gap-trailing-drop','segment-trailing-drop'] else inp
   records=0 if name=='empty-selection' else 2 if name in ['sparse-blocks','selection-holes','full-before-gap','segment-change'] else 1
   if phase=='baseline':
    if name=='sparse-blocks':expected=pairs(0x1000,4,1)|pairs(0x1004,3,0xa1);records=1
    elif name=='selection-holes':expected=pairs(0x1000,4,1)|pairs(0x1004,4,9);records=1
    elif name=='gap-trailing-drop':expected={};records=0
   assert actual==expected and int(m[4])==records and int(m[5])==(0 if name=='empty-selection' else 2 if name in ['segment-change','segment-trailing-drop'] else 1)
   observations[name]={'input':inp,'actual':actual,'data_records':int(m[4]),'extended_records':int(m[5]),'drop':drop}
  assert set(observations)==set(inputs)
  r[phase+'-markers']={'size':markers,'gap':gapmarkers,'observations':observations};save()
  code,old[phase],_=invoke(phase+'-originals',originals,'test');assert code==0 and all(v['kind']=='PASS' for v in old[phase].values())
 assert old['baseline']==old['fixed'];r['original_all_passed']=True
 assert run('full-build',g+['buildGhidra'])==0 and 'BUILD SUCCESSFUL' in (e/'full-build.log').read_text();r['full_build_passed']=True
 assert all((p/x).read_bytes()==v for x,v in fixed.items()) and all((p/x).read_bytes()==v for x,v in fixture_bytes.items())
 assert all(sha((p/x).read_bytes())==h for x,h in original_hashes.items())
 for x in fixtures.values(): (p/x).unlink()
 status=git('status','--porcelain');(e/'final-git-status.bin').write_bytes(status);r['final_status_sha256']=sha(status);save();assert status==b''
 r.update(status='QUALIFIED_INTELHEX_EXPORT_BASELINE_FIXED',publication_gate=True)
except Exception as ex:r.update(status='INCONCLUSIVE',error=str(ex),traceback=traceback.format_exc());raise
finally:
 for x in locals().get('fixtures',{}).values():
  if (p/x).exists(): (p/x).unlink()
 for x,v in fixed.items():(p/x).write_bytes(v)
 r['finished_at']=utc();save()
 print(json.dumps({'head':head,'status':r['status'],'full_build_passed':r['full_build_passed'],'counts':{key:{kind:sum(x['kind']==kind for x in r.get(key,{}).get('cases',[])) for kind in ['PASS','failure','error','skipped']} for key in ['baseline-export','fixed-export','baseline-originals','fixed-originals']}}),flush=True)
