import datetime, hashlib, json, os, pathlib, re, shutil, subprocess, traceback
import xml.etree.ElementTree as ET
p=pathlib.Path.cwd(); e=p/'native-evidence';e.mkdir(exist_ok=True)
head=os.environ['HEAD_SHA'];base=os.environ['BASE_SHA'];cfg=json.loads(pathlib.Path(os.environ['CONFIG_FILE']).read_text())
cpp=p/'Ghidra/Features/Decompiler/src/decompile/cpp'
r={'head':head,'base':base,'status':'INCONCLUSIVE','steps':[],'full_build_passed':False}
def sha(b):return hashlib.sha256(b).hexdigest()
def save():(e/'receipt.json').write_text(json.dumps(r,indent=2)+'\n')
def git(ref,path):return subprocess.check_output(['git','show',ref+':'+path])
def run(label,args,**kwargs):
 started=datetime.datetime.now(datetime.timezone.utc).isoformat()
 with (e/(label+'.log')).open('w') as out:
  result=subprocess.run(args,stdout=out,stderr=subprocess.STDOUT,timeout=3600,**kwargs)
 r['steps'].append({'label':label,'args':args,'exit_code':result.returncode,'started_at':started,'ended_at':datetime.datetime.now(datetime.timezone.utc).isoformat()});save();return result.returncode
def capture_cleanliness(label):
 # Preserve exact tracked changes before the existing fail-closed cleanliness assertion.
 diff=subprocess.check_output(['git','diff','--name-only','-z','HEAD'])
 status=subprocess.check_output(['git','status','--porcelain=v1','-z'])
 assert len(diff)<=1048576 and len(status)<=1048576, 'Cleanliness path inventory exceeds bounded receipt'
 (e/(label+'-diff-paths.bin')).write_bytes(diff)
 (e/(label+'-status.bin')).write_bytes(status)
 inventory={'observed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
  'diff_paths_sha256':sha(diff),'status_sha256':sha(status),'tracked_changes':[]}
 remaining=8388608
 for raw in diff.split(b'\0'):
  if not raw:continue
  name=os.fsdecode(raw);path=p/name
  assert path.parent.resolve().is_relative_to(p.resolve())
  item={'path':name,'exists':path.exists(),'symlink':path.is_symlink()}
  for ref in ('HEAD',base):
   proc=subprocess.run(['git','rev-parse',ref+':'+name],capture_output=True,text=True)
   item[ref+'_git_blob']=proc.stdout.strip() if proc.returncode==0 else None
  if path.is_symlink():
   item['link_target']=os.readlink(path)
  elif path.is_file():
   digest=hashlib.sha256();count=0;content=bytearray();limit=min(262144,remaining)
   with path.open('rb') as stream:
    for block in iter(lambda:stream.read(65536),b''):
     digest.update(block);count+=len(block)
     if len(content)<limit:content.extend(block[:limit-len(content)])
   remaining-=len(content)
   item.update({'sha256':digest.hexdigest(),'bytes':count,'captured_bytes':len(content),
    'content_truncated':count>len(content),'content_utf8':content.decode('utf-8',errors='replace')})
  inventory['tracked_changes'].append(item)
 r[label+'_cleanliness']=inventory;save()
 return diff
def java_phase(label,module,classes,failures):
 result=p/('Ghidra/'+cfg['modules'][module]+'/build/test-results/'+('integrationTest' if module=='IntegrationTest' else 'test'))
 shutil.rmtree(result,ignore_errors=True)
 args=g+[':'+module+':'+('integrationTest' if module=='IntegrationTest' else 'test')]
 for klass in classes:args+=['--tests',klass]
 code=run(label,['xvfb-run','-a','-s','-screen 0 1600x1200x24']+args)
 assert (code in (0,1) if failures else code == 0) and result.is_dir()
 target=e/(label+'-xml');shutil.copytree(result,target)
 cases={};output='';xml_metadata={}
 for path in target.glob('*.xml'):
  xml=ET.parse(path).getroot();assert xml.get('errors')=='0' and xml.get('skipped')=='0'
  xml_metadata[path.name]={'sha256':sha(path.read_bytes()),'timestamp':xml.get('timestamp'),'tests':xml.get('tests'),'failures':xml.get('failures'),'errors':xml.get('errors'),'skipped':xml.get('skipped')}
  assert xml.get('timestamp') and int(xml.get('tests'))==len(list(xml.iter('testcase')))
  output+=xml.findtext('system-out','')
  for case in xml.iter('testcase'):
   identity=case.get('classname')+'.'+case.get('name');assert identity not in cases
   assert case.find('error') is None and case.find('skipped') is None
   failure=case.find('failure');cases[identity]=None if failure is None else {'type':failure.get('type'),'message':failure.get('message')}
 expected={name for klass in classes for name in cfg['java_cases'][klass]}
 assert set(cases)==expected
 assert {name for name,value in cases.items() if value is not None}==set(failures)
 for name,message in failures.items():assert cases[name]=={'type':'java.lang.AssertionError','message':'java.lang.AssertionError: '+message}
 if any('ArmOverrideCapacityTest' in klass for klass in classes):
  for count in (129,130,185):
   assert f'ARM_OVERRIDE_PRODUCER count={count} persisted=1 callsite=00001004 native='+str(native) in output
   complete=not failures or count==129
   assert f'ARM_OVERRIDE_OUTCOME count={count} completed={str(complete).lower()} error=' in output
   if not complete:
    lines=[x for x in output.splitlines() if x.startswith(f'ARM_OVERRIDE_OUTCOME count={count} ')]
    assert len(lines)==1 and 'Cannot assign parameter address' in lines[0]
 if any('ArmBoundedAllocationCompatibilityTest' in klass for klass in classes):
  markers=re.findall(r'^ARM_BOUNDED_PACKED=([A-Za-z0-9+/=]+)$',output,re.MULTILINE)
  assert len(markers)==1
  r[label+'_bounded_packed']=markers[0]
  if label.startswith('fixed-'):assert markers[0]==r['baseline-IntegrationTest_bounded_packed']
 original={key:value for key,value in cases.items() if key in cfg['original_java_cases']}
 if label.startswith('fixed-'):
  prior=r['baseline-'+module]['cases']
  assert original=={key:value for key,value in prior.items() if key in cfg['original_java_cases']}
 r[label]={'cases':cases,'original_cases':original,'xml_metadata':xml_metadata,'exit_code':code};save()
def units(label,contracts):
 parsers={}
 for name in ('xml','grammar'):
  path=cpp/(name+'.cc');original=git(base,str(path.relative_to(p)));assert path.read_bytes()==original
  os.utime(path,None);assert path.stat().st_mtime >= (cpp/(name+'.y')).stat().st_mtime;parsers[name]=original
 assert run(label+'-make',['make','-j2','decomp_test_dbg'],cwd=cpp)==0
 for name,b in parsers.items():assert (cpp/(name+'.cc')).read_bytes()==b
 assert run(label+'-units',[str(cpp/'decomp_test_dbg'),'-sleighpath',str(p),'unittests'],cwd=cpp)==0
 output=(e/(label+'-units.log')).read_text();cases={}
 for chunk in re.split(r'^testing : ',output,flags=re.MULTILINE)[1:]:
  name,body=chunk.split(' ...\n',1);assert name not in cases
  assert re.search(r'^  passed\.$',body,re.MULTILINE) and not re.search(r'^  fail(?:\n|:)',body,re.MULTILINE)
  cases[name]=True
 expected=set(cfg['original_cpp_cases']) | (set(cfg['contract_cpp_cases']) if contracts else set())
 assert set(cases)==expected and f'{len(expected)}/{len(expected)} tests passed.' in output
 r[label]={'cases':sorted(cases),'original_cases':len(cfg['original_cpp_cases']),'contracts':contracts};save()
def phase_hashes(label,ref):
 paths=cfg['production_paths']+cfg['original_paths']+['Ghidra/Features/Decompiler/src/decompile/cpp/'+name+'.cc' for name in ('xml','grammar')]
 hashes={}
 for path in paths:
  actual=(p/path).read_bytes();expected=git(ref,path) if path in cfg['production_paths'] else git(base,path)
  assert actual==expected
  hashes[path]={'actual':sha(actual),'expected':sha(expected)}
 r[label+'_source_fixture_parser_hashes']=hashes;save()
def check_originals():
 for path,content in originals.items():assert (p/path).read_bytes()==content
try:
 assert subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()==head
 actual=set(subprocess.check_output(['git','diff','--name-only',base,head],text=True).splitlines())
 assert actual==set(cfg['production_paths'])|set(cfg['fixture_paths'])
 originals={path:git(base,path) for path in cfg['original_paths']}
 fixed={path:git(head,path) for path in cfg['production_paths']}
 contracts={path:git(head,path) for path in cfg['fixed_only_paths']}
 initial_outputs={name: (cpp/name).exists() for name in ('test_dbg','com_opt','decomp_test_dbg','decomp_opt')};assert not any(initial_outputs.values())
 # Fixed-only fixtures use new APIs; remove them before compiling unchanged production.
 for path in contracts:(p/path).unlink()
 for path in fixed:(p/path).write_bytes(git(base,path))
 check_originals()
 g=['./gradlew','--no-daemon','--max-workers=2','-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
 assert run('fetch',g+['-I','gradle/support/fetchDependencies.gradle','-DhideDownloadProgress','-DnoEclipse'])==0
 assert run('baseline-prep',g+['prepDev'])==0
 languages=[':'+name+':sleighCompile' for name in cfg['languages']]
 assert run('baseline-native-languages',g+[':Decompiler:buildNatives']+languages)==0
 native=p/'Ghidra/Features/Decompiler/build/os/linux_x86_64/decompile';assert native.is_file()
 r['baseline_native_sha256']=sha(native.read_bytes());save()
 for module,classes in cfg['baseline_groups'].items():java_phase('baseline-'+module,module,classes,cfg['baseline_failures'].get(module,{}))
 units('baseline-cpp',False);check_originals();phase_hashes('baseline',base)
 for path,content in fixed.items():(p/path).write_bytes(content)
 for path,content in contracts.items():(p/path).parent.mkdir(parents=True,exist_ok=True);(p/path).write_bytes(content)
 assert run('fixed-prep',g+['prepDev'])==0
 assert run('fixed-native-languages',g+[':Decompiler:buildNatives']+languages)==0
 r['fixed_native_sha256']=sha(native.read_bytes());save()
 for module,classes in cfg['fixed_groups'].items():java_phase('fixed-'+module,module,classes,{})
 units('fixed-cpp',True);check_originals();phase_hashes('fixed',head)
 # Original Makefile outputs are outside Gradle's IP-aware build tree.
 removed={}
 for name in initial_outputs:
  path=cpp/name
  if not path.exists():continue
  assert not path.is_symlink()
  tracked=subprocess.check_output(['git','ls-files','--',str(path.relative_to(p))],text=True);assert not tracked
  if path.is_dir():
   removed[name]=[{ 'path':str(f.relative_to(p)),'sha256':sha(f.read_bytes()),'bytes':f.stat().st_size} for f in path.rglob('*') if f.is_file()]
   assert not any(f.is_symlink() for f in path.rglob('*'));shutil.rmtree(path)
  else:removed[name]={'sha256':sha(path.read_bytes()),'bytes':path.stat().st_size};path.unlink()
 r['owned_make_outputs_removed']=removed;save()
 assert capture_cleanliness('pre-full-build')==b''
 assert run('full-build',g+['buildGhidra'])==0
 assert 'BUILD SUCCESSFUL' in (e/'full-build.log').read_text()
 for path,content in fixed.items():assert (p/path).read_bytes()==content
 for path,content in contracts.items():assert (p/path).read_bytes()==content
 check_originals();assert subprocess.check_output(['git','diff','--name-only','HEAD'],text=True).strip()==''
 r['production_hashes']={path:{'base':sha(git(base,path)),'fixed':sha(content)} for path,content in fixed.items()}
 r['full_build_passed']=True;r['status']='EXACT_NATIVE_PASS';save()
except Exception:
 r['exception']=traceback.format_exc();save();raise
