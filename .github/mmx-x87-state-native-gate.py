import pathlib,subprocess,json,os,xml.etree.ElementTree as ET,shutil,hashlib
p=pathlib.Path.cwd();e=p/'native-evidence';e.mkdir();kind=os.environ['KIND'];head=os.environ['HEAD_SHA'];base='918d44ebc2962a53d23eeee52b8f44c7816e7815';cfg=json.loads(os.environ['CONFIG']);r={'kind':kind,'head':head,'base':base,'steps':[],'status':'running'}
def save():(e/'receipt.json').write_text(json.dumps(r,indent=2))
def run(label,args):
 with(e/(label+'.log')).open('w')as f:x=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT)
 r['steps'].append({'label':label,'args':args,'exit_code':x.returncode});save();print(label,x.returncode,flush=True)
 if x.returncode:print((e/(label+'.log')).read_text()[-5000:],flush=True)
 return x.returncode
def cases(files):return [{'name':c.get('name'),'class':c.get('classname'),'failed':c.find('failure')is not None,'error':c.find('error')is not None,'skipped':c.find('skipped')is not None,'failure_type':c.find('failure').get('type')if c.find('failure')is not None else '', 'failure_message':c.find('failure').get('message')if c.find('failure')is not None else ''}for f in files for c in ET.parse(f).getroot().iter('testcase')]
g=['./gradlew','--no-daemon','--max-workers=2','-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
try:
 assert subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()==head
 assert set(subprocess.check_output(['git','diff','--name-only',base,head],text=True).splitlines())=={'Ghidra/Processors/x86/data/languages/ia.sinc','Ghidra/Features/Base/src/test/java/ghidra/app/emulator/MmxX87StateTest.java'}
 for original_path in ['Ghidra/Test/IntegrationTest/src/test.slow/java/ghidra/pcode/emu/AbstractPcodeEmulatorTest.java','Ghidra/Test/IntegrationTest/src/test.slow/java/ghidra/pcode/emu/PlainPcodeEmulatorTest.java']:
  assert subprocess.check_output(['git','show',base+':'+original_path])==subprocess.check_output(['git','show',head+':'+original_path])
 assert run('fetch',g+['-I','gradle/support/fetchDependencies.gradle','-DhideDownloadProgress','-DnoEclipse'])==0
 assert run('prep',g+['prepDev'])==0
 assert run('actual-support-languages',g+[':Toy:sleighCompile',':ARM:sleighCompile'])==0
 if cfg['language']=='python':
  assert run('runtime',g+[':PyGhidra:jar',':LaunchSupport:jar',':JVM:jar',':JVM:sleighCompile',':PyGhidra:prepPyGhidra'])==0
  python=str(p/'build/venv/bin/python3');assert run('pytest-install',[python,'-m','pip','install','pytest','pytest-datadir'])==0;os.environ['GHIDRA_INSTALL_DIR']=str(p);cmd=[python,'-m','pytest','-p','no:cacheprovider',cfg['test_path'],'-k',cfg['pattern']]
  if cfg.get('marker'):cmd+=['-m',cfg['marker']]
 else:
  cmd=g+[cfg['test_task']]
  cmd+=['--tests',cfg['test_classes'][0]]
 prod=p/cfg['production'];fixed=prod.read_bytes();prod.write_bytes(subprocess.check_output(['git','show',base+':'+cfg['production']]))
 for phase in ['baseline','fixed']:
  if phase=='fixed':prod.write_bytes(fixed)
  assert prod.read_bytes()==(fixed if phase=='fixed' else subprocess.check_output(['git','show',base+':'+cfg['production']]))
  r[phase+'_production_sha256']=hashlib.sha256(prod.read_bytes()).hexdigest();save()
  language_dir=p/'Ghidra/Processors/x86/data/languages'
  for generated_sla in language_dir.glob('*.sla'):generated_sla.unlink()
  assert run(phase+'-actual-x86-compile',g+[':x86:sleighCompile','--rerun-tasks'])==0
  actual_sla=language_dir/'x86-64.sla';assert actual_sla.is_file()
  r[phase+'_sla_sha256']=hashlib.sha256(actual_sla.read_bytes()).hexdigest();save()
  if cfg['language']=='python':
   xml=e/(phase+'.xml');rc=run(phase,cmd+['--junitxml='+str(xml)]);cs=cases([xml])
  else:
   result=p/cfg['result_dir'];shutil.rmtree(result,ignore_errors=True)
   rc=run(phase,cmd);shutil.copytree(result,e/(phase+'-xml'));cs=cases((e/(phase+'-xml')).glob('*.xml'))
  original_result=p/'Ghidra/Test/IntegrationTest/build/test-results/integrationTest'
  shutil.rmtree(original_result,ignore_errors=True)
  original_rc=run(phase+'-original-emulator',['xvfb-run','-a']+g+[':IntegrationTest:integrationTest','--tests',cfg['test_classes'][1]])
  shutil.copytree(original_result,e/(phase+'-original-xml'))
  original_cases=cases((e/(phase+'-original-xml')).glob('*.xml'))
  assert original_rc==0 and len(original_cases)==9 and not any(c['failed']or c['error']or c['skipped']for c in original_cases)
  cs+=original_cases
  output='\n'.join(ET.parse(f).getroot().findtext('system-out','')for f in (e/(phase+'-xml')).glob('*.xml'))
  expected_observations=16 if phase=='baseline' else 30
  assert output.count('MMX_CURRENT_SLA mnemonic=')==expected_observations
  assert output.count('MMX_SAVE mnemonic=')==expected_observations
  r[phase+'_actual_save_observations']=expected_observations
  r[phase]={'exit_code':rc,'original_exit_code':original_rc,'cases':cs};save();assert len(cs)==cfg['total'];assert not any(c['error']or c['skipped']for c in cs)
  if cfg['language']=='java':
   assert {c['class']for c in cs}==set(cfg['test_classes'])
   assert {k:sum(c['class']==k for c in cs)for k in cfg['test_classes']}==cfg['class_counts']
   assert len({(c['class'],c['name'])for c in cs})==len(cs)
   assert {(c['class'],c['name'])for c in cs}=={tuple(x)for x in cfg['expected_cases']}
  if phase=='baseline':
   assert rc==1 if cfg['language']=='python' else rc in (0,1)
   assert {(c['class'],c['name'])for c in cs if c['failed']}=={tuple(x)for x in cfg['failures']}
   expected_highs={'testPxorFirstRegister': 4660, 'testPxorLastRegister': 4667, 'testMovdRegisterTransfer': 4662, 'testPackedByteArithmetic': 4664, 'testReversedMovqDestination': 4666, 'testSignedMaximumConditionalWrite': 4663, 'testUnsignedMaximumConditionalWrite': 4663, 'testSignedMinimumUnchangedLowBits': 4663, 'testUnsignedMinimumUnchangedLowBits': 4663, 'testEveryRegisterDestinationMapping': 4660, 'testEveryReversedDestinationMapping': 4660, 'testMemorySourceWrite': 4660}
   assert all(c['failure_type']=='java.lang.AssertionError' and c['failure_message']=='java.lang.AssertionError: MMX writes set only the corresponding x87 high bits expected:<65535> but was:<'+str(expected_highs[c['name']])+'>'for c in cs if c['failed'])
  else:assert rc==0 and not any(c['failed']for c in cs)
 if cfg['language']=='python':
  xml=e/'full-suite.xml';full=[python,'-m','pytest','-p','no:cacheprovider',cfg['test_path'],'--junitxml='+str(xml)]+(['-m',cfg['marker']]if cfg.get('marker')else []);assert run('full-suite',full)==0;cs=cases([xml]);assert len(cs)>cfg['total']and not any(c['failed']or c['error']or c['skipped']for c in cs);r['full_suite']={'cases':cs};save()
 assert r['baseline_sla_sha256']!=r['fixed_sla_sha256']
 assert run('full-build',g+['buildGhidra'])==0
 assert not subprocess.check_output(['git','diff','--name-only'],text=True).strip()
 r['status']='passed';r['full_build_passed']=True
except Exception as ex:
 import traceback
 r['status']='failed';r['error']=str(ex);r['traceback']=traceback.format_exc();raise
finally:save()
