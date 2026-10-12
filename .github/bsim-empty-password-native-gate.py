import pathlib,subprocess,json,os,xml.etree.ElementTree as ET,shutil
p=pathlib.Path.cwd();e=p/'native-evidence';e.mkdir();kind=os.environ['KIND'];head=os.environ['HEAD_SHA'];base='918d44ebc2962a53d23eeee52b8f44c7816e7815';cfg=json.loads(os.environ['CONFIG']);r={'kind':kind,'head':head,'base':base,'steps':[],'status':'running'}
def save():(e/'receipt.json').write_text(json.dumps(r,indent=2))
def run(label,args):
 with(e/(label+'.log')).open('w')as f:x=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT)
 r['steps'].append({'label':label,'args':args,'exit_code':x.returncode});save();print(label,x.returncode,flush=True)
 if x.returncode:print((e/(label+'.log')).read_text()[-5000:],flush=True)
 return x.returncode
def cases(files):return [{'name':c.get('name'),'class':c.get('classname'),'failed':c.find('failure')is not None,'error':c.find('error')is not None,'skipped':c.find('skipped')is not None}for f in files for c in ET.parse(f).getroot().iter('testcase')]
g=['./gradlew','--no-daemon','--max-workers=2','-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
try:
 assert subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()==head
 assert set(subprocess.check_output(['git','diff','--name-only',base,head],text=True).splitlines())==set(cfg['source_paths'])
 assert run('fetch',g+['-I','gradle/support/fetchDependencies.gradle','-DhideDownloadProgress','-DnoEclipse'])==0
 assert run('prep',g+['prepDev'])==0
 assert run('actual-toy-language',g+[':Toy:sleighCompile'])==0
 if cfg['language']=='python':
  assert run('runtime',g+[':PyGhidra:jar',':LaunchSupport:jar',':JVM:jar',':JVM:sleighCompile',':PyGhidra:prepPyGhidra'])==0
  python=str(p/'build/venv/bin/python3');assert run('pytest-install',[python,'-m','pip','install','pytest','pytest-datadir'])==0;os.environ['GHIDRA_INSTALL_DIR']=str(p);cmd=[python,'-m','pytest','-p','no:cacheprovider',cfg['test_path'],'-k',cfg['pattern']]
  if cfg.get('marker'):cmd+=['-m',cfg['marker']]
 else:
  cmd=g+[cfg['test_task']]
  for test_class in cfg['test_classes']:cmd+=['--tests',test_class]
 prod=p/cfg['production'];fixed=prod.read_bytes();prod.write_bytes(subprocess.check_output(['git','show',base+':'+cfg['production']]))
 for phase in ['baseline','fixed']:
  if phase=='fixed':prod.write_bytes(fixed)
  if cfg['language']=='python':
   xml=e/(phase+'.xml');rc=run(phase,cmd+['--junitxml='+str(xml)]);cs=cases([xml])
  else:
   result=p/cfg['result_dir'];shutil.rmtree(result,ignore_errors=True)
   rc=run(phase,cmd);shutil.copytree(result,e/(phase+'-xml'));cs=cases((e/(phase+'-xml')).glob('*.xml'))
  r[phase]={'exit_code':rc,'cases':cs};save();assert len(cs)==cfg['total'];assert not any(c['error']or c['skipped']for c in cs)
  if cfg['language']=='java':
   assert {c['class']for c in cs}==set(cfg['test_classes'])
   assert {k:sum(c['class']==k for c in cs)for k in cfg['test_classes']}==cfg['class_counts']
   assert len({(c['class'],c['name'])for c in cs})==len(cs)
   assert {(c['class'],c['name'])for c in cs}=={tuple(x)for x in cfg['expected_cases']}
  if phase=='baseline':
   assert rc==1 if cfg['language']=='python' else rc in (0,1)
   assert {(c['class'],c['name'])for c in cs if c['failed']}=={tuple(x)for x in cfg['failures']}
  else:assert rc==0 and not any(c['failed']for c in cs)
 if cfg['language']=='python':
  xml=e/'full-suite.xml';full=[python,'-m','pytest','-p','no:cacheprovider',cfg['test_path'],'--junitxml='+str(xml)]+(['-m',cfg['marker']]if cfg.get('marker')else []);assert run('full-suite',full)==0;cs=cases([xml]);assert len(cs)>cfg['total']and not any(c['failed']or c['error']or c['skipped']for c in cs);r['full_suite']={'cases':cs};save()
 assert run('full-build',g+['buildGhidra'])==0
 assert not subprocess.check_output(['git','diff','--name-only'],text=True).strip()
 r['status']='passed';r['full_build_passed']=True
except Exception as ex:
 import traceback
 r['status']='failed';r['error']=str(ex);r['traceback']=traceback.format_exc();raise
finally:save()
