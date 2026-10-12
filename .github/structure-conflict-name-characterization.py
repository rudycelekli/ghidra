import pathlib,subprocess,json,xml.etree.ElementTree as ET,shutil,os,hashlib
p=pathlib.Path.cwd();e=p/'native-evidence';e.mkdir(exist_ok=True);head=os.environ['HEAD_SHA'];base=os.environ['BASE_SHA'];r={'head':head,'base':base,'status':'running','publication_gate':False,'production_unchanged':True,'full_build_passed':False,'steps':[]}
klass='ghidra.app.plugin.core.compositeeditor.StructureConflictNameCharacterizationTest'
target='testConflictSuffixStructureCanContainBaseNamedStructure'
controls={'testOrdinaryDifferentNameControl'}

def save():(e/'receipt.json').write_text(json.dumps(r,indent=2))
def run(label,args):
 with(e/(label+'.log')).open('w') as out:x=subprocess.run(args,stdout=out,stderr=subprocess.STDOUT)
 r['steps'].append({'label':label,'exit_code':x.returncode,'args':args});save();return x.returncode
g=['./gradlew','--no-daemon','--max-workers=2','-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
try:
 assert subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()==head
 assert subprocess.check_output(['git','diff','--name-only',base,head],text=True).splitlines()==['Ghidra/Features/Base/src/test.slow/java/ghidra/app/plugin/core/compositeeditor/StructureConflictNameCharacterizationTest.java']
 assert run('fetch',g+['-I','gradle/support/fetchDependencies.gradle','-DhideDownloadProgress','-DnoEclipse'])==0
 assert run('prep',g+['prepDev'])==0
 assert run('actual-toy-language',g+[':Toy:sleighCompile'])==0
 result=p/'Ghidra/Features/Base/build/test-results/integrationTest';shutil.rmtree(result,ignore_errors=True)
 code=run('characterization',['xvfb-run','-a','-s','-screen 0 1600x1200x24']+g+[':Base:integrationTest','--tests',klass]);assert code in (0,1)
 shutil.copytree(result,e/'characterization-xml');cs=[]
 for f in(e/'characterization-xml').glob('*.xml'):
  for case in ET.parse(f).getroot().iter('testcase'):
   fail=case.find('failure');cs.append({'class':case.get('classname'),'name':case.get('name'),'failed':fail is not None,'error':case.find('error')is not None,'skipped':case.find('skipped')is not None,'failure_message':fail.get('message','') if fail is not None else '', 'failure_type':fail.get('type','') if fail is not None else ''})
 r['cases']=cs;save();assert len(cs)==2 and len({(c['class'],c['name'])for c in cs})==2
 assert {(c['class'],c['name'])for c in cs}=={(klass,n) for n in {target}|controls}
 assert not any(c['error']or c['skipped']for c in cs)
 assert not any(c['failed'] for c in cs if c['name'] in controls)
 observed=next(c for c in cs if c['name']==target)
 if observed['failed']:assert observed['failure_type']=='org.junit.ComparisonFailure' and "can't contain itself." in observed['failure_message']
 evidence_text=(e/'characterization.log').read_text()
 for f in(e/'characterization-xml').glob('*.xml'):
  for out in ET.parse(f).getroot().iter('system-out'):evidence_text+=out.text or ''
 assert 'STRUCTURE_NAME_DROP target=bar source=foo components=1 status=' in evidence_text
 if observed['failed']:
  assert "STRUCTURE_NAME_DROP target=foo.conflict source=foo components=0 status=Data type \"foo.conflict\" can't contain itself." in evidence_text
 else:
  assert 'STRUCTURE_NAME_DROP target=foo.conflict source=foo components=1 status=' in evidence_text
 assert not subprocess.check_output(['git','diff','--name-only'],text=True).strip()
 r['status']='REPRODUCED_EDITOR_NAME_COLLISION' if observed['failed'] else 'NOT_REPRODUCED';r['observed_failures']=int(observed['failed']);r['passing_controls']=1
except Exception as ex:
 import traceback
 r['status']='INCONCLUSIVE';r['error']=str(ex);r['traceback']=traceback.format_exc();raise
finally:save()
