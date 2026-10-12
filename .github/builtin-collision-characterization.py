import pathlib,subprocess,json,xml.etree.ElementTree as ET,shutil,os
p=pathlib.Path.cwd();e=p/'native-evidence';e.mkdir(exist_ok=True);head=os.environ['HEAD_SHA'];base=os.environ['BASE_SHA'];r={'head':head,'base':base,'status':'running','publication_gate':False,'production_unchanged':True,'steps':[]}
def save():(e/'receipt.json').write_text(json.dumps(r,indent=2))
def run(label,args):
 with(e/(label+'.log')).open('w') as out:x=subprocess.run(args,stdout=out,stderr=subprocess.STDOUT)
 r['steps'].append({'label':label,'exit_code':x.returncode,'args':args});save();return x.returncode
g=['./gradlew','--no-daemon','--max-workers=2','-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
try:
 assert subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()==head
 assert subprocess.check_output(['git','diff','--name-only',base,head],text=True).splitlines()==['Ghidra/Features/Base/src/test.slow/java/ghidra/program/database/dtarchive/BuiltInCollisionCharacterizationTest.java']
 assert run('fetch',g+['-I','gradle/support/fetchDependencies.gradle','-DhideDownloadProgress','-DnoEclipse'])==0
 assert run('prep',g+['prepDev'])==0
 result=p/'Ghidra/Features/Base/build/test-results/integrationTest';shutil.rmtree(result,ignore_errors=True)
 assert run('characterization',g+[':Base:integrationTest','--tests','ghidra.program.database.dtarchive.BuiltInCollisionCharacterizationTest'])==0
 shutil.copytree(result,e/'characterization-xml');cs=[]
 for f in(e/'characterization-xml').glob('*.xml'):
  for case in ET.parse(f).getroot().iter('testcase'):cs.append({'class':case.get('classname'),'name':case.get('name'),'failed':case.find('failure')is not None,'error':case.find('error')is not None,'skipped':case.find('skipped')is not None})
 r['cases']=cs;save();assert len(cs)==2 and len({(c['class'],c['name'])for c in cs})==2
 assert {(c['class'],c['name'])for c in cs}=={('ghidra.program.database.dtarchive.BuiltInCollisionCharacterizationTest','testIncompatibleExtensionCollisionIsCurrentlySilent'),('ghidra.program.database.dtarchive.BuiltInCollisionCharacterizationTest','testUniqueExtensionIsDiscoveredAndResolved')}
 assert not any(c['failed']or c['error']or c['skipped']for c in cs)
 xml=''.join(f.read_text()for f in(e/'characterization-xml').glob('*.xml'))
 assert 'ACTUAL_EXTENSION_CHARACTERIZED:byte' in xml and 'ACTUAL_EXTENSION_CHARACTERIZED:fixture_unique_byte' in xml
 assert not subprocess.check_output(['git','diff','--name-only'],text=True).strip()
 r['status']='characterized';r['full_build_passed']=False
except Exception as ex:
 import traceback
 r['status']='failed';r['error']=str(ex);r['traceback']=traceback.format_exc();raise
finally:save()
