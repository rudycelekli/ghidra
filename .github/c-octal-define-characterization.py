import pathlib,subprocess,json,xml.etree.ElementTree as ET,shutil,os,hashlib
p=pathlib.Path.cwd();e=p/'native-evidence';e.mkdir(exist_ok=True);head=os.environ['HEAD_SHA'];base=os.environ['BASE_SHA'];r={'head':head,'base':base,'status':'running','publication_gate':False,'production_unchanged':True,'full_build_passed':False,'steps':[]}
klass='ghidra.app.util.cparser.OctalDefineEquateTest'
expected={'testOctalOrExpression':'expected:<9> but was:<11>','testOctalShiftExpression':'expected:<16> but was:<20>','testOctalAdditionExpression':'expected:<9> but was:<11>','testExpandedOctalExpression':'expected:<9> but was:<11>'}
controls={'testSingleOctalLiteralControl','testDecimalAndHexExpressionControl'}
def save():(e/'receipt.json').write_text(json.dumps(r,indent=2))
def run(label,args):
 with(e/(label+'.log')).open('w') as out:x=subprocess.run(args,stdout=out,stderr=subprocess.STDOUT)
 r['steps'].append({'label':label,'exit_code':x.returncode,'args':args});save();return x.returncode
g=['./gradlew','--no-daemon','--max-workers=2','-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
try:
 assert subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()==head
 assert subprocess.check_output(['git','diff','--name-only',base,head],text=True).splitlines()==['Ghidra/Features/Base/src/test/java/ghidra/app/util/cparser/OctalDefineEquateTest.java']
 assert run('fetch',g+['-I','gradle/support/fetchDependencies.gradle','-DhideDownloadProgress','-DnoEclipse'])==0
 assert run('prep',g+['prepDev'])==0
 result=p/'Ghidra/Features/Base/build/test-results/test';shutil.rmtree(result,ignore_errors=True)
 code=run('characterization',g+[':Base:test','--tests',klass]);assert code in (0,1)
 shutil.copytree(result,e/'characterization-xml');cs=[]
 for f in(e/'characterization-xml').glob('*.xml'):
  for case in ET.parse(f).getroot().iter('testcase'):
   fail=case.find('failure');cs.append({'class':case.get('classname'),'name':case.get('name'),'failed':fail is not None,'error':case.find('error')is not None,'skipped':case.find('skipped')is not None,'failure_message':fail.get('message','') if fail is not None else ''})
 r['cases']=cs;save();assert len(cs)==6 and len({(c['class'],c['name'])for c in cs})==6
 assert {(c['class'],c['name'])for c in cs}=={(klass,n) for n in set(expected)|controls}
 assert not any(c['error']or c['skipped']for c in cs)
 assert {c['name']for c in cs if c['failed']}==set(expected)
 for c in cs:
  if c['name'] in expected:assert expected[c['name']] in c['failure_message']
 assert not subprocess.check_output(['git','diff','--name-only'],text=True).strip()
 r['status']='REPRODUCED_COMPOUND_OCTAL_VALUE_MISMATCH';r['observed_failures']=4;r['passing_controls']=2
except Exception as ex:
 import traceback
 r['status']='INCONCLUSIVE';r['error']=str(ex);r['traceback']=traceback.format_exc();raise
finally:save()
