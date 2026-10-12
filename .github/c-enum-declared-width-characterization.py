import pathlib,subprocess,json,xml.etree.ElementTree as ET,shutil,os,hashlib
p=pathlib.Path.cwd();e=p/'native-evidence';e.mkdir(exist_ok=True);head=os.environ['HEAD_SHA'];base=os.environ['BASE_SHA'];r={'head':head,'base':base,'status':'running','publication_gate':False,'production_unchanged':True,'full_build_passed':False,'steps':[]}
klass='ghidra.app.util.cparser.DeclaredWideEnumCharacterizationTest'
expected={'testWideUnsignedAndImplicitNext': 'expected:<4294967296> but was:<0>', 'testWideSignedNegative': 'expected:<-4294967297> but was:<-1>', 'testShiftedWideConstant': 'expected:<1099511627776> but was:<0>', 'testHighSignedConstant': 'expected:<9223372032559808512> but was:<0>', 'testSignedMinimum': 'expected:<-9223372036854775808> but was:<0>', 'testImplicitCrossesSignedIntBoundary': 'expected:<2147483648> but was:<-2147483648>'}
controls={'testSmallEightByteControl', 'testOrdinaryIntControl', 'testUnsignedMaximumRawBitsControl'}

def save():(e/'receipt.json').write_text(json.dumps(r,indent=2))
def run(label,args):
 with(e/(label+'.log')).open('w') as out:x=subprocess.run(args,stdout=out,stderr=subprocess.STDOUT)
 r['steps'].append({'label':label,'exit_code':x.returncode,'args':args});save();return x.returncode
g=['./gradlew','--no-daemon','--max-workers=2','-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
try:
 assert subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()==head
 assert subprocess.check_output(['git','diff','--name-only',base,head],text=True).splitlines()==['Ghidra/Features/Base/src/test/java/ghidra/app/util/cparser/DeclaredWideEnumCharacterizationTest.java']
 assert run('fetch',g+['-I','gradle/support/fetchDependencies.gradle','-DhideDownloadProgress','-DnoEclipse'])==0
 assert run('prep',g+['prepDev'])==0
 result=p/'Ghidra/Features/Base/build/test-results/test';shutil.rmtree(result,ignore_errors=True)
 code=run('characterization',g+[':Base:test','--tests',klass]);assert code in (0,1)
 shutil.copytree(result,e/'characterization-xml');cs=[]
 for f in(e/'characterization-xml').glob('*.xml'):
  for case in ET.parse(f).getroot().iter('testcase'):
   fail=case.find('failure');cs.append({'class':case.get('classname'),'name':case.get('name'),'failed':fail is not None,'error':case.find('error')is not None,'skipped':case.find('skipped')is not None,'failure_message':fail.get('message','') if fail is not None else '', 'failure_type':fail.get('type','') if fail is not None else ''})
 r['cases']=cs;save();assert len(cs)==9 and len({(c['class'],c['name'])for c in cs})==9
 assert {(c['class'],c['name'])for c in cs}=={(klass,n) for n in set(expected)|controls}
 assert not any(c['error']or c['skipped']for c in cs)
 assert {c['name']for c in cs if c['failed']}==set(expected)
 for c in cs:
  if c['name'] in expected:
   assert c['failure_type']=='java.lang.AssertionError'
   assert expected[c['name']] in c['failure_message']
 evidence_text=(e/'characterization.log').read_text()
 for f in(e/'characterization-xml').glob('*.xml'):
  for out in ET.parse(f).getroot().iter('system-out'):evidence_text+=out.text or ''
 for marker in ['ENUM_WIDTH member=WIDE expected=4294967296 actual=0 length=8', 'ENUM_WIDTH member=VALUE expected=-4294967297 actual=-1 length=8', 'ENUM_WIDTH member=VALUE expected=1099511627776 actual=0 length=8', 'ENUM_WIDTH member=VALUE expected=9223372032559808512 actual=0 length=8', 'ENUM_WIDTH member=VALUE expected=-9223372036854775808 actual=0 length=8', 'ENUM_WIDTH member=SECOND expected=2147483648 actual=-2147483648 length=8', 'ENUM_WIDTH member=SECOND expected=43 actual=43 length=8', 'ENUM_WIDTH member=LAST expected=2147483647 actual=2147483647 length=4', 'ENUM_WIDTH member=VALUE expected=-1 actual=-1 length=8']:assert marker in evidence_text
 assert not subprocess.check_output(['git','diff','--name-only'],text=True).strip()
 r['status']='REPRODUCED_DECLARED_WIDE_ENUM_TRUNCATION';r['observed_failures']=6;r['passing_controls']=3
except Exception as ex:
 import traceback
 r['status']='INCONCLUSIVE';r['error']=str(ex);r['traceback']=traceback.format_exc();raise
finally:save()
