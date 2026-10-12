import pathlib,subprocess,json,xml.etree.ElementTree as ET,shutil,os,hashlib
p=pathlib.Path.cwd();e=p/'native-evidence';e.mkdir(exist_ok=True);head=os.environ['HEAD_SHA'];base=os.environ['BASE_SHA'];r={'head':head,'base':base,'status':'running','publication_gate':False,'production_unchanged':True,'full_build_passed':False,'steps':[]}
klass='ghidra.app.util.cparser.MacroCastCharacterizationTest'
expected={'testAliasHighBit16':'expected:<-32768> but was:<32768>','testAliasHighBit32':'expected:<-2147483648> but was:<2147483648>','testBuiltinAllBits16':'expected:<-1> but was:<65535>','testBuiltinAllBits32':'expected:<-1> but was:<4294967295>'}
controls={'testUnsignedHighBit16Control','testUnsignedHighBit32Control','testUncastHighBitControl','testPositiveCastControl'}

def save():(e/'receipt.json').write_text(json.dumps(r,indent=2))
def run(label,args):
 with(e/(label+'.log')).open('w') as out:x=subprocess.run(args,stdout=out,stderr=subprocess.STDOUT)
 r['steps'].append({'label':label,'exit_code':x.returncode,'args':args});save();return x.returncode
g=['./gradlew','--no-daemon','--max-workers=2','-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
try:
 assert subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()==head
 assert subprocess.check_output(['git','diff','--name-only',base,head],text=True).splitlines()==['Ghidra/Features/Base/src/test/java/ghidra/app/util/cparser/MacroCastCharacterizationTest.java']
 assert run('fetch',g+['-I','gradle/support/fetchDependencies.gradle','-DhideDownloadProgress','-DnoEclipse'])==0
 assert run('prep',g+['prepDev'])==0
 assert run('actual-x86-language',g+[':x86:sleighCompile'])==0
 result=p/'Ghidra/Features/Base/build/test-results/test';shutil.rmtree(result,ignore_errors=True)
 code=run('characterization',g+[':Base:test','--tests',klass]);assert code in (0,1)
 shutil.copytree(result,e/'characterization-xml');cs=[]
 for f in(e/'characterization-xml').glob('*.xml'):
  for case in ET.parse(f).getroot().iter('testcase'):
   fail=case.find('failure');cs.append({'class':case.get('classname'),'name':case.get('name'),'failed':fail is not None,'error':case.find('error')is not None,'skipped':case.find('skipped')is not None,'failure_message':fail.get('message','') if fail is not None else '', 'failure_type':fail.get('type','') if fail is not None else ''})
 r['cases']=cs;save();assert len(cs)==8 and len({(c['class'],c['name'])for c in cs})==8
 assert {(c['class'],c['name'])for c in cs}=={(klass,n) for n in set(expected)|controls}
 assert not any(c['error']or c['skipped']for c in cs)
 assert not any(c['failed'] for c in cs if c['name'] in controls)
 failures={c['name']for c in cs if c['failed']};assert failures in (set(),set(expected))
 for c in cs:
  if c['failed']:assert c['failure_type']=='java.lang.AssertionError' and expected[c['name']] in c['failure_message']
 evidence_text=(e/'characterization.log').read_text()
 for f in(e/'characterization-xml').glob('*.xml'):
  for out in ET.parse(f).getroot().iter('system-out'):evidence_text+=out.text or ''
 fixtures=[(2,'((INT)0x8000)',-32768,32768),(4,'((INT)0x80000000)',-2147483648,2147483648),(2,'((int)0xffff)',-1,65535),(4,'((int)0xffffffff)',-1,4294967295),(2,'((unsigned int)0x8000)',32768,32768),(4,'((unsigned int)0x80000000)',2147483648,2147483648),(4,'0x80000000',2147483648,2147483648),(4,'((int)127)',127,127)]
 for size,expression,value,old in fixtures:
  actual=old if failures else value
  assert f'MACRO_CAST intSize={size} expression={expression} expected={value} actual={actual} width=' in evidence_text
 assert not subprocess.check_output(['git','diff','--name-only'],text=True).strip()
 r['status']='REPRODUCED_C_MACRO_CAST_SIGN' if failures else 'NOT_REPRODUCED';r['observed_failures']=len(failures);r['passing_controls']=4
except Exception as ex:
 import traceback
 r['status']='INCONCLUSIVE';r['error']=str(ex);r['traceback']=traceback.format_exc();raise
finally:save()
