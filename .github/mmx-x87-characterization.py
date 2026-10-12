import pathlib,subprocess,json,xml.etree.ElementTree as ET,shutil,os,hashlib
p=pathlib.Path.cwd();e=p/'native-evidence';e.mkdir(exist_ok=True);head=os.environ['HEAD_SHA'];base=os.environ['BASE_SHA'];r={'head':head,'base':base,'status':'running','publication_gate':False,'production_unchanged':True,'full_build_passed':False,'steps':[]}
klass='ghidra.app.emulator.MmxX87SaveCharacterizationTest'
expected={'testPxorFirstRegister': 'expected:<65535> but was:<4660>', 'testPxorLastRegister': 'expected:<65535> but was:<4667>', 'testMovdRegisterTransfer': 'expected:<65535> but was:<4662>', 'testPackedByteArithmetic': 'expected:<65535> but was:<4664>', 'testReversedMovqDestination': 'expected:<65535> but was:<4666>'}
controls={'testMovqMemoryReadControl', 'testEmmsControl'}

def save():(e/'receipt.json').write_text(json.dumps(r,indent=2))
def run(label,args):
 with(e/(label+'.log')).open('w') as out:x=subprocess.run(args,stdout=out,stderr=subprocess.STDOUT)
 r['steps'].append({'label':label,'exit_code':x.returncode,'args':args});save();return x.returncode
g=['./gradlew','--no-daemon','--max-workers=2','-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
try:
 assert subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()==head
 assert subprocess.check_output(['git','diff','--name-only',base,head],text=True).splitlines()==['Ghidra/Features/Base/src/test/java/ghidra/app/emulator/MmxX87SaveCharacterizationTest.java']
 assert run('fetch',g+['-I','gradle/support/fetchDependencies.gradle','-DhideDownloadProgress','-DnoEclipse'])==0
 assert run('prep',g+['prepDev'])==0
 assert run('actual-x86-compile',g+[':x86:sleighCompile'])==0
 sla=p/'Ghidra/Processors/x86/data/languages/x86-64.sla';assert sla.is_file();r['actual_sla_sha256']=hashlib.sha256(sla.read_bytes()).hexdigest();save()
 result=p/'Ghidra/Features/Base/build/test-results/test';shutil.rmtree(result,ignore_errors=True)
 code=run('characterization',g+[':Base:test','--tests',klass]);assert code in (0,1)
 shutil.copytree(result,e/'characterization-xml');cs=[]
 for f in(e/'characterization-xml').glob('*.xml'):
  for case in ET.parse(f).getroot().iter('testcase'):
   fail=case.find('failure');cs.append({'class':case.get('classname'),'name':case.get('name'),'failed':fail is not None,'error':case.find('error')is not None,'skipped':case.find('skipped')is not None,'failure_message':fail.get('message','') if fail is not None else '', 'failure_type':fail.get('type','') if fail is not None else ''})
 r['cases']=cs;save();assert len(cs)==7 and len({(c['class'],c['name'])for c in cs})==7
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
 for marker in ['MMX_SAVE mnemonic=PXOR destination=0 expectedHigh=65535 actualHigh=4660 lowBits=true untouched=true', 'MMX_SAVE mnemonic=PXOR destination=7 expectedHigh=65535 actualHigh=4667 lowBits=true untouched=true', 'MMX_SAVE mnemonic=MOVD destination=2 expectedHigh=65535 actualHigh=4662 lowBits=true untouched=true', 'MMX_SAVE mnemonic=PADDB destination=4 expectedHigh=65535 actualHigh=4664 lowBits=true untouched=true', 'MMX_SAVE mnemonic=MOVQ destination=6 expectedHigh=65535 actualHigh=4666 lowBits=true untouched=true', 'MMX_SAVE mnemonic=MOVQ destination=-1 highBits=unchanged lowBits=true untouched=true', 'MMX_SAVE mnemonic=EMMS destination=-1 highBits=unchanged lowBits=true untouched=true']:assert marker in evidence_text
 for mnemonic in ['PXOR','MOVD','PADDB','MOVQ','EMMS']:assert 'MMX_CURRENT_SLA mnemonic='+mnemonic+' path=' in evidence_text
 assert not subprocess.check_output(['git','diff','--name-only'],text=True).strip()
 r['status']='REPRODUCED_MMX_X87_HIGH_BITS_OMISSION';r['observed_failures']=5;r['passing_controls']=2
except Exception as ex:
 import traceback
 r['status']='INCONCLUSIVE';r['error']=str(ex);r['traceback']=traceback.format_exc();raise
finally:save()
