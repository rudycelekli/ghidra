import pathlib,subprocess,json,os,xml.etree.ElementTree as ET,shutil,traceback,hashlib
p=pathlib.Path.cwd();e=p/'native-evidence';e.mkdir();head=os.environ['HEAD_SHA'];cls='ghidra.features.codecompare.decompile.ExternalCalleeNameCharacterizationTest';r={'head':head,'base':'918d44ebc2962a53d23eeee52b8f44c7816e7815','status':'running','purpose':'Actual external callee naming investigation only, not publication qualification','steps':[]}
def save():(e/'receipt.json').write_text(json.dumps(r,indent=2))
def run(label,args):
 with(e/(label+'.log')).open('w')as f:x=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT)
 r['steps'].append({'label':label,'args':args,'exit_code':x.returncode});save();print(label,x.returncode,flush=True)
 if x.returncode:print((e/(label+'.log')).read_text()[-5000:],flush=True)
 return x.returncode
g=['./gradlew','--no-daemon','--max-workers=2','-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
try:
 assert subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()==head
 paths=subprocess.check_output(['git','diff','--name-only',r['base'],head],text=True).splitlines()
 assert paths==['Ghidra/Features/CodeCompare/src/test/java/ghidra/features/codecompare/decompile/ExternalCalleeNameCharacterizationTest.java']
 assert run('fetch',g+['-I','gradle/support/fetchDependencies.gradle','-DhideDownloadProgress','-DnoEclipse'])==0
 assert run('prep',g+['prepDev'])==0
 assert run('native-decompiler-and-x86',g+[':Decompiler:buildNatives',':x86:sleighCompile'])==0
 assert (p/'Ghidra/Features/Decompiler/build/os/linux_x86_64/decompile').is_file(), 'No actual native decompiler executable'
 r['native_executable_sha256']=hashlib.sha256((p/'Ghidra/Features/Decompiler/build/os/linux_x86_64/decompile').read_bytes()).hexdigest();save()
 results=p/'Ghidra/Features/CodeCompare/build/test-results/test';shutil.rmtree(results,ignore_errors=True)
 rc=run('native-gui',['xvfb-run','-a','-s','-screen 0 1600x1200x24']+g+[':CodeCompare:test','--tests',cls]);shutil.copytree(results,e/'native-gui-xml')
 cs=[{'class':c.get('classname'),'name':c.get('name'),'failed':c.find('failure')is not None,'error':c.find('error')is not None,'skipped':c.find('skipped')is not None} for f in (e/'native-gui-xml').glob('*.xml')for c in ET.parse(f).getroot().iter('testcase')]
 r['native_gui']={'exit_code':rc,'cases':cs};save()
 names={'testExternalCalleeNameCanBeTransferred','testInternalCalleeNameControl'}
 assert len(cs)==2 and {(c['class'],c['name'])for c in cs}=={(cls,n)for n in names}
 assert rc in(0,1)and not any(c['error']or c['skipped']for c in cs)
 assert not any(c['failed']for c in cs if c['name']=='testInternalCalleeNameControl')
 log=(e/'native-gui.log').read_text()+'\n'+'\n'.join(n.text or '' for f in (e/'native-gui-xml').glob('*.xml') for n in ET.parse(f).getroot().iter('system-out'))
 assert all('CALLEE_CURRENT_NATIVE external='+label+' path=' in log for label in ['true','false']), 'Current built executable not proven consumed in both tests'
 assert 'ACTUAL_CALLEE_NAME external=false matched=true warning=false result=imported_name' in log, 'Internal caller control preconditions not reached'
 failures=[c['name']for c in cs if c['failed']]
 assert failures in ([],['testExternalCalleeNameCanBeTransferred'])
 if failures:
  assert 'ACTUAL_CALLEE_NAME external=true matched=true warning=true result=unknown_name' in log, 'Actual external caller/action rejection not proven'
  nodes=[n for f in (e/'native-gui-xml').glob('*.xml')for n in ET.parse(f).iter('failure')]
  assert len(nodes)==1 and nodes[0].get('type')=='org.junit.ComparisonFailure'
  assert nodes[0].get('message')=='expected:<[imported]_name> but was:<[unknown]_name>', 'Failure differs from intended name-transfer oracle'
 else:
  assert 'ACTUAL_CALLEE_NAME external=true matched=true warning=false result=imported_name' in log
 r['observation']={'failed_external_name_after_actual_native_matched_call':failures,'controls_passed':True,'result':'REPRODUCED' if failures else 'NOT_REPRODUCED'}
 assert not subprocess.check_output(['git','diff','--name-only'],text=True).strip()
 r['full_build_passed']=False;r['publication_gate']=False;r['status']='investigation_completed'
except Exception as ex:
 r['status']='inconclusive';r['error']=str(ex);r['traceback']=traceback.format_exc();raise
finally:save()
