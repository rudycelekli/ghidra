import pathlib,subprocess,json,os,xml.etree.ElementTree as ET,shutil,traceback,hashlib
p=pathlib.Path.cwd();e=p/'native-evidence';e.mkdir();head=os.environ['HEAD_SHA'];cls='ghidra.features.codecompare.decompile.ExternalCalleeMixedNameCharacterizationTest';r={'head':head,'base':'918d44ebc2962a53d23eeee52b8f44c7816e7815','status':'running','purpose':'Actual external callee naming investigation only, not publication qualification','steps':[]}
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
 assert paths==['Ghidra/Features/CodeCompare/src/main/java/ghidra/features/codecompare/decompile/AbstractMatchedCalleeTokensAction.java', 'Ghidra/Features/CodeCompare/src/main/java/ghidra/features/codecompare/decompile/ApplyCalleeFunctionNameFromMatchedTokensAction.java', 'Ghidra/Features/CodeCompare/src/test/java/ghidra/features/codecompare/decompile/ExternalCalleeMixedNameCharacterizationTest.java']
 assert run('fetch',g+['-I','gradle/support/fetchDependencies.gradle','-DhideDownloadProgress','-DnoEclipse'])==0
 assert run('prep',g+['prepDev'])==0
 assert run('native-decompiler-and-x86',g+[':Decompiler:buildNatives',':x86:sleighCompile'])==0
 assert (p/'Ghidra/Features/Decompiler/build/os/linux_x86_64/decompile').is_file(), 'No actual native decompiler executable'
 r['native_executable_sha256']=hashlib.sha256((p/'Ghidra/Features/Decompiler/build/os/linux_x86_64/decompile').read_bytes()).hexdigest();save()
 results=p/'Ghidra/Features/CodeCompare/build/test-results/test';shutil.rmtree(results,ignore_errors=True)
 rc=run('native-gui',['xvfb-run','-a','-s','-screen 0 1600x1200x24']+g+[':CodeCompare:test','--tests',cls]);shutil.copytree(results,e/'native-gui-xml')
 cs=[{'class':c.get('classname'),'name':c.get('name'),'failed':c.find('failure')is not None,'error':c.find('error')is not None,'skipped':c.find('skipped')is not None} for f in (e/'native-gui-xml').glob('*.xml')for c in ET.parse(f).getroot().iter('testcase')]
 r['native_gui']={'exit_code':rc,'cases':cs};save()
 names={'testExternalCalleeNameCanBeTransferred','testInternalCalleeNameControl','testExternalSourceInternalTargetNameCanBeTransferred','testInternalSourceExternalTargetNameCanBeTransferred','testCompareExternalCalleesRemainRejected'}
 assert len(cs)==5 and {(c['class'],c['name'])for c in cs}=={(cls,n)for n in names}
 assert rc in(0,1)and not any(c['error']or c['skipped']for c in cs)
 mixed={'testExternalSourceInternalTargetNameCanBeTransferred','testInternalSourceExternalTargetNameCanBeTransferred'}
 assert not any(c['failed']for c in cs if c['name'] not in mixed), 'Name opt-in or preserved Compare control failed'
 log=(e/'native-gui.log').read_text()+'\n'+'\n'.join(n.text or '' for f in (e/'native-gui-xml').glob('*.xml') for n in ET.parse(f).getroot().iter('system-out'))
 for source,target in [('true','true'),('false','false'),('true','false'),('false','true')]:
  assert 'CALLEE_CURRENT_NATIVE sourceExternal='+source+' targetExternal='+target+' path=' in log
  assert 'ACTUAL_CALLEE_NAME sourceExternal='+source+' targetExternal='+target+' compare=false matched=true warning=' in log
 assert 'ACTUAL_CALLEE_NAME sourceExternal=true targetExternal=true compare=true matched=true warning=true result=unknown_name namespace=' in log
 failures=[c['name']for c in cs if c['failed']]
 for f in (e/'native-gui-xml').glob('*.xml'):
  for c in ET.parse(f).getroot().iter('testcase'):
   n=c.find('failure')
   if n is not None:
    assert c.get('name') in mixed
    assert n.get('type')=='org.junit.ComparisonFailure'
    assert n.get('message')=='org.junit.ComparisonFailure: expected:<[imported]_name> but was:<[unknown]_name>'
 r['observation']={'mixed_name_failures':failures,'both_external_and_internal_controls_passed':True,'compare_external_rejection_preserved':True,'result':'MIXED_NAMESPACE_FAILURE_REPRODUCED' if failures else 'ALL_NAME_COMBINATIONS_PASSED'}
 assert not subprocess.check_output(['git','diff','--name-only'],text=True).strip()
 r['full_build_passed']=False;r['publication_gate']=False;r['status']='investigation_completed'
except Exception as ex:
 r['status']='inconclusive';r['error']=str(ex);r['traceback']=traceback.format_exc();raise
finally:save()
