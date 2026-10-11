import pathlib,subprocess,json,os,xml.etree.ElementTree as ET,shutil,traceback,hashlib
p=pathlib.Path.cwd();e=p/'native-evidence';e.mkdir();head=os.environ['HEAD_SHA'];cls='ghidra.app.plugin.core.decompile.DecompilerEquateReconversionInvestigationTest';r={'head':head,'base':'918d44ebc2962a53d23eeee52b8f44c7816e7815','status':'running','purpose':'Decompiler listing equate reconversion investigation only, not publication qualification','steps':[]}
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
 assert paths==['Ghidra/Features/Decompiler/src/test.slow/java/ghidra/app/plugin/core/decompile/DecompilerEquateReconversionInvestigationTest.java']
 assert run('fetch',g+['-I','gradle/support/fetchDependencies.gradle','-DhideDownloadProgress','-DnoEclipse'])==0
 assert run('prep',g+['prepDev'])==0
 assert run('native-decompiler-and-x86',g+[':Decompiler:buildNatives',':x86:sleighCompile'])==0
 assert (p/'Ghidra/Features/Decompiler/build/os/linux_x86_64/decompile').is_file(), 'No actual native decompiler executable'
 r['native_executable_sha256']=hashlib.sha256((p/'Ghidra/Features/Decompiler/build/os/linux_x86_64/decompile').read_bytes()).hexdigest();save()
 results=p/'Ghidra/Features/Decompiler/build/test-results/integrationTest';shutil.rmtree(results,ignore_errors=True)
 rc=run('native-gui',['xvfb-run','-a','-s','-screen 0 1600x1200x24']+g+[':Decompiler:integrationTest','--tests',cls]);shutil.copytree(results,e/'native-gui-xml')
 cs=[{'class':c.get('classname'),'name':c.get('name'),'failed':c.find('failure')is not None,'error':c.find('error')is not None,'skipped':c.find('skipped')is not None} for f in (e/'native-gui-xml').glob('*.xml')for c in ET.parse(f).getroot().iter('testcase')]
 r['native_gui']={'exit_code':rc,'cases':cs};save()
 names={'testListingDecimalEquateKeepsUnsignedValue','testListingEquateCanBeConvertedAgain'}
 assert len(cs)==2 and {(c['class'],c['name'])for c in cs}=={(cls,n)for n in names}
 assert rc in(0,1)and not any(c['error']or c['skipped']for c in cs)
 assert not any(c['failed']for c in cs if c['name']=='testListingDecimalEquateKeepsUnsignedValue')
 log=(e/'native-gui.log').read_text()+'\n'+'\n'.join(n.text or '' for f in (e/'native-gui-xml').glob('*.xml') for n in ET.parse(f).getroot().iter('system-out'))
 markers=['EQUATE_LISTING_DECIMAL_READY test='+label+' value=2852126725 hash=0' for label in ['control','reconversion']]
 assert all('EQUATE_CURRENT_NATIVE_EXECUTABLE test='+label+' path=' in log for label in ['control','reconversion']), 'Built native executable was not proven consumed in both actual tests'
 assert all(m in log for m in markers), 'Actual action/listing-equate precondition did not pass independently in both tests; inconclusive'
 failures=[c['name']for c in cs if c['failed']];r['observation']={'failed_reconversion_after_decimal_listing_equate_precondition':failures,'controls_passed':True,'result':'REPRODUCED' if failures else 'NOT_REPRODUCED'}
 assert run('full-build',g+['buildGhidra'])==0
 assert not subprocess.check_output(['git','diff','--name-only'],text=True).strip()
 r['full_build_passed']=True;r['status']='investigation_completed'
except Exception as ex:
 r['status']='inconclusive';r['error']=str(ex);r['traceback']=traceback.format_exc();raise
finally:save()
