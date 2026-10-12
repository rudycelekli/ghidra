import hashlib, json, os, pathlib, re, shutil, subprocess, traceback
import xml.etree.ElementTree as ET
p=pathlib.Path.cwd(); e=p/'native-evidence'; e.mkdir()
head=os.environ['HEAD_SHA']; base=os.environ['BASE_SHA']
klass='ghidra.feature.vt.gui.provider.functionassociation.VTFunctionRenameCharacterizationTest'
fixture='Ghidra/Features/VersionTracking/src/test.slow/java/'+klass.replace('.','/')+'.java'
targets={'testSourceRenameUpdatesActiveFilter','testDestinationRenameUpdatesActiveFilter'}
controls={'testSourceUnchangedFilterControl','testDestinationUnchangedFilterControl'}
production_paths=['Ghidra/Features/VersionTracking/src/main/java/ghidra/feature/vt/gui/provider/functionassociation/VTFunctionAssociationProvider.java','Ghidra/Features/VersionTracking/src/main/java/ghidra/feature/vt/gui/provider/functionassociation/VTFunctionAssociationTableModel.java','Ghidra/Features/VersionTracking/src/main/java/ghidra/feature/vt/gui/plugin/VTControllerImpl.java','Ghidra/Framework/Docking/src/main/java/docking/widgets/table/GTableFilterPanel.java','Ghidra/Features/Base/src/main/java/ghidra/util/table/field/LabelTableColumn.java']
r={'head':head,'base':base,'status':'INCONCLUSIVE','steps':[],'production_unchanged':False,'publication_gate':False,'full_build_passed':False}
def sha(b):return hashlib.sha256(b).hexdigest()
def git(*a):return subprocess.check_output(['git',*a])
def save():(e/'receipt.json').write_text(json.dumps(r,indent=2)+'\n')
def run(label,args):
 with(e/(label+'.log')).open('w') as f:x=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT,timeout=3600)
 r['steps'].append({'label':label,'args':args,'exit_code':x.returncode});save();print(label,x.returncode,flush=True);return x.returncode
try:
 assert base=='918d44ebc2962a53d23eeee52b8f44c7816e7815'
 assert git('rev-parse','HEAD').decode().strip()==head
 assert git('diff','--name-only',base,head).decode().splitlines()==[fixture]
 hashes={}
 for path in production_paths:
  b=(p/path).read_bytes();assert b==git('show',base+':'+path);hashes[path]=sha(b)
 r['production_sha256']=hashes;r['fixture_sha256']=sha((p/fixture).read_bytes());r['production_unchanged']=True;save()
 g=['./gradlew','--no-daemon','--max-workers=2','-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
 assert run('fetch',g+['-I','gradle/support/fetchDependencies.gradle','-DhideDownloadProgress','-DnoEclipse'])==0
 assert run('prep',g+['prepDev'])==0
 assert run('actual-native-and-languages',g+[':Decompiler:buildNatives',':x86:sleighCompile',':Toy:sleighCompile'])==0
 native=p/'Ghidra/Features/Decompiler/build/os/linux_x86_64/decompile';assert native.is_file();r['native_executable_sha256']=sha(native.read_bytes());save()
 result=p/'Ghidra/Features/VersionTracking/build/test-results/integrationTest';shutil.rmtree(result,ignore_errors=True)
 code=run('characterization',['xvfb-run','-a','-s','-screen 0 1600x1200x24']+g+[':VersionTracking:integrationTest','--tests',klass]);assert code in (0,1)
 dest=e/'characterization-xml';shutil.copytree(result,dest);cases={};out='';xml_hashes={};stamps={}
 for f in dest.glob('*.xml'):
  root=ET.parse(f).getroot();assert root.get('name')==klass and root.get('errors')=='0' and root.get('skipped')=='0';stamps[f.name]=root.get('timestamp');assert stamps[f.name]
  xml_hashes[f.name]=sha(f.read_bytes());out+=root.findtext('system-out','')
  for t in root.iter('testcase'):
   assert t.get('classname')==klass and t.get('name') not in cases and t.find('error') is None and t.find('skipped') is None
   failure=t.find('failure');cases[t.get('name')]={'failed':failure is not None,'message':failure.get('message') if failure is not None else ''}
   if failure is not None:
    assert t.get('name') in targets and failure.get('type')=='java.lang.AssertionError'
    assert failure.get('message')=='java.lang.AssertionError: Active name filter must reflect the actual function name expected:<0> but was:<1>'
 assert set(cases)==targets|controls
 failed={name for name,c in cases.items() if c['failed']};assert failed in (set(),targets)
 lines=re.findall(r'^VT_RENAME_FILTER side=\S+ rename=\w+ rows=\d+ function=\S+ filter=\S+ visible=\w+$',out,re.MULTILINE);assert len(lines)==4 and len(set(lines))==4
 for side in ['source','destination']:
  for rename in [True,False]:
   rows=1 if not rename or failed else 0
   function='__vt_rename_'+side+('_updated' if rename else '_original')
   line=f'VT_RENAME_FILTER side={side} rename={str(rename).lower()} rows={rows} function={function} filter=__vt_rename_{side}_original visible=true';assert line in lines
 if not failed:assert code==0
 assert not git('diff','--name-only','HEAD').decode().strip()
 for path,h in hashes.items():assert sha((p/path).read_bytes())==h
 r.update(status='REPRODUCED_NATIVE_SOURCE_AND_DESTINATION_STALE_NAME_FILTER' if failed else 'NOT_REPRODUCED',cases=cases,failures=len(failed),exit_code=code,xml_sha256=xml_hashes,xml_timestamps=stamps,actual_markers=lines)
except Exception as ex:
 r.update(status='INCONCLUSIVE',error=str(ex),traceback=traceback.format_exc());raise
finally:save()
