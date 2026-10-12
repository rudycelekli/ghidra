import hashlib,json,os,pathlib,re,shutil,subprocess,traceback
import xml.etree.ElementTree as ET
p=pathlib.Path.cwd();e=p/'native-evidence';e.mkdir();head=os.environ['HEAD_SHA'];base=os.environ['BASE_SHA']
package='ghidra.feature.vt.gui.provider.functionassociation.';new=package+'VTFunctionRenameCharacterizationTest';original=package+'VTFunctionAssociationTest'
root='Ghidra/Features/VersionTracking/src/';production=[root+'main/java/'+package.replace('.','/')+name+'.java' for name in ['VTFunctionAssociationProvider','VTFunctionAssociationTableModel']]
fixture=root+'test.slow/java/'+new.replace('.','/')+'.java';oldtest=root+'test.slow/java/'+original.replace('.','/')+'.java'
r={'head':head,'base':base,'status':'INCONCLUSIVE','steps':[],'full_build_passed':False,'publication_gate':False}
def sha(b):return hashlib.sha256(b).hexdigest()
def git(*a):return subprocess.check_output(['git',*a])
def save():(e/'receipt.json').write_text(json.dumps(r,indent=2)+'\n')
def run(label,args):
 with (e/(label+'.log')).open('w') as f:x=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT,timeout=5400)
 r['steps'].append({'label':label,'args':args,'exit_code':x.returncode});save();print(label,x.returncode,flush=True);return x.returncode
def names(path):return set(re.findall(r'@Test\s+public void (\w+)\(',path.read_text()))
try:
 assert base=='918d44ebc2962a53d23eeee52b8f44c7816e7815' and git('rev-parse','HEAD').decode().strip()==head
 assert set(git('diff','--name-only',base,head).decode().splitlines())==set(production+[fixture])
 assert (p/oldtest).read_bytes()==git('show',base+':'+oldtest)
 expected=names(p/fixture);oldnames=names(p/oldtest);assert len(expected)==12 and len(oldnames)==9
 r['new_test_names']=sorted(expected);r['original_test_names']=sorted(oldnames);r['original_test_sha256']=sha((p/oldtest).read_bytes());r['fixture_sha256']=sha((p/fixture).read_bytes())
 fixed={path:(p/path).read_bytes() for path in production};baseline={path:git('show',base+':'+path) for path in production};r['fixed_production_sha256']={path:sha(b) for path,b in fixed.items()};r['base_production_sha256']={path:sha(b) for path,b in baseline.items()};save()
 g=['./gradlew','--no-daemon','--max-workers=2','-Dorg.gradle.jvmargs=-Xmx3g -XX:+UseCompactObjectHeaders']
 assert run('fetch',g+['-I','gradle/support/fetchDependencies.gradle','-DhideDownloadProgress','-DnoEclipse'])==0
 assert run('prep',g+['prepDev'])==0
 assert run('actual-native-and-languages',g+[':Decompiler:buildNatives',':x86:sleighCompile',':Toy:sleighCompile'])==0
 native=p/'Ghidra/Features/Decompiler/build/os/linux_x86_64/decompile';assert native.is_file();r['native_executable_sha256']=sha(native.read_bytes());save()
 results=p/'Ghidra/Features/VersionTracking/build/test-results/integrationTest';outcomes={};markers={}
 for phase,byteset in [('baseline',baseline),('fixed',fixed)]:
  for path,b in byteset.items():(p/path).write_bytes(b)
  shutil.rmtree(results,ignore_errors=True)
  code=run(phase,['xvfb-run','-a','-s','-screen 0 1600x1200x24']+g+[':VersionTracking:integrationTest','--tests',new,'--tests',original]);assert code in (0,1)
  dest=e/(phase+'-xml');shutil.copytree(results,dest);cases={};stdout='';xml={}
  for file in dest.glob('*.xml'):
   rr=ET.parse(file).getroot();klass=rr.get('name');assert klass in [new,original] and rr.get('timestamp')
   xml[file.name]={'sha256':sha(file.read_bytes()),'timestamp':rr.get('timestamp'),'tests':rr.get('tests'),'errors':rr.get('errors'),'skipped':rr.get('skipped')}
   if klass==new:assert rr.get('errors')=='0' and rr.get('skipped')=='0';stdout+=rr.findtext('system-out','')
   for t in rr.findall('testcase'):
    identity=(t.get('classname'),t.get('name'));assert identity not in cases and identity[0]==klass
    children=[c for c in t if c.tag in ['failure','error','skipped']];assert len(children)<=1
    outcome={'kind':children[0].tag,'type':children[0].get('type'),'message':children[0].get('message')} if children else {'kind':'PASS'}
    cases[identity]=outcome
  assert set(cases)=={(new,n) for n in expected}|{(original,n) for n in oldnames}
  target_messages={'testSourceRenameUpdatesActiveFilter':'Active name filter must reflect the actual function name expected:<0> but was:<1>','testDestinationRenameUpdatesActiveFilter':'Active name filter must reflect the actual function name expected:<0> but was:<1>','testSourceRenameEntersActiveFilter':'Actual function rename must update active filter membership expected:<1> but was:<0>','testDestinationRenameEntersActiveFilter':'Actual function rename must update active filter membership expected:<1> but was:<0>'}
  for name in expected:
   outcome=cases[(new,name)]
   if phase=='baseline' and name in target_messages:assert outcome=={'kind':'failure','type':'java.lang.AssertionError','message':'java.lang.AssertionError: '+target_messages[name]}
   else:assert outcome=={'kind':'PASS'},(phase,name,outcome)
  actual=re.findall(r'^VT_RENAME_(?:FILTER|ACTION) .+$',stdout,re.MULTILINE);assert len(actual)==16 and len(set(actual))==16
  required=[]
  for side in ['source','destination']:
   for rename in [True,False]:
    rows=0 if rename and phase=='fixed' else 1;function='__vt_rename_'+side+('_updated' if rename else '_original')
    required.append(f'VT_RENAME_FILTER side={side} rename={str(rename).lower()} rows={rows} function={function} filter=__vt_rename_{side}_original visible=true')
   rows=0 if phase=='baseline' else 1;target='__vt_enter_'+side+'_target';required.append(f'VT_RENAME_ACTION side={side} action=enter rows={rows} function={target} filter={target} visible=true')
   for action,suffix in [('history-renamed','updated'),('undo','original'),('redo','updated')]:required.append(f'VT_RENAME_ACTION side={side} action={action} rows=1 function=__vt_history_{side}_{suffix} filter=__vt_history_{side} visible=true')
   name='__vt_label_control_'+side;required.append(f'VT_RENAME_ACTION side={side} action=unrelated-label rows=1 function={name} filter={name} visible=true')
   name='__vt_association_'+side;required.append(f'VT_RENAME_ACTION side={side} action=accepted-association rows=1 function={name}_updated filter={name} visible=true')
  assert set(actual)==set(required)
  outcomes[phase]=cases;markers[phase]=actual;r[phase]={'exit_code':code,'cases':[{'class':k[0],'name':k[1],**v} for k,v in sorted(cases.items())],'xml':xml,'actual_markers':actual};save()
 assert {k:v for k,v in outcomes['baseline'].items() if k[0]==original}=={k:v for k,v in outcomes['fixed'].items() if k[0]==original}
 assert (p/oldtest).read_bytes()==git('show',base+':'+oldtest)
 for path,b in fixed.items():assert (p/path).read_bytes()==b
 assert run('full-build',g+['buildGhidra'])==0
 assert 'BUILD SUCCESSFUL' in (e/'full-build.log').read_text()
 assert not git('diff','--name-only','HEAD').decode().strip()
 r['inherited_original_outcomes']=[{'name':n,**outcomes['fixed'][(original,n)]} for n in sorted(oldnames) if outcomes['fixed'][(original,n)]!={'kind':'PASS'}]
 r.update(status='PASSED_TARGETED_REGRESSIONS_ORIGINAL_OUTCOMES_UNCHANGED_FULL_BUILD',full_build_passed=True,publication_gate=True)
except Exception as ex:r.update(status='INCONCLUSIVE',error=str(ex),traceback=traceback.format_exc());raise
finally:
 if 'fixed' in globals():
  for path,b in fixed.items():(p/path).write_bytes(b)
 save()
