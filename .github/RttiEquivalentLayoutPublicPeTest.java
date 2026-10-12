import classrecovery.*;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.script.*;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.program.model.data.Structure;
import ghidra.program.model.symbol.*;
import java.lang.reflect.*;
import java.util.*;

/** Fork-only complete public script execution and actual recovered class outputs. */
public class RttiEquivalentLayoutPublicPeTest extends HeadlessScript {
    @Override public void run() throws Exception {
        if (analysisTimeoutOccurred() || currentProgram == null ||
            currentProgram.getDefaultPointerSize() != 8 ||
            !"Portable Executable (PE)".equals(currentProgram.getExecutableFormat()) ||
            !GhidraProgramUtilities.isAnalyzed(currentProgram)) {
            throw new IllegalStateException("Actual analyzed public PE required");
        }
        String[] args = getScriptArgs();
        if (args.length != 1 || !(args[0].equals("baseline") || args[0].equals("fixed"))) {
            throw new IllegalArgumentException("Exact phase required");
        }
        String expectedName = "std::_Func_impl_no_alloc<ConfigValidation::<lambda_6>,bool,int>";
        var source = GhidraScriptUtil.findScriptByName("RecoverClassesFromRTTIScript.java");
        if (source == null) { throw new IllegalStateException("Original public script missing"); }
        GhidraScript script = GhidraScriptUtil.getProvider(source).getScriptInstance(source, errorWriter);
        // Observe the real original public script without replacing its recoverer or mutating maps.
        // This is map-only telemetry; the local recoveredClasses list is not reflected or claimed.
        Thread observer = new Thread(() -> {
            for (int sample=0; sample<20; sample++) {
                try { Thread.sleep(120000); }
                catch (InterruptedException ex) { Thread.currentThread().interrupt(); return; }
                observeRecoveryMap(script,args[0],sample);
            }
        }, "RTTI-public-map-observer");
        observer.setDaemon(true);
        observer.start();
        println("RTTI_PUBLIC_PE_PHASE phase="+args[0]+" event=ORIGINAL_SCRIPT_START");
        try {
            script.execute(new GhidraState(state), getControls());
            println("RTTI_PUBLIC_PE_PHASE phase="+args[0]+" event=ORIGINAL_SCRIPT_RETURN");
        }
        catch (Exception ex) {
            for (Throwable cause = ex; cause != null; cause = cause.getCause()) {
                if (args[0].equals("baseline") && cause instanceof IllegalArgumentException &&
                    cause.getMessage() != null && cause.getMessage().equals("More than one Base Class Array for " + expectedName) &&
                    Arrays.stream(cause.getStackTrace()).anyMatch(frame ->
                        frame.getClassName().equals("classrecovery.RTTIWindowsClassRecoverer") &&
                        frame.getMethodName().equals("getClassHierarchyFromRTTI"))) {
                    println("RTTI_PUBLIC_PE_OUTCOME phase=baseline outcome=EXPECTED_REGRESSION_FAILURE message=" + cause.getMessage());
                    return;
                }
            }
            throw ex;
        }
        finally {
            observer.interrupt();
            observer.join(1000);
        }
        if (!args[0].equals("fixed")) { throw new AssertionError("Unchanged baseline no longer reproduces"); }
        Field field = script.getClass().getDeclaredField("recoverClassesFromRTTI");
        field.setAccessible(true);
        RTTIWindowsClassRecoverer recoverer = (RTTIWindowsClassRecoverer) field.get(script);
        Set<Namespace> namespaces = new HashSet<>();
        SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(false);
        while (symbols.hasNext()) {
            monitor.checkCancelled();
            Namespace namespace = symbols.next().getParentNamespace();
            if (namespace.getName(true).equals(expectedName)) { namespaces.add(namespace); }
        }
        if (namespaces.size() != 1) { throw new AssertionError("Actual target namespace not unique"); }
        Namespace targetNamespace = namespaces.iterator().next();
        int arrays = 0, descriptors = 0;
        symbols = currentProgram.getSymbolTable().getAllSymbols(false);
        while (symbols.hasNext()) {
            monitor.checkCancelled();
            Symbol symbol = symbols.next();
            if (!symbol.getParentNamespace().equals(targetNamespace)) { continue; }
            if (symbol.getName().equals("RTTI_Base_Class_Array")) { arrays++; }
            if (symbol.getName().equals("RTTI_Class_Hierarchy_Descriptor")) { descriptors++; }
        }
        if (arrays != 107 || descriptors != 107) {
            throw new AssertionError("Actual original target RTTI provenance changed: arrays=" + arrays + " descriptors=" + descriptors);
        }
        RecoveredClass target = recoverer.getClass(namespaces.iterator().next());
        if (target == null || target.getClassHierarchy().size() != 2 ||
            target.getClassHierarchy().get(0) != target ||
            !target.getClassHierarchy().get(1).getClassNamespace().getName(true).equals("std::_Func_base<bool,int>")) {
            throw new AssertionError("Actual target class hierarchy not recovered");
        }
        RecoveredClass parent = target.getClassHierarchy().get(1);
        if (!Boolean.FALSE.equals(target.getParentToBaseTypeMap().get(parent))) {
            throw new AssertionError("Actual target parent relationship not recovered");
        }
        Method method = RTTIWindowsClassRecoverer.class.getDeclaredMethod("getBaseClassOffsetMap", RecoveredClass.class);
        method.setAccessible(true);
        @SuppressWarnings("unchecked") Map<RecoveredClass, Integer> offsets =
            (Map<RecoveredClass, Integer>) method.invoke(recoverer, target);
        if (!Integer.valueOf(0).equals(offsets.get(parent))) { throw new AssertionError("Actual parent offset not recovered"); }
        Structure structure = target.getComputedClassStructure();
        if (structure == null || structure.getLength() < currentProgram.getDefaultPointerSize()) {
            throw new AssertionError("Public script did not finish producing target class structure");
        }
        println("RTTI_PUBLIC_PE_OUTCOME phase=fixed outcome=COMPLETE_RECOVERY hierarchy=" + expectedName +
            ",std::_Func_base<bool,int> arrays=107 descriptors=107 parentOffset=0 virtual=false structureLength=" + structure.getLength());
    }
    private void observeRecoveryMap(GhidraScript script,String phase,int sample) {
        try {
            Field recovererField=script.getClass().getDeclaredField("recoverClassesFromRTTI");
            recovererField.setAccessible(true);
            Object recoverer=recovererField.get(script);
            if (recoverer==null) {
                println("RTTI_PUBLIC_PE_MAP phase="+phase+" sample="+sample+
                    " scope=MAP_ONLY status=NOT_INITIALIZED");
                return;
            }
            Field mapField=RecoveredClassHelper.class.getDeclaredField("namespaceToClassMap");
            mapField.setAccessible(true);
            Map<?,?> map=(Map<?,?>)mapField.get(recoverer);
            int declaredSize=map.size(),visited=0,maxVftables=0,maxHierarchy=0;
            long totalVftables=0;
            Set<Long> namespaceIds=new HashSet<>();
            Set<RecoveredClass> identities=Collections.newSetFromMap(new IdentityHashMap<>());
            for (Map.Entry<?,?> entry:map.entrySet()) {
                if (visited>=20000) { break; }
                visited++;
                Namespace namespace=(Namespace)entry.getKey();
                RecoveredClass recovered=(RecoveredClass)entry.getValue();
                namespaceIds.add(namespace.getID());identities.add(recovered);
                int tables=recovered.getVftableAddresses().size();
                maxVftables=Math.max(maxVftables,tables);totalVftables+=tables;
                maxHierarchy=Math.max(maxHierarchy,recovered.getClassHierarchy().size());
            }
            println("RTTI_PUBLIC_PE_MAP phase="+phase+" sample="+sample+
                " scope=MAP_ONLY status=OBSERVED declaredSize="+declaredSize+" visited="+visited+
                " uniqueNamespaceIds="+namespaceIds.size()+" uniqueRecoveredIdentities="+identities.size()+
                " maxVftableList="+maxVftables+" totalVftableEntries="+totalVftables+
                " maxHierarchy="+maxHierarchy+" complete="+(visited==declaredSize && map.size()==declaredSize));
        }
        catch (Exception ex) {
            // Concurrent reads may be unavailable; this is never a test or qualification outcome.
            println("RTTI_PUBLIC_PE_MAP phase="+phase+" sample="+sample+
                " scope=MAP_ONLY status=UNAVAILABLE type="+ex.getClass().getName());
        }
    }

}
