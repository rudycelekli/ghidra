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
        try { script.execute(new GhidraState(state), getControls()); }
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
}
