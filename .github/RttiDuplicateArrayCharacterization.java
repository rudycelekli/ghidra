import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.util.GhidraProgramUtilities;

/** Fork-only characterization of the public issue #9747 executable. */
public class RttiDuplicateArrayCharacterization extends HeadlessScript {
    @Override
    public void run() throws Exception {
        if (analysisTimeoutOccurred() || currentProgram == null || currentProgram.getDefaultPointerSize() != 8 ||
            !"Portable Executable (PE)".equals(currentProgram.getExecutableFormat()) ||
            !GhidraProgramUtilities.isAnalyzed(currentProgram)) {
            throw new IllegalStateException("Actual analyzed 64-bit PE import required");
        }
        println("RTTI_PUBLIC_PE_READY name=" + currentProgram.getName() +
            " format=" + currentProgram.getExecutableFormat() + " pointerSize=8 analyzed=true");
        try {
            runScript("RecoverClassesFromRTTIScript.java");
            println("RTTI_CHARACTERIZATION_OUTCOME=NOT_REPRODUCED");
        }
        catch (Exception exception) {
            for (Throwable cause = exception; cause != null; cause = cause.getCause()) {
                String message = cause.getMessage();
                if (cause instanceof IllegalArgumentException && message != null &&
                    message.startsWith("More than one Base Class Array for ")) {
                    boolean productionFrame = false;
                    for (StackTraceElement frame : cause.getStackTrace()) {
                        productionFrame |= frame.getClassName().equals("classrecovery.RTTIWindowsClassRecoverer") &&
                            frame.getMethodName().equals("getClassHierarchyFromRTTI");
                    }
                    if (!productionFrame) {
                        throw exception;
                    }
                    println("RTTI_CHARACTERIZATION_EXPECTED_EXCEPTION=" + message);
                    println("RTTI_CHARACTERIZATION_OUTCOME=REPRODUCED");
                    return;
                }
            }
            println("RTTI_CHARACTERIZATION_OUTCOME=INCONCLUSIVE");
            throw exception;
        }
    }
}
