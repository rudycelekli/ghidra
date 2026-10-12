import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.analyzers.FunctionStartAnalyzer;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.util.DefaultLanguageService;
import java.math.BigInteger;
import java.util.*;

/** Fork-only discovery: real decoder/context and actual public analyzer-created functions. */
public class PowerPcVleFunctionStartCharacterization extends HeadlessScript {
    @Override public void run() throws Exception {
        int missing = 0;
        for (String name : List.of("direct-stack", "padded-stack", "direct-lr-stack", "padded-lr-stack",
                "standard-control", "disabled-vle-control", "existing-control", "padding-only-control",
                "mixed-mode-control", "nonexecutable-control", "defined-data-control")) {
            boolean standard = name.equals("standard-control") || name.equals("nonexecutable-control") ||
                name.equals("defined-data-control");
            boolean enabled = !standard && !name.equals("disabled-vle-control");
            boolean padding = name.startsWith("padded") || name.equals("padding-only-control");
            boolean lr = name.contains("lr-stack");
            Language language = DefaultLanguageService.getLanguageService().getLanguage(
                new LanguageID("PowerPC:BE:64:VLE-32addr"));
            ProgramDB p = new ProgramDB("VLE-native-" + name, language, language.getDefaultCompilerSpec(), this);
            int tx = -1;
            try {
                tx = p.startTransaction("Actual VLE function discovery producer");
                Address start = p.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                FlatProgramAPI api = new FlatProgramAPI(p, monitor);
                MemoryBlock block = p.getMemory().createInitializedBlock(".text", start, 0x100, (byte) 0, monitor, false);
                block.setExecute(!name.equals("nonexecutable-control"));
                if (name.equals("nonexecutable-control")) {
                    p.getMemory().createInitializedBlock(".otherText", start.add(0x1000), 0x10, (byte) 0, monitor, false).setExecute(true);
                }
                Register vle = p.getProgramContext().getRegister("vle");
                if (vle == null) { throw new AssertionError("Actual VLE context register missing"); }
                p.getProgramContext().setValue(vle, start, start.add(0xff), enabled ? BigInteger.ONE : BigInteger.ZERO);
                String hex = standard ? "4e8000209421fff07c0802a6382100104e800020" :
                    "0004" + (padding ? "4444" : "") + (lr ? "0080" : "") +
                    (name.equals("padding-only-control") ? "4444" : "182106f0") + "0004";
                byte[] bytes = HexFormat.of().parseHex(hex);
                p.getMemory().setBytes(start, bytes);
                Address target = start.add(standard ? 4 : padding ? 4 : 2);
                if (name.equals("defined-data-control")) {
                    api.disassemble(start);
                    api.createData(target, new ArrayDataType(ByteDataType.dataType, bytes.length - 4, 1));
                    if (p.getListing().getDefinedDataAt(target) == null) {
                        throw new AssertionError("Actual defined-data guard input missing");
                    }
                }
                else if (enabled || standard) {
                    if (!api.disassemble(start) || !api.disassemble(target)) {
                        throw new AssertionError("Real producer instructions did not decode: " + name);
                    }
                    String predecessor = p.getListing().getInstructionAt(start).getMnemonicString();
                    if (!predecessor.equalsIgnoreCase(standard ? "blr" : "se_blr")) {
                        throw new AssertionError("Actual previous return differs: " + predecessor);
                    }
                    if (padding) {
                        Instruction pad = p.getListing().getInstructionAt(start.add(2));
                        if (pad == null) { api.disassemble(start.add(2)); pad = p.getListing().getInstructionAt(start.add(2)); }
                        if (pad == null || !pad.getMnemonicString().equals("se_or") || pad.getLength() != 2 ||
                            pad.getRegister(0) == null || !pad.getRegister(0).getName().equals("r4") ||
                            pad.getRegister(1) == null || !pad.getRegister(1).getName().equals("r4")) {
                            throw new AssertionError("Actual reported alignment OR did not decode");
                        }
                    }
                    Instruction first = p.getListing().getInstructionAt(target);
                    String expected = standard ? "stwu" : lr ? "se_mflr" :
                        name.equals("padding-only-control") ? "se_or" : "e_stwu";
                    if (first == null || !first.getMnemonicString().equalsIgnoreCase(expected)) {
                        throw new AssertionError("Actual target opcode differs: " + name);
                    }
                    if (standard || expected.equals("e_stwu")) { assertActualStackStore(first); }
                    if (lr) {
                        Instruction stack = p.getListing().getInstructionAt(target.add(2));
                        if (first.getLength() != 2 || stack == null || !stack.getMnemonicString().equals("e_stwu")) {
                            throw new AssertionError("Actual LR/store sequence differs");
                        }
                        if (first.getRegister(0) == null || !first.getRegister(0).getName().equals("r0")) {
                            throw new AssertionError("Actual LR destination is not r0");
                        }
                        assertActualStackStore(stack);
                    }
                }
                Address mixedStandard = start.add(0x84);
                if (name.equals("mixed-mode-control")) {
                    p.getProgramContext().setValue(vle, start.add(0x80), start.add(0xff), BigInteger.ZERO);
                    byte[] standardBytes = HexFormat.of().parseHex("4e8000209421fff07c0802a6382100104e800020");
                    p.getMemory().setBytes(start.add(0x80), standardBytes);
                    if (!api.disassemble(start.add(0x80)) || !api.disassemble(mixedStandard) ||
                        !p.getListing().getInstructionAt(mixedStandard).getMnemonicString().equals("stwu") ||
                        p.getFunctionManager().getFunctionAt(mixedStandard) != null) {
                        throw new AssertionError("Actual adjacent standard-mode producer differs");
                    }
                    assertActualStackStore(p.getListing().getInstructionAt(mixedStandard));
                }
                if (name.equals("existing-control")) { api.createFunction(target, "ExistingVleFunction"); }
                Instruction targetInstruction = p.getListing().getInstructionAt(target);
                println("VLE_NATIVE_INPUT name=" + name + " hex=" + hex + " execute=" + block.isExecute() +
                    " controlledVle=" + p.getProgramContext().getValue(vle, target, false) +
                    " targetMnemonic=" + (targetInstruction == null ? "NONE" : targetInstruction.getMnemonicString()) +
                    " targetLength=" + (targetInstruction == null ? 0 : targetInstruction.getLength()) +
                    " targetDefinedData=" + (p.getListing().getDefinedDataAt(target) != null));
                Function before = p.getFunctionManager().getFunctionAt(target);
                if ((before != null) != name.equals("existing-control")) {
                    throw new AssertionError("Actual initial function precondition differs");
                }
                p.flushEvents();
                // Construct the real manager after decoder setup, then call the actual public producer.
                AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(p);
                FunctionStartAnalyzer analyzer = new FunctionStartAnalyzer();
                if (!analyzer.canAnalyze(p)) { throw new AssertionError("Actual configured patterns unsupported"); }
                MessageLog log = new MessageLog();
                if (!analyzer.added(p, new AddressSet(start, start.add(name.equals("mixed-mode-control") ? 0xff : bytes.length - 1)), monitor, log)) {
                    throw new AssertionError("Actual public function-start analyzer failed: " + log);
                }
                manager.startAnalysis(monitor);
                p.flushEvents();
                Function after = p.getFunctionManager().getFunctionAt(target);
                if (after != null && (!after.getEntryPoint().equals(target) ||
                    !after.getBody().contains(start.add(bytes.length - (standard ? 4 : 2))))) {
                    throw new AssertionError("Actual function entry/body excludes target return");
                }
                boolean candidate = name.endsWith("stack") || name.equals("mixed-mode-control");
                if (candidate && after == null) { missing++; }
                if (name.equals("standard-control") && after == null) { throw new AssertionError("Unchanged standard PPC control not created"); }
                if (name.equals("existing-control") && (after == null || after.getID() != before.getID())) {
                    throw new AssertionError("Existing real function not preserved");
                }
                if ((name.equals("disabled-vle-control") || name.equals("padding-only-control") || name.equals("nonexecutable-control") || name.equals("defined-data-control")) && after != null) {
                    throw new AssertionError("Actual negative control gained a function");
                }
                BigInteger actualMode = p.getProgramContext().getValue(vle, target, false);
                if (!actualMode.equals(enabled ? BigInteger.ONE : BigInteger.ZERO)) {
                    throw new AssertionError("Analyzer changed actual VLE mode");
                }
                if (name.equals("mixed-mode-control")) {
                    Function standardFunction = p.getFunctionManager().getFunctionAt(mixedStandard);
                    BigInteger standardMode = p.getProgramContext().getValue(vle, mixedStandard, false);
                    if (standardFunction == null || !standardMode.equals(BigInteger.ZERO) ||
                        !standardFunction.getBody().contains(start.add(0x90))) {
                        throw new AssertionError("Actual mixed-mode standard positive control differs");
                    }
                    println("VLE_NATIVE_MIXED standardTarget=" + mixedStandard + " vle=" + standardMode + " function=true");
                }
                println("VLE_NATIVE_CASE name=" + name + " target=" + target + " vle=" + actualMode +
                    " functionBefore=" + (before != null) + " functionAfter=" + (after != null) + " bodyAddresses=" + (after == null ? 0 : after.getBody().getNumAddresses()) + " messageLog=" + log);
            }
            finally {
                try { if (tx >= 0) { p.endTransaction(tx, false); } }
                finally { p.release(this); }
            }
        }
        println("VLE_NATIVE_OUTCOME cases=11 missingCandidates=" + missing +
            " outcome=" + (missing == 5 ? "REPRODUCED" : missing == 0 ? "NOT_REPRODUCED" : "PARTIAL"));
    }
    private void assertActualStackStore(Instruction instruction) {
        if (instruction.getLength() != 4 || instruction.getRegister(0) == null ||
            !instruction.getRegister(0).getName().equals("r1") ||
            !Arrays.stream(instruction.getOpObjects(1)).anyMatch(object ->
                object instanceof Register register && register.getName().equals("r1")) ||
            !Arrays.stream(instruction.getOpObjects(1)).anyMatch(object ->
                object instanceof Scalar scalar && scalar.getSignedValue() == -16)) {
            throw new AssertionError("Actual reported stack store operands/length differ");
        }
    }

}
