import classrecovery.*;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.util.opinion.PeLoader;
import ghidra.app.util.opinion.PeLoader.CompilerOpinion.CompilerEnum;
import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.rtti.*;
import ghidra.app.util.datatype.microsoft.*;
import ghidra.program.database.ProgramDB;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Fork-only native tests of real applied RTTI data through production recovery consumers. */
public class RttiEquivalentLayoutNativeTest extends HeadlessScript {
    private boolean baseline;
    private int passes, failures;
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1 || !(args[0].equals("baseline") || args[0].equals("fixed"))) {
            throw new IllegalArgumentException("Exact baseline/fixed phase required");
        }
        baseline = args[0].equals("baseline");
        for (String name : List.of("unique-x86", "unique-x64", "zero-arrays", "equivalent-x86",
                "equivalent-x64", "equivalent-no-vftable", "equivalent-raw-only-meta", "flags",
                "count", "order", "name", "contained", "mdisp", "pdisp", "vdisp", "attributes",
                "namespace", "orphan", "missing-bcd", "malformed-chd", "relative-reference-conflict", "record-reference-conflict-x86",
                "absolute-reference-conflict", "col-type-conflict", "missing-meta", "cancel")) {
            boolean x64 = !name.endsWith("x86") && !name.equals("zero-arrays");
            boolean unique = name.startsWith("unique");
            boolean zero = name.equals("zero-arrays");
            boolean positive = unique || zero || name.startsWith("equivalent");
            try (Fixture f = new Fixture(name, x64, unique, zero)) {
                f.mutate(name);
                if (positive) {
                    try {
                        f.assertProductionOutputs(zero);
                        passes++;
                        println("RTTI_RESOLVER_CASE phase=" + args[0] + " name=" + name + " outcome=PASS");
                    }
                    catch (IllegalArgumentException ex) {
                        if (!baseline || !name.startsWith("equivalent") ||
                            !ex.getMessage().startsWith("More than one Base Class Array for ")) {
                            throw ex;
                        }
                        boolean actualFrame = Arrays.stream(ex.getStackTrace()).anyMatch(frame ->
                            frame.getClassName().equals("classrecovery.RTTIWindowsClassRecoverer") &&
                            frame.getMethodName().equals("getClassHierarchyFromRTTI"));
                        if (!actualFrame) { throw ex; }
                        failures++;
                        println("RTTI_RESOLVER_CASE phase=baseline name=" + name +
                            " outcome=EXPECTED_REGRESSION_FAILURE type=java.lang.IllegalArgumentException message=" + ex.getMessage());
                    }
                }
                else {
                    try { f.call("getClassHierarchyFromRTTI", new Class<?>[]{RecoveredClass.class}, f.self); }
                    catch (IllegalArgumentException ex) {
                        if (name.equals("cancel")) { throw ex; }
                        if (baseline && !ex.getMessage().startsWith("More than one Base Class Array for ")) { throw ex; }
                        if (!baseline && !ex.getMessage().startsWith(expectedRejection(name))) { throw ex; }
                        if (!Arrays.stream(ex.getStackTrace()).anyMatch(frame ->
                            frame.getClassName().equals("classrecovery.RTTIWindowsClassRecoverer") &&
                            frame.getMethodName().equals(baseline ? "getClassHierarchyFromRTTI" : "resolveRttiHierarchy"))) { throw ex; }
                        passes++;
                        println("RTTI_RESOLVER_CASE phase=" + args[0] + " name=" + name +
                            " outcome=REJECTED_INVALID type=java.lang.IllegalArgumentException message=" + ex.getMessage());
                        continue;
                    }
                    catch (CancelledException ex) {
                        if (!name.equals("cancel")) { throw ex; }
                        passes++;
                        println("RTTI_RESOLVER_CASE phase=" + args[0] + " name=cancel outcome=CANCELLED");
                        continue;
                    }
                    throw new AssertionError("Production accepted invalid layout: " + name);
                }
            }
        }
        int expectedFailures = baseline ? 4 : 0;
        if (failures != expectedFailures || passes != 26 - expectedFailures) {
            throw new AssertionError("Incomplete native outcomes passes=" + passes + " failures=" + failures);
        }
        println("RTTI_RESOLVER_COMPLETE phase=" + args[0] + " cases=26 passes=" + passes + " failures=" + failures);
    }

    private String expectedRejection(String name) {
        return switch (name) {
            case "flags" -> "Conflicting RTTI inheritance flags at ";
            case "count" -> "Unassociated RTTI array or count at ";
            case "order" -> "RTTI self descriptor namespace differs at ";
            case "name", "contained", "mdisp", "pdisp", "vdisp", "attributes", "namespace" ->
                "Conflicting RTTI base class layout at ";
            case "orphan" -> "Orphan RTTI base class array for NativeSelf";
            case "missing-bcd" -> "Missing encoded RTTI reference at ";
            case "malformed-chd" -> "Missing applied RTTIClassHierarchyDescriptor at ";
            case "relative-reference-conflict", "record-reference-conflict-x86" ->
                "Missing, ambiguous or conflicting RTTI reference at ";
            case "absolute-reference-conflict" -> "Ambiguous or conflicting RTTI absolute reference at ";
            case "col-type-conflict" -> "Conflicting RTTI locator type at ";
            case "missing-meta" -> "Missing encoded RTTI absolute pointer at ";
            default -> throw new AssertionError("No intended rejection for " + name);
        };
    }

    private class Fixture implements AutoCloseable {
        final ProgramDB p;
        final FlatProgramAPI api;
        RTTIWindowsClassRecoverer recoverer;
        final TaskMonitorAdapter taskMonitor = new TaskMonitorAdapter(true);
        final Namespace selfNamespace, baseNamespace;
        final RecoveredClass self, parent;
        final int tx;
        final boolean x64;
        Fixture(String name, boolean x64, boolean unique, boolean zero) throws Exception {
            this.x64 = x64;
            Language language = DefaultLanguageService.getLanguageService().getLanguage(
                new LanguageID(x64 ? "x86:LE:64:default" : "x86:LE:32:default"));
            p = new ProgramDB("RTTI-native-" + name, language, language.getCompilerSpecByID(new CompilerSpecID("windows")), this);
            tx = p.startTransaction("Real RTTI fixture and recovery");
            try {
            p.setExecutableFormat(PeLoader.PE_NAME);
            p.setCompiler(CompilerEnum.VisualStudio.toString());
            p.setImageBase(address(0), true);
            p.getMemory().createInitializedBlock(".data", address(0), 0x10000, (byte) 0, monitor, false);
            api = new FlatProgramAPI(p, taskMonitor);
            SymbolTable symbols = p.getSymbolTable();
            selfNamespace = symbols.createClass(p.getGlobalNamespace(), "NativeSelf", SourceType.USER_DEFINED);
            baseNamespace = symbols.createClass(p.getGlobalNamespace(), "NativeBase", SourceType.USER_DEFINED);
            RttiUtil.createTypeInfoVftableSymbol(p, address(0x8000));
            type(0x3000, ".?AVNativeSelf@@"); type(0x3100, ".?AVNativeSelf@@");
            type(0x3200, ".?AVNativeBase@@"); type(0x3300, ".?AVNativeOther@@");
            if (!address(0x8000).equals(RttiUtil.findTypeInfoVftableAddress(p, monitor))) {
                throw new AssertionError("Actual Windows type_info vftable provenance missing");
            }
            bcd(0x4000, 0x3000, selfNamespace, 1, 0);
            bcd(0x4040, 0x3200, baseNamespace, 0, 16);
            bcd(0x4100, 0x3100, selfNamespace, 1, 0);
            bcd(0x4140, 0x3200, baseNamespace, 0, 16);
            if (!zero) {
                array(0x2000, 0x4000, 0x4040); chd(0x1000, 0x2000);
                if (!unique) { array(0x2100, 0x4100, 0x4140); chd(0x1100, 0x2100); }
            }
            if (!zero && !name.equals("equivalent-no-vftable")) {
                col(0x6000, 0x3000, 0x1000); meta(0x7000, 0x6000);
                if (!unique) {
                    col(0x6100, 0x3100, 0x1100); meta(0x7040, 0x6100);
                }
            }
            p.flushEvents();
            Namespace actualSelfNamespace = canonicalNamespace(0x4000, selfNamespace);
            Namespace actualBaseNamespace = canonicalNamespace(0x4040, baseNamespace);
            recoverer = new RTTIWindowsClassRecoverer(p, null, api, false, false, false, false, false, taskMonitor);
            self = recoverer.createNewClass(actualSelfNamespace, false);
            parent = recoverer.createNewClass(actualBaseNamespace, false);
            self.addParent(parent);
            if (!zero && !name.equals("equivalent-no-vftable")) {
                self.addVftableAddress(address(0x7000 + p.getDefaultPointerSize()));
                if (!unique) { self.addVftableAddress(address(0x7040 + p.getDefaultPointerSize())); }
            }
            assertCanonicalRegistration();
            }
            catch (Exception | Error failure) {
                close();
                throw failure;
            }
        }
        Namespace canonicalNamespace(long bcdOffset, Namespace created) {
            Symbol descriptor = p.getSymbolTable().getPrimarySymbol(address(bcdOffset));
            if (descriptor == null || !descriptor.getName().equals("RTTI_Base_Class_Descriptor")) {
                throw new AssertionError("Actual canonical BCD producer missing");
            }
            Namespace actual = descriptor.getParentNamespace();
            if (!(actual instanceof GhidraClass) || actual.getID() != created.getID() ||
                !actual.getName(true).equals(created.getName(true)) ||
                actual.getSymbol().getProgram() != p || created.getSymbol().getProgram() != p) {
                throw new AssertionError("Actual canonical BCD namespace provenance differs");
            }
            return actual;
        }
        void assertCanonicalRegistration() {
            if (recoverer.getClass(canonicalNamespace(0x4000, selfNamespace)) != self ||
                recoverer.getClass(canonicalNamespace(0x4040, baseNamespace)) != parent) {
                throw new AssertionError("Actual canonical recovered-class registration differs");
            }
        }
        Address address(long offset) { return p.getAddressFactory().getDefaultAddressSpace().getAddress(0x10000000L + offset); }
        void writeInt(long offset, int value) throws Exception { p.getMemory().setInt(address(offset), value); }
        void pointer(long offset, long target) throws Exception {
            writeInt(offset, (int) (x64 ? target : address(target).getOffset()));
        }
        void apply(long offset, DataType type) throws Exception { api.createData(address(offset), type); }
        void label(long offset, String name, Namespace namespace) throws Exception {
            p.getSymbolTable().createLabel(address(offset), name, namespace, SourceType.USER_DEFINED).setPrimary();
        }
        void type(long offset, String name) throws Exception {
            if (x64) { p.getMemory().setLong(address(offset), address(0x8000).getOffset()); }
            else { writeInt(offset, (int) address(0x8000).getOffset()); }
            p.getMemory().setBytes(address(offset + 2 * p.getDefaultPointerSize()), (name + "\0").getBytes(StandardCharsets.US_ASCII));
            TypeDescriptorModel model = new TypeDescriptorModel(p, address(offset), new DataValidationOptions());
            model.validate();
            String actual = model.getTypeName();
            if (!name.equals(actual)) { throw new AssertionError("Native TypeDescriptor validation did not preserve original name"); }
        }
        void bcd(long offset, long type, Namespace namespace, int contained, int mdisp) throws Exception {
            pointer(offset, type); writeInt(offset + 4, contained); writeInt(offset + 8, mdisp);
            writeInt(offset + 12, -1); writeInt(offset + 16, 0); writeInt(offset + 20, 64);
            pointer(offset + 24, 0x1000);
            apply(offset, Rtti1Model.getDataType(p));
            label(offset, "RTTI_Base_Class_Descriptor", namespace);
        }
        void array(long offset, long first, long second) throws Exception {
            pointer(offset, first); pointer(offset + 4, second);
            apply(offset, new ArrayDataType(MSDataTypeUtils.getReferenceDataType(p, null), 2, 4));
            label(offset, "RTTI_Base_Class_Array", selfNamespace);
        }
        void chd(long offset, long array) throws Exception {
            writeInt(offset + 4, 0); writeInt(offset + 8, 2); pointer(offset + 12, array);
            apply(offset, Rtti3Model.getDataType(p));
            label(offset, "RTTI_Class_Hierarchy_Descriptor", selfNamespace);
        }
        void col(long offset, long type, long chd) throws Exception {
            writeInt(offset, x64 ? 1 : 0); pointer(offset + 12, type); pointer(offset + 16, chd);
            if (x64) { pointer(offset + 20, offset); }
            apply(offset, Rtti4Model.getDataType(p));
            label(offset, "RTTI_Complete_Object_Locator", selfNamespace);
        }
        void meta(long offset, long col) throws Exception {
            if (x64) { p.getMemory().setLong(address(offset), address(col).getOffset()); }
            else { writeInt(offset, (int) address(col).getOffset()); }
            apply(offset, new PointerDataType(p.getDataTypeManager()));
        }
        void badReference(long offset, long target) {
            p.getReferenceManager().removeAllReferencesFrom(address(offset));
            p.getReferenceManager().addMemoryReference(address(offset), address(target), RefType.DATA, SourceType.USER_DEFINED, 0);
            Address encoded = offset == 0x7040 ? MSDataTypeUtils.getAbsoluteAddress(p, address(offset)) : MSDataTypeUtils.getReferencedAddress(p, address(offset));
            Reference[] refs = p.getReferenceManager().getReferencesFrom(address(offset));
            if (refs.length != 1 || refs[0].getToAddress().equals(encoded)) { throw new AssertionError("Actual raw/reference mismatch producer failed"); }
            println("RTTI_REFERENCE_MISMATCH field=" + address(offset) + " raw=" + encoded + " reference=" + refs[0].getToAddress());
        }
        void mutate(String name) throws Exception {
            switch (name) {
                case "flags": writeInt(0x1104, 1); break;
                case "count": writeInt(0x1108, 1); break;
                case "order": pointer(0x2100, 0x4140); pointer(0x2104, 0x4100); break;
                case "name": pointer(0x4100, 0x3300); break;
                case "contained": writeInt(0x4104, 0); break;
                case "mdisp": writeInt(0x4148, 32); break;
                case "pdisp": writeInt(0x414c, 4); break;
                case "vdisp": writeInt(0x4150, 4); break;
                case "attributes": writeInt(0x4154, 0); break;
                case "namespace":
                    Namespace other = p.getSymbolTable().createClass(p.getGlobalNamespace(), "OtherNamespace", SourceType.USER_DEFINED);
                    p.getSymbolTable().getPrimarySymbol(address(0x4140)).setNamespace(other); break;
                case "orphan": p.getSymbolTable().getPrimarySymbol(address(0x1100)).delete(); break;
                case "missing-bcd": pointer(0x2104, 0x20000); break;
                case "malformed-chd": p.getListing().clearCodeUnits(address(0x1100), address(0x110f), false); break;
                case "relative-reference-conflict":
                case "record-reference-conflict-x86": badReference(0x110c, 0x2000); break;
                case "absolute-reference-conflict": badReference(0x7040, 0x6000); break;
                case "col-type-conflict": pointer(0x610c, 0x3200); break;
                case "missing-meta": if (x64) { p.getMemory().setLong(address(0x7040), 0); } else { writeInt(0x7040, 0); } break;
                case "equivalent-raw-only-meta":
                    p.getReferenceManager().removeAllReferencesFrom(address(0x7040));
                    if (p.getReferenceManager().getReferencesFrom(address(0x7040)).length != 0) { throw new AssertionError("Actual raw-only absolute pointer producer failed"); }
                    break;
                case "cancel": taskMonitor.cancel(); break;
                default: break;
            }
            p.flushEvents();
        }
        Object call(String name, Class<?>[] types, Object... args) throws Exception {
            Method method = RTTIWindowsClassRecoverer.class.getDeclaredMethod(name, types);
            method.setAccessible(true);
            try { return method.invoke(recoverer, args); }
            catch (InvocationTargetException ex) {
                Throwable cause = ex.getCause();
                if (cause instanceof Exception exception) { throw exception; }
                if (cause instanceof Error error) { throw error; }
                throw ex;
            }
        }
        @SuppressWarnings("unchecked") void assertProductionOutputs(boolean zero) throws Exception {
            assertCanonicalRegistration();
            List<RecoveredClass> hierarchy = (List<RecoveredClass>) call("getClassHierarchyFromRTTI", new Class<?>[]{RecoveredClass.class}, self);
            Data array = (Data) call("getBaseClassArray", new Class<?>[]{RecoveredClass.class}, self);
            int flags;
            try { flags = (int) call("getClassInheritanceFlag", new Class<?>[]{RecoveredClass.class}, self); }
            catch (NoSuchMethodException oldSignature) { flags = (int) call("getClassInheritanceFlag", new Class<?>[]{Namespace.class}, selfNamespace); }
            println("RTTI_PRODUCTION_DIAGNOSTIC hierarchySize=" + hierarchy.size() +
                " selfIdentity=" + (!hierarchy.isEmpty() && hierarchy.get(0) == self) +
                " parentIdentity=" + (hierarchy.size() > 1 && hierarchy.get(1) == parent) +
                " array=" + (array == null ? "null" : array.getAddress()) +
                " components=" + (array == null ? -1 : array.getNumComponents()) + " flags=" + flags);
            for (int i = 0; i < hierarchy.size(); i++) {
                println("RTTI_PRODUCTION_DIAGNOSTIC index=" + i + " namespace=" + hierarchy.get(i).getClassNamespace().getName(true));
            }
            for (long offset : new long[]{0x1000, 0x2000, 0x2004, 0x4000, 0x4040}) {
                Symbol symbol = p.getSymbolTable().getPrimarySymbol(address(offset));
                println("RTTI_PRODUCTION_DIAGNOSTIC address=" + address(offset) + " symbol=" +
                    (symbol == null ? "null" : symbol.getName(true)) + " refs=" +
                    java.util.Arrays.toString(p.getReferenceManager().getReferencesFrom(address(offset))));
            }
            if (zero) {
                if (!hierarchy.isEmpty() || array != null || flags != -1) { throw new AssertionError("Zero-array legacy outputs changed"); }
                return;
            }
            if (hierarchy.size() != 2 || hierarchy.get(0) != self || hierarchy.get(1) != parent ||
                array == null || !array.getAddress().equals(address(0x2000)) || flags != 0) {
                throw new AssertionError("Actual hierarchy/array/inheritance output differs");
            }
            call("determineParentClassInfoFromBaseClassArray", new Class<?>[]{List.class}, List.of(self));
            if (!Boolean.FALSE.equals(self.getParentToBaseTypeMap().get(parent))) { throw new AssertionError("Actual nonvirtual parent output differs"); }
            Map<RecoveredClass, Integer> offsets = (Map<RecoveredClass, Integer>) call("getBaseClassOffsetMap", new Class<?>[]{RecoveredClass.class}, self);
            if (!Integer.valueOf(16).equals(offsets.get(parent))) { throw new AssertionError("Actual parent offset output differs"); }
            println("RTTI_PRODUCTION_OUTPUT hierarchy=NativeSelf,NativeBase parentOffset=16 flags=0 array=" + array.getAddress());
        }
        @Override public void close() {
            try {
                if (recoverer != null) {
                    recoverer.getDecompilerUtils().getDecompilerInterface().dispose();
                }
            }
            finally {
                try { p.endTransaction(tx, false); }
                finally { p.release(this); }
            }
        }
    }
}
