import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.symbol.*;
import java.util.*;

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
                    inventory(message.substring("More than one Base Class Array for ".length()));
                    println("RTTI_CHARACTERIZATION_OUTCOME=REPRODUCED");
                    return;
                }
            }
            println("RTTI_CHARACTERIZATION_OUTCOME=INCONCLUSIVE");
            throw exception;
        }
    }
    private Address rva(Address field) throws Exception {
        return currentProgram.getImageBase().addNoWrap(
            Integer.toUnsignedLong(currentProgram.getMemory().getInt(field)));
    }

    private void inventory(String className) throws Exception {
        SymbolTable table = currentProgram.getSymbolTable();
        Set<Namespace> namespaces = new LinkedHashSet<>();
        SymbolIterator all = table.getAllSymbols(false);
        while (all.hasNext()) {
            monitor.checkCancelled();
            Namespace namespace = all.next().getParentNamespace();
            if (namespace.getName(true).equals(className)) {
                namespaces.add(namespace);
            }
        }
        if (namespaces.size() != 1) {
            throw new IllegalStateException("Exact actual class namespace required: " + namespaces.size());
        }
        Namespace namespace = namespaces.iterator().next();
        int descriptors = 0;
        int arrays = 0;
        SymbolIterator symbols = table.getSymbols(namespace);
        while (symbols.hasNext()) {
            monitor.checkCancelled();
            Symbol symbol = symbols.next();
            String name = symbol.getName();
            Address address = symbol.getAddress();
            if (name.equals("RTTI_Class_Hierarchy_Descriptor")) {
                descriptors++;
                dumpDescriptor(address);
            }
            if (name.equals("RTTI_Base_Class_Array")) {
                arrays++;
                Data data = currentProgram.getListing().getDataAt(address);
                println("RTTI_INVENTORY_ARRAY address=" + address + " components=" +
                    (data == null ? -1 : data.getNumComponents()));
            }
            if (name.equals("RTTI_Complete_Object_Locator")) {
                println("RTTI_INVENTORY_COL address=" + address + " type=" + rva(address.add(12)) +
                    " chd=" + rva(address.add(16)));
            }
            if ((name.equals("vftable") || (name.length() > 1 && name.substring(1).startsWith("vftable")) ||
                    name.contains("vftable_for_") || name.contains("vftable{for")) &&
                    !name.contains("vftable_meta_ptr")) {
                Address pointer = address.subtract(8);
                Address col = address.getAddressSpace().getAddress(currentProgram.getMemory().getLong(pointer));
                println("RTTI_INVENTORY_VFTABLE name=" + name + " address=" + address +
                    " col=" + col + " chd=" + rva(col.add(16)));
            }
        }
        if (descriptors == 0 || arrays < 2) {
            throw new IllegalStateException("Actual duplicate RTTI descriptor inventory required");
        }
        println("RTTI_INVENTORY_COMPLETE class=" + className + " descriptors=" + descriptors +
            " arrays=" + arrays);
    }

    private void dumpDescriptor(Address descriptor) throws Exception {
        int flags = currentProgram.getMemory().getInt(descriptor.add(4));
        long count = Integer.toUnsignedLong(currentProgram.getMemory().getInt(descriptor.add(8)));
        Address array = rva(descriptor.add(12));
        Data data = currentProgram.getListing().getDataAt(array);
        if (data == null || !data.isArray() || data.getNumComponents() != count) {
            throw new IllegalStateException("Actual descriptor count/array mismatch at " + descriptor);
        }
        println("RTTI_INVENTORY_CHD address=" + descriptor + " flags=" + flags +
            " count=" + count + " array=" + array);
        for (int index = 0; index < data.getNumComponents(); index++) {
            monitor.checkCancelled();
            Address base = rva(data.getComponent(index).getAddress());
            Address type = rva(base);
            Symbol typeSymbol = currentProgram.getSymbolTable().getPrimarySymbol(type);
            String identity = typeSymbol == null ? "<missing>" : typeSymbol.getName(true);
            println("RTTI_INVENTORY_BCD chd=" + descriptor + " index=" + index +
                " address=" + base + " type=" + type + " identity=" + identity +
                " contained=" + Integer.toUnsignedLong(currentProgram.getMemory().getInt(base.add(4))) +
                " mdisp=" + currentProgram.getMemory().getInt(base.add(8)) +
                " pdisp=" + currentProgram.getMemory().getInt(base.add(12)) +
                " vdisp=" + currentProgram.getMemory().getInt(base.add(16)) +
                " attributes=" + Integer.toUnsignedLong(currentProgram.getMemory().getInt(base.add(20))));
        }
    }
}
