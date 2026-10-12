/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.cmd.data.rtti;

import static org.junit.Assert.*;
import java.nio.charset.StandardCharsets;
import org.junit.Test;
import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.util.opinion.PeLoader.CompilerOpinion.CompilerEnum;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.app.util.opinion.PeLoader;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.util.task.TaskMonitor;

/** Discovery only: actual Windows label producers and public RTTI consumers. */
public class RttiTypeInfoLabelCharacterizationTest extends AbstractGhidraHeadlessIntegrationTest {
    private static class Fixture implements AutoCloseable {
        private final Object consumer = new Object();
        final ProgramDB program;
        final String caseName;
        int transaction = -1;
        final Address descriptor, vftable, alternative;
        Fixture(String caseName, String blockName) throws Exception {
            this.caseName = caseName;
            Language language = DefaultLanguageService.getLanguageService().getLanguage(
                new LanguageID("x86:LE:32:default"));
            program = new ProgramDB("Actual Windows RTTI label", language,
                language.getCompilerSpecByID(new CompilerSpecID("windows")), consumer);
            try {
                transaction = program.startTransaction("Public RTTI symbol producer");
                program.setExecutableFormat(PeLoader.PE_NAME);
                program.setCompiler(CompilerEnum.VisualStudio.toString());
                Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10000000);
                program.setImageBase(start, true);
                program.getMemory().createInitializedBlock(blockName, start, 0x1000, (byte)0,
                    TaskMonitor.DUMMY, false);
                descriptor = start.add(0x100); vftable = start.add(0x800); alternative = start.add(0x900);
                program.getMemory().setInt(descriptor, (int)vftable.getOffset());
                program.getMemory().setBytes(descriptor.add(8),
                    (".?AVActualNativeClass@@\0").getBytes(StandardCharsets.US_ASCII));
            }
            catch (Exception | Error ex) { close(); throw ex; }
        }
        Namespace typeInfo() throws Exception {
            Namespace namespace = program.getSymbolTable().createClass(program.getGlobalNamespace(),
                "type_info", SourceType.IMPORTED);
            assertEquals(SymbolType.CLASS, namespace.getSymbol().getSymbolType());
            return namespace;
        }
        Symbol label(Address address, String name, Namespace namespace) throws Exception {
            Symbol symbol = program.getSymbolTable().createLabel(address,name,namespace,SourceType.IMPORTED);
            assertEquals(SymbolType.LABEL,symbol.getSymbolType());
            assertEquals(address,symbol.getAddress());
            assertEquals(namespace.getID(),symbol.getParentNamespace().getID());
            return symbol;
        }
        void observe(String result) throws Exception {
            Namespace namespace=program.getSymbolTable().getNamespace("type_info",program.getGlobalNamespace());
            int labels=0;
            if (namespace != null) {
                for (String name : new String[]{"vftable", "`vftable'", "type_info"}) {
                    for (Symbol symbol : program.getSymbolTable().getSymbols(name,namespace)) {
                        if (symbol.getSymbolType()==SymbolType.LABEL) { labels++; }
                    }
                }
            }
            assertEquals(PeLoader.PE_NAME,program.getExecutableFormat());
            assertEquals(CompilerEnum.VisualStudio.toString(),program.getCompiler());
            assertEquals("windows",program.getCompilerSpec().getCompilerSpecID().getIdAsString());
            assertEquals(vftable.getOffset(),Integer.toUnsignedLong(program.getMemory().getInt(descriptor)));
            System.out.println("RTTI_LABEL_OBSERVATION case="+caseName+
                " block="+program.getMemory().getBlock(descriptor).getName()+" labelRecords="+labels+
                " rawPointer="+vftable+" result="+result);
        }
        Address find() throws Exception {
            Address result=RttiUtil.findTypeInfoVftableAddress(program,TaskMonitor.DUMMY);
            observe(result==null ? "NULL" : result.toString());return result;
        }
        public void close() {
            try { if (transaction >= 0) { program.endTransaction(transaction,false); transaction=-1; } }
            finally { if (program.isUsedBy(consumer)) { program.release(consumer); } }
        }
    }
    @Test public void testPublicCreatedLabelRoundTripOutsideData() throws Exception {
        try (Fixture f = new Fixture("created", ".rdata")) {
            RttiUtil.createTypeInfoVftableSymbol(f.program,f.vftable);
            Namespace namespace=f.program.getSymbolTable().getNamespace("type_info",f.program.getGlobalNamespace());
            assertNotNull(namespace);
            Symbol symbol=f.program.getSymbolTable().getSymbol("vftable",f.vftable,namespace);
            assertNotNull(symbol);assertEquals(SymbolType.LABEL,symbol.getSymbolType());
            assertEquals("Publicly created vftable label must be found outside .data",f.vftable,f.find());
        }
    }
    @Test public void testActualWindowsTypeDescriptorCallerOutsideData() throws Exception {
        try (Fixture f = new Fixture("windows-model", ".rdata")) {
            RttiUtil.createTypeInfoVftableSymbol(f.program,f.vftable);
            f.observe("MODEL_INPUT");
            TypeDescriptorModel model=new TypeDescriptorModel(f.program,f.descriptor,new DataValidationOptions());
            try { model.validate(); }
            catch (InvalidDataTypeException ex) {
                assertEquals("No vf table pointer is defined for this TypeDescriptor model.",ex.getMessage());
                assertTrue(java.util.Arrays.stream(ex.getStackTrace()).anyMatch(frame ->
                    frame.getClassName().equals(TypeDescriptorModel.class.getName()) &&
                    frame.getMethodName().equals("checkVfTablePointerComponent")));
                System.out.println("RTTI_LABEL_MODEL_RESULT case=windows-model result=NO_VF_POINTER");
                fail("Actual Windows descriptor lost its labeled vftable pointer");
            }
            assertEquals(".?AVActualNativeClass@@",model.getTypeName());
            assertEquals("Actual Windows descriptor must retain its vftable pointer",f.vftable,model.getVFTableAddress());
            System.out.println("RTTI_LABEL_MODEL_RESULT case=windows-model result="+model.getVFTableAddress());
        }
    }
    @Test public void testPdbVftableLabelOutsideData() throws Exception {
        try (Fixture f = new Fixture("pdb", ".rdata")) {
            f.label(f.vftable,"`vftable'",f.typeInfo());
            assertEquals("Actual PDB vftable label must be found",f.vftable,f.find());
        }
    }
    @Test public void testLegacyTypeInfoLabelOutsideData() throws Exception {
        try (Fixture f = new Fixture("legacy-label", ".rdata")) {
            f.label(f.vftable,"type_info",f.typeInfo());
            assertEquals("Actual legacy type_info label must be found",f.vftable,f.find());
        }
    }
    @Test public void testAmbiguousSameNameLabelsFailClosed() throws Exception {
        try (Fixture f = new Fixture("same-name-ambiguity", ".rdata")) {
            Namespace namespace=f.typeInfo();f.label(f.vftable,"vftable",namespace);f.label(f.alternative,"vftable",namespace);
            assertNull("Two distinct actual table labels must not pick an arbitrary address",f.find());
        }
    }
    @Test public void testConflictingLabelAliasesFailClosed() throws Exception {
        try (Fixture f = new Fixture("alias-ambiguity", ".rdata")) {
            Namespace namespace=f.typeInfo();f.label(f.vftable,"vftable",namespace);f.label(f.alternative,"`vftable'",namespace);
            assertNull("Distinct actual alias labels must not pick an arbitrary address",f.find());
        }
    }
    @Test public void testWrongNamespaceLabelIsIgnored() throws Exception {
        try (Fixture f = new Fixture("wrong-namespace", ".rdata")) {
            f.label(f.vftable,"vftable",f.program.getGlobalNamespace());assertNull(f.find());
        }
    }
    @Test public void testUnlabeledLegacyDataFallback() throws Exception {
        try (Fixture f = new Fixture("raw-data", ".data")) { assertEquals(f.vftable,f.find()); }
    }
    @Test public void testUnlabeledNonDataIsNotGuessed() throws Exception {
        try (Fixture f = new Fixture("raw-nondata", ".rdata")) { assertNull(f.find()); }
    }
}
