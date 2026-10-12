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
package ghidra.app.cmd.data;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.*;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.task.TaskMonitor;

/** Fork-only observation of genuine disassembly diagnostics after public data creation. */
public class BadInstructionDataCharacterizationTest extends AbstractGenericTest {
    private ToyProgramBuilder builder;
    private Program program;
    private int transaction = -1;

    @Before
    public void setUp() throws Exception {
        builder = new ToyProgramBuilder("BadInstructionData", true);
        program = builder.getProgram();
        transaction = program.startTransaction("Observe actual disassembly and data producer");
        builder.createMemory(".text", "1000", 0x40).setExecute(true);
    }

    @After
    public void tearDown() {
        try {
            if (program != null && transaction >= 0) {
                program.endTransaction(transaction, false);
            }
        }
        finally {
            if (builder != null) {
                builder.dispose();
            }
        }
    }

    @Test
    public void testAppliedDataRemovesObsoleteParseError() throws Exception {
        builder.addBytesBadInstruction(0x1000);
        disassembler().disassemble(addr(0x1000), null);
        assertNull(program.getListing().getInstructionAt(addr(0x1000)));
        Bookmark prior = badBookmark(0x1000);
        assertNotNull("Actual decoder must create parse-error bookmark", prior);
        assertTrue(prior.getComment().contains("Unable to resolve constructor"));
        assertTrue(new CreateDataCmd(addr(0x1000), WordDataType.dataType).applyTo(program));
        assertEquals(2, program.getListing().getDefinedDataAt(addr(0x1000)).getLength());
        boolean remaining = badBookmark(0x1000) != null;
        System.out.println("BAD_DATA_OBSERVATION case=parse-error dataLength=2 obsoleteBookmark=" + remaining);
        assertFalse("Obsolete parse-error bookmark must be removed after data creation", remaining);
    }

    @Test
    public void testCustomNoteSurvivesDataCreation() {
        assertBookmarkPreserved(BookmarkType.NOTE, "User note", "Keep user annotation");
    }

    @Test
    public void testIndependentErrorSurvivesDataCreation() {
        assertBookmarkPreserved(BookmarkType.ERROR, "Independent diagnostic", "Keep independent error");
    }

    @Test
    public void testActualCallToDataConflictSurvivesDataReplacement() throws Exception {
        builder.addBytesCall(0x1000, 0x1008);
        builder.addBytesReturn(0x1002);
        assertTrue(new CreateDataCmd(addr(0x1008), WordDataType.dataType).applyTo(program));
        disassembler().disassemble(addr(0x1000), null);
        Instruction call = program.getListing().getInstructionAt(addr(0x1000));
        assertNotNull(call);
        assertTrue(call.getFlowType().isCall());
        assertArrayEquals(new Address[] { addr(0x1008) }, call.getFlows());
        Bookmark prior = badBookmark(0x1008);
        assertNotNull("Actual call-to-data conflict must be observed", prior);
        assertTrue(prior.getComment().contains("conflicting data"));
        long id = prior.getId();
        String description = prior.getComment();
        Data original = program.getListing().getDefinedDataAt(addr(0x1008));
        assertEquals(2, original.getLength());
        assertTrue(original.getDataType().isEquivalent(WordDataType.dataType));
        CreateDataCmd replacement = new CreateDataCmd(addr(0x1008), ByteDataType.dataType,
            false, ClearDataMode.CLEAR_SINGLE_DATA);
        assertTrue(replacement.getStatusMsg(), replacement.applyTo(program));
        Bookmark after = badBookmark(0x1008);
        assertNotNull(after);
        assertEquals(id, after.getId());
        assertEquals(description, after.getComment());
        Data replaced = program.getListing().getDefinedDataAt(addr(0x1008));
        assertEquals(1, replaced.getLength());
        assertTrue(replaced.getDataType().isEquivalent(ByteDataType.dataType));
        assertTrue(program.getListing().getInstructionAt(addr(0x1000)).getFlowType().isCall());
        assertArrayEquals(new Address[] { addr(0x1008) },
            program.getListing().getInstructionAt(addr(0x1000)).getFlows());
        System.out.println("BAD_DATA_OBSERVATION case=call-conflict dataLength=1 conflictPreserved=true");
    }

    @Test
    public void testFailedDataCreationPreservesInstructionAndBookmark() throws Exception {
        builder.addBytesReturn(0x1000);
        disassembler().disassemble(addr(0x1000), null);
        Instruction before = program.getListing().getInstructionAt(addr(0x1000));
        assertNotNull(before);
        Bookmark prior = program.getBookmarkManager().setBookmark(addr(0x1000), BookmarkType.ERROR,
            "Independent diagnostic", "Keep error on rejected data creation");
        assertFalse(new CreateDataCmd(addr(0x1000), WordDataType.dataType).applyTo(program));
        assertEquals(before, program.getListing().getInstructionAt(addr(0x1000)));
        assertNull(program.getListing().getDefinedDataAt(addr(0x1000)));
        assertEquals(prior.getId(), program.getBookmarkManager().getBookmark(addr(0x1000),
            BookmarkType.ERROR, "Independent diagnostic").getId());
        System.out.println("BAD_DATA_OBSERVATION case=rejected-data instructionPreserved=true bookmarkPreserved=true");
    }

    private void assertBookmarkPreserved(String type, String category, String text) {
        Bookmark prior = program.getBookmarkManager().setBookmark(addr(0x1000), type, category, text);
        assertTrue(new CreateDataCmd(addr(0x1000), WordDataType.dataType).applyTo(program));
        Bookmark after = program.getBookmarkManager().getBookmark(addr(0x1000), type, category);
        assertNotNull(after);
        assertEquals(prior.getId(), after.getId());
        assertEquals(text, after.getComment());
        System.out.println("BAD_DATA_OBSERVATION case=" + (type.equals(BookmarkType.NOTE) ? "custom-note" : "independent-error") +
            " dataLength=2 bookmarkPreserved=true");
    }

    private Address addr(long offset) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private Bookmark badBookmark(long offset) {
        return program.getBookmarkManager().getBookmark(addr(offset), BookmarkType.ERROR,
            Disassembler.ERROR_BOOKMARK_CATEGORY);
    }

    private Disassembler disassembler() {
        return Disassembler.getDisassembler(program, TaskMonitor.DUMMY, null);
    }
}
