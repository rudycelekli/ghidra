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
package ghidra.app.util.exporter;

import static org.junit.Assert.*;
import org.junit.Test;
import ghidra.app.util.opinion.IntelHexRecord;
import ghidra.app.util.opinion.IntelHexRecordReader;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;
import java.nio.file.*;
import java.util.*;

/** Actual public Intel HEX export must retain selected address and byte pairs. */
public class IntelHexExportGapCharacterizationTest extends AbstractGhidraHeadlessIntegrationTest {
    private static class Fixture implements AutoCloseable {
        final ProgramBuilder builder;
        final Program program;
        Fixture() throws Exception {
            builder = new ProgramBuilder("IntelHexGap", ProgramBuilder._TOY, null);
            program = builder.getProgram();
        }
        void block(String name, long address, byte[] bytes) throws Exception {
            String location=Long.toHexString(address);
            builder.createMemory(name, location, bytes.length);
            builder.setBytes(location, bytes);
        }
        AddressSet selection(long first, long last) {
            return new AddressSet(builder.addr(first), builder.addr(last));
        }
        public void close() { builder.dispose(); }
    }
    private static byte[] sequence(int count, int start) {
        byte[] bytes=new byte[count];
        for (int i=0;i<count;i++) { bytes[i]=(byte)(start+i); }
        return bytes;
    }
    private Map<Long,Byte> selectedInput(Fixture fixture, AddressSetView selection) throws Exception {
        assertEquals(32,fixture.program.getAddressFactory().getDefaultAddressSpace().getSize());
        assertEquals(1,fixture.program.getAddressFactory().getDefaultAddressSpace().getAddressableUnitSize());
        AddressSetView selected=selection==null ? fixture.program.getMemory() : selection;
        Map<Long,Byte> input=new TreeMap<>();
        AddressIterator addresses=selected.getAddresses(true);
        while (addresses.hasNext()) {
            Address address=addresses.next();
            assertTrue(fixture.program.getMemory().getBlock(address).isInitialized());
            input.put(address.getOffset(),fixture.program.getMemory().getByte(address));
        }
        return input;
    }
    private Map<Long,Byte> exportAndRead(String name, Fixture fixture, AddressSetView selection,
            boolean drop, int expectedInputBytes) throws Exception {
        Map<Long,Byte> input=selectedInput(fixture,selection);
        assertEquals(expectedInputBytes,input.size());
        Path file=Files.createTempFile("intelhex-address-gap-", ".hex");
        try {
            assertTrue(new IntelHexExporter(16,drop).export(file.toFile(),fixture.program,selection,TaskMonitor.DUMMY));
            List<String> lines=Files.readAllLines(file);
            Map<Long,Byte> actual=new TreeMap<>();
            long upper=0;
            int dataRecords=0,extendedRecords=0,eofRecords=0;
            for (int lineIndex=0;lineIndex<lines.size();lineIndex++) {
                IntelHexRecord record=IntelHexRecordReader.readRecord(lines.get(lineIndex));
                assertTrue("Actual record checksum must be valid",record.isReportedChecksumCorrect());
                switch (record.getRecordType()) {
                    case IntelHexRecord.EXTENDED_LINEAR_ADDRESS_RECORD_TYPE:
                        assertEquals(0,eofRecords);
                        assertEquals(2,record.getRecordLength());
                        byte[] segment=record.getData();
                        upper=(((segment[0]&255L)<<8)|(segment[1]&255L))<<16;
                        extendedRecords++;break;
                    case IntelHexRecord.DATA_RECORD_TYPE:
                        assertEquals(0,eofRecords);
                        byte[] data=record.getData();
                        assertTrue(data.length>0 && data.length<=16);
                        for (int i=0;i<data.length;i++) {
                            long address=upper+record.getLoadOffset()+i;
                            assertNull("Actual exported addresses must not overlap",actual.put(address,data[i]));
                        }
                        dataRecords++;break;
                    case IntelHexRecord.END_OF_FILE_RECORD_TYPE:
                        eofRecords++;assertEquals(lines.size()-1,lineIndex);break;
                    default:fail("Unexpected actual record type: "+record.getRecordType());
                }
            }
            assertEquals(1,eofRecords);
            System.out.println("INTEL_HEX_OBSERVATION case="+name+" input="+format(input)+
                " actual="+format(actual)+" dataRecords="+dataRecords+" extendedRecords="+extendedRecords+
                " eofRecords="+eofRecords+" drop="+drop);
            return actual;
        }
        finally { Files.deleteIfExists(file); }
    }
    private String format(Map<Long,Byte> data) {
        List<String> pairs=new ArrayList<>();
        data.forEach((address,value)->pairs.add(String.format("%08x:%02x",address,value&255)));
        return String.join(",",pairs);
    }
    @Test public void testSparseBlocksPreserveActualAddresses() throws Exception {
        try (Fixture fixture=new Fixture()) {
            fixture.block("first",0x1000,sequence(4,1));fixture.block("second",0x1020,sequence(3,0xa1));
            Map<Long,Byte> expected=selectedInput(fixture,null);
            assertEquals("Sparse initialized block export must preserve actual address-byte map",expected,
                exportAndRead("sparse-blocks",fixture,null,false,7));
        }
    }
    @Test public void testSelectionHolesPreserveActualAddresses() throws Exception {
        try (Fixture fixture=new Fixture()) {
            fixture.block("contiguous",0x1000,sequence(16,1));
            AddressSet selected=fixture.selection(0x1000,0x1003);selected.add(fixture.selection(0x1008,0x100b));
            Map<Long,Byte> expected=selectedInput(fixture,selected);
            assertEquals("Sparse selection export must preserve actual address-byte map",expected,
                exportAndRead("selection-holes",fixture,selected,false,8));
        }
    }
    @Test public void testContiguousShortRecordPreserved() throws Exception {
        try (Fixture fixture=new Fixture()) {
            fixture.block("contiguous",0x1000,sequence(7,1));
            assertEquals(selectedInput(fixture,null),exportAndRead("contiguous",fixture,null,false,7));
        }
    }
    @Test public void testAdjacentBlocksRemainContiguous() throws Exception {
        try (Fixture fixture=new Fixture()) {
            fixture.block("first",0x1000,sequence(4,1));fixture.block("second",0x1004,sequence(3,5));
            assertEquals(selectedInput(fixture,null),exportAndRead("adjacent-blocks",fixture,null,false,7));
        }
    }
    @Test public void testFullRecordBeforeGapPreserved() throws Exception {
        try (Fixture fixture=new Fixture()) {
            fixture.block("first",0x1000,sequence(16,1));fixture.block("second",0x1020,sequence(3,0xa1));
            assertEquals(selectedInput(fixture,null),exportAndRead("full-before-gap",fixture,null,false,19));
        }
    }
    @Test public void testSegmentChangePreservesActualAddresses() throws Exception {
        try (Fixture fixture=new Fixture()) {
            fixture.block("first",0x1000,sequence(4,1));fixture.block("second",0x10020,sequence(3,0xa1));
            assertEquals(selectedInput(fixture,null),exportAndRead("segment-change",fixture,null,false,7));
        }
    }
    @Test public void testDeliberateTrailingDropPreserved() throws Exception {
        try (Fixture fixture=new Fixture()) {
            fixture.block("contiguous",0x1000,sequence(19,1));
            Map<Long,Byte> expected=selectedInput(fixture,fixture.selection(0x1000,0x100f));
            assertEquals(expected,exportAndRead("trailing-drop",fixture,null,true,19));
        }
    }
    @Test public void testEmptySelectionProducesOnlyEof() throws Exception {
        try (Fixture fixture=new Fixture()) {
            fixture.block("unselected",0x1000,sequence(7,1));
            assertEquals(Map.of(),exportAndRead("empty-selection",fixture,new AddressSet(),false,0));
        }
    }
}
