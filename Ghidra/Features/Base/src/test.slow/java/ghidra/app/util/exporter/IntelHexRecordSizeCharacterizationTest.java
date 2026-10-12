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
import java.awt.*;
import java.nio.file.*;
import java.util.*;
import java.util.List;
import org.junit.*;
import docking.widgets.textfield.HintTextField;
import ghidra.app.util.Option;
import ghidra.program.database.*;
import ghidra.program.model.address.Address;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.task.TaskMonitor;

/** Actual public option editor input followed by export of independently known bytes. */
public class IntelHexRecordSizeCharacterizationTest extends AbstractGhidraHeadedIntegrationTest {
    private ProgramDB program;
    @Before public void setUp() throws Exception {
        program=createDefaultProgram("IntelHex record size",ProgramBuilder._TOY,this);
        int tx=program.startTransaction("Contiguous known bytes");
        try {
            Address start=program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
            program.getMemory().createInitializedBlock(".data",start,20,(byte)0,TaskMonitor.DUMMY,false);
            byte[] bytes=new byte[20];for(int i=0;i<20;i++)bytes[i]=(byte)i;
            program.getMemory().setBytes(start,bytes);
            assertEquals(32,start.getSize());
        }
        finally { program.endTransaction(tx,true); }
    }
    @After public void tearDown() { if(program!=null)program.release(this); }
    private HintTextField field(Component component) {
        if(component instanceof HintTextField input)return input;
        if(component instanceof Container container)for(Component child:container.getComponents()) {
            HintTextField found=field(child);if(found!=null)return found;
        }
        return null;
    }
    private void check(String text,boolean valid,int size) throws Exception {
        IntelHexExporter exporter=new IntelHexExporter();
        List<Option> options=runSwing(()->exporter.getOptions(()->program));
        assertEquals(2,options.size());assertEquals("Record Size",options.get(1).getName());
        Component component=runSwing(()->options.get(1).getCustomEditorComponent(null));
        HintTextField input=field(component);assertNotNull(input);
        runSwing(()->{input.setText(text);});
        assertEquals("Actual verifier precondition",valid,runSwing(()->input.isFieldValid()));
        exporter.setOptions(options);
        Path output=Files.createTempFile("intelhex-record-size-",".hex");
        try {
            boolean exported=false;String error="NONE";
            try {exported=exporter.export(output.toFile(),program,null,TaskMonitor.DUMMY);}
            catch(NumberFormatException ex){error=ex.getClass().getName();}
            System.out.println("INTELHEX_SIZE_INPUT text="+(text.isEmpty()?"EMPTY":text)+" valid="+valid+" expectedSize="+size+" exported="+exported+" error="+error);
            assertEquals("Actual valid record-size option must export",true,exported);
            List<Integer> lengths=new ArrayList<>();List<Integer> actualBytes=new ArrayList<>();int eof=0;
            for(String line:Files.readAllLines(output)) {
                assertTrue(line.startsWith(":"));byte[] record=HexFormat.of().parseHex(line.substring(1));
                int length=Byte.toUnsignedInt(record[0]);assertEquals(length+5,record.length);
                int sum=0;for(byte value:record)sum+=Byte.toUnsignedInt(value);assertEquals(0,sum&255);
                int type=Byte.toUnsignedInt(record[3]);
                if(type==0){lengths.add(length);assertEquals(0x1000+actualBytes.size(),(Byte.toUnsignedInt(record[1])<<8)|Byte.toUnsignedInt(record[2]));for(int i=0;i<length;i++)actualBytes.add(Byte.toUnsignedInt(record[4+i]));}
                else if(type==1){assertEquals(0,length);eof++;}
                else {assertEquals(4,type);assertEquals(2,length);assertEquals(0,record[4]);assertEquals(0,record[5]);}
            }
            List<Integer> expectedLengths=new ArrayList<>();for(int left=20;left>0;left-=Math.min(size,left))expectedLengths.add(Math.min(size,left));
            List<Integer> expectedBytes=new ArrayList<>();for(int i=0;i<20;i++)expectedBytes.add(i);
            assertEquals(expectedBytes,actualBytes);assertEquals(1,eof);
            System.out.println("INTELHEX_SIZE_OUTPUT text="+(text.isEmpty()?"EMPTY":text)+" lengths="+lengths+" bytes="+actualBytes.size()+" eof="+eof);
            assertEquals("Actual accepted record-size data lengths",expectedLengths,lengths);
        }
        finally {Files.deleteIfExists(output);}
    }
    @Test public void testHexPrefix() throws Exception {check("0x10",true,16);}
    @Test public void testHashHexPrefix() throws Exception {check("#10",true,16);}
    @Test public void testAcceptedOctalPrefix() throws Exception {check("010",true,8);}
    @Test public void testDecimalControl() throws Exception {check("16",true,16);}
    @Test public void testEmptyDefaultControl() throws Exception {check("",false,16);}
    @Test public void testInvalidTooLargeDefaultControl() throws Exception {check("256",false,16);}
}
