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
package ghidra.app.cmd.function;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/** Fork-only observations of the public command's return value and real effects. */
public class CreateFunctionResultCharacterizationTest extends AbstractGhidraHeadlessIntegrationTest {
    private ProgramBuilder builder;
    private Program program;
    private Address entry;

    @Before
    public void setUp() throws Exception {
        builder = new ProgramBuilder("CreateFunctionResult", ProgramBuilder._X86);
        builder.createMemory("code", "0x1000", 0x100);
        program = builder.getProgram();
        entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
        assertNull(program.getListing().getInstructionAt(entry));
        assertNull(program.getFunctionManager().getFunctionAt(entry));
    }

    @After
    public void tearDown() {
        if (builder != null) {
            builder.dispose();
        }
    }

    @Test
    public void testUndisassembledFindEntryReportsFailure() {
        int transaction = program.startTransaction("undisassembled public command");
        try {
            boolean result = new CreateFunctionCmd(entry, true).applyTo(program, TaskMonitor.DUMMY);
            assertNull("No function was actually created", program.getFunctionManager().getFunctionAt(entry));
            observe("undisassembled", result, false);
            assertFalse("No function must not report success", result);
        }
        finally { program.endTransaction(transaction, true); }
    }

    @Test
    public void testNewExternalFunctionReportsSuccess() throws Exception { checkExternal(false); }

    @Test
    public void testExistingExternalFunctionReportsSuccess() throws Exception { checkExternal(true); }

    private void checkExternal(boolean existing) throws Exception {
        int transaction = program.startTransaction("external public command");
        try {
            ExternalLocation location = external();
            if (existing) { location.createFunction(); }
            assertEquals(existing, location.isFunction());
            boolean result = new CreateFunctionCmd(location.getExternalSpaceAddress()).applyTo(program, TaskMonitor.DUMMY);
            assertTrue("Actual external location is a function", location.isFunction());
            assertNotNull(location.getFunction());
            observe(existing ? "existing-external" : "new-external", result, true);
            assertTrue("Successful external command must report success", result);
        }
        finally { program.endTransaction(transaction, true); }
    }

    @Test
    public void testMixedInternalExternalReportsSuccess() throws Exception {
        disassembleReturn();
        int transaction = program.startTransaction("mixed public command");
        try {
            ExternalLocation location = external();
            AddressSet entries = new AddressSet(entry);
            entries.add(location.getExternalSpaceAddress());
            assertEquals(2, entries.getNumAddresses());
            boolean result = new CreateFunctionCmd(entries).applyTo(program, TaskMonitor.DUMMY);
            assertNotNull(program.getFunctionManager().getFunctionAt(entry));
            assertTrue(location.isFunction());
            observe("mixed", result, true);
            assertTrue("Both real function operations succeeded", result);
        }
        finally { program.endTransaction(transaction, true); }
    }

    @Test
    public void testDisassembledInternalControl() throws Exception {
        disassembleReturn();
        int transaction = program.startTransaction("internal control");
        try {
            boolean result = new CreateFunctionCmd(entry, true).applyTo(program, TaskMonitor.DUMMY);
            assertNotNull(program.getFunctionManager().getFunctionAt(entry));
            observe("internal-control", result, true);
            assertTrue(result);
        }
        finally { program.endTransaction(transaction, true); }
    }

    @Test
    public void testMissingExternalControl() {
        int transaction = program.startTransaction("missing external control");
        try {
            Address external = program.getAddressFactory().getAddressSpace("EXTERNAL").getAddress(0x1234);
            assertNull(program.getSymbolTable().getPrimarySymbol(external));
            boolean result = new CreateFunctionCmd(external).applyTo(program, TaskMonitor.DUMMY);
            assertNull(program.getFunctionManager().getFunctionAt(external));
            observe("missing-external-control", result, false);
            assertFalse(result);
        }
        finally { program.endTransaction(transaction, true); }
    }

    @Test
    public void testCanceledControl() {
        int transaction = program.startTransaction("canceled control");
        try {
            TaskMonitorAdapter monitor = new TaskMonitorAdapter(true);
            monitor.cancel();
            assertTrue(monitor.isCancelled());
            boolean result = new CreateFunctionCmd(entry).applyTo(program, monitor);
            assertNull(program.getFunctionManager().getFunctionAt(entry));
            observe("canceled-control", result, false);
            assertFalse(result);
        }
        finally { program.endTransaction(transaction, true); }
    }

    private ExternalLocation external() throws Exception {
        return program.getExternalManager().addExtLocation("fixture.dll", "external_fn", null, SourceType.USER_DEFINED);
    }

    private void disassembleReturn() throws Exception {
        builder.setBytes("0x1000", "c3");
        builder.disassemble("0x1000", 1);
        assertEquals("RET", program.getListing().getInstructionAt(entry).getMnemonicString());
    }

    private void observe(String fixture, boolean result, boolean effect) {
        System.out.println("CREATE_FUNCTION_RESULT fixture=" + fixture + " result=" + result + " effect=" + effect);
    }
}
