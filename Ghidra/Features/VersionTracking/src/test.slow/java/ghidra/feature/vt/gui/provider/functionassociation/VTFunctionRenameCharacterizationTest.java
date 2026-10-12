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
package ghidra.feature.vt.gui.provider.functionassociation;

import static org.junit.Assert.*;

import java.util.concurrent.TimeUnit;

import org.junit.*;
import generic.test.TestUtils;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.feature.vt.api.correlator.program.ExactMatchInstructionsProgramCorrelatorFactory;
import ghidra.feature.vt.gui.VTTestEnv;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;

/** Fork-only real name-filter observations through the Version Tracking provider. */
public class VTFunctionRenameCharacterizationTest extends AbstractGhidraHeadedIntegrationTest {
    private VTTestEnv env;
    private PluginTool tool;
    private VTFunctionAssociationProvider provider;

    @Before
    public void setUp() throws Exception {
        setErrorGUIEnabled(false);
        env = new VTTestEnv();
        tool = env.showTool();
        tool.setSize(800, 800);
        env.createSession("VersionTracking/WallaceSrc", "VersionTracking/WallaceVersion2",
            new ExactMatchInstructionsProgramCorrelatorFactory());
        VTPlugin plugin = env.getVersionTrackingPlugin();
        provider = (VTFunctionAssociationProvider) TestUtils.getInstanceField("functionAssociationProvider", plugin);
        runSwing(() -> tool.showComponentProvider(provider, true));
        waitForSwing();
        waitForTasks();
        waitForSwing();
        assertTrue(provider.isVisible());
    }

    @After
    public void tearDown() {
        if (tool != null) { runSwing(() -> tool.close()); }
        if (env != null) { env.dispose(); }
    }

    @Test
    public void testSourceRenameUpdatesActiveFilter() throws Exception { check(true, true); }
    @Test
    public void testDestinationRenameUpdatesActiveFilter() throws Exception { check(false, true); }
    @Test
    public void testSourceUnchangedFilterControl() throws Exception { check(true, false); }
    @Test
    public void testDestinationUnchangedFilterControl() throws Exception { check(false, false); }

    private void check(boolean source, boolean rename) throws Exception {
        Program program = source ? env.getSourceProgram() : env.getDestinationProgram();
        String side = source ? "source" : "destination";
        GhidraTable table = (GhidraTable) TestUtils.getInstanceField(side + "FunctionsTable", provider);
        GhidraTableFilterPanel<?> filter = (GhidraTableFilterPanel<?>)
            TestUtils.getInstanceField(side + "TableFilterPanel", provider);
        VTFunctionAssociationTableModel model = (VTFunctionAssociationTableModel) table.getModel();
        waitForTableModel((ThreadedTableModel<?, ?>) model);
        assertTrue(model.getRowCount() > 0);
        Function function = model.getFunction(0);
        assertNotNull(function);
        String oldName = "__vt_rename_" + side + "_original";
        rename(function, oldName);
        runSwing(() -> filter.setFilterText(oldName));
        waitForRowCount(model, 1);
        waitForTableModel((ThreadedTableModel<?, ?>) model);
        assertEquals("Real initial name filter must select its one function", 1,
            (int) runSwing(() -> model.getRowCount()));
        assertEquals(function.getEntryPoint(), model.getFunction(0).getEntryPoint());
        assertEquals(oldName, runSwing(() -> filter.getFilterText()));
        if (rename) { rename(function, "__vt_rename_" + side + "_updated"); }
        else { program.flushEvents(); }
        waitForSwing();
        waitForTasks();
        waitForSwing();
        waitForRowCount(model, rename ? 0 : 1);
        waitForTableModel((ThreadedTableModel<?, ?>) model);
        assertEquals(oldName, runSwing(() -> filter.getFilterText()));
        assertEquals(rename ? "__vt_rename_" + side + "_updated" : oldName, function.getName());
        int rows = runSwing(() -> model.getRowCount());
        System.out.println("VT_RENAME_FILTER side=" + side + " rename=" + rename + " rows=" + rows +
            " function=" + function.getName() + " filter=" + oldName + " visible=" + provider.isVisible());
        assertEquals("Active name filter must reflect the actual function name", rename ? 0 : 1, rows);
    }

    private void waitForRowCount(VTFunctionAssociationTableModel model, int expected) {
        // A filter edit uses a deferred Swing update; the model can initially appear idle.
        // Observe natural filtering and program-event work without reapplying the filter.
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        do {
            boolean settled = runSwing(() ->
                !model.isBusy() && model.getRowCount() == expected);
            if (settled) {
                return;
            }
            sleep(50);
        }
        while (System.nanoTime() < deadline);
        // The caller records the actual row count and makes the numeric assertion.
    }

    private void rename(Function function, String name) throws Exception {
        Program program = function.getProgram();
        int transaction = program.startTransaction("real function rename");
        try { function.setName(name, SourceType.USER_DEFINED); }
        finally { program.endTransaction(transaction, true); }
        program.flushEvents();
        waitForSwing();
    }
}
