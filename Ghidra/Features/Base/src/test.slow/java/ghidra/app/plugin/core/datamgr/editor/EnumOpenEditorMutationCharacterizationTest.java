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
package ghidra.app.plugin.core.datamgr.editor;

import static org.junit.Assert.*;

import java.util.*;
import java.util.concurrent.*;

import org.junit.Test;

import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Program;
import ghidra.test.*;

/** Fork-only bounded observation of the publicly reported open-editor/script interaction. */
public class EnumOpenEditorMutationCharacterizationTest extends AbstractGhidraHeadedIntegrationTest {

    @Test
    public void testOpenEditorWhileReplacingEntries() throws Exception {
        characterize(true);
    }

    @Test
    public void testClosedEditorMutationControl() throws Exception {
        characterize(false);
    }

    private void characterize(boolean openEditor) throws Exception {
        TestEnv env = null;
        ProgramBuilder builder = null;
        Thread.UncaughtExceptionHandler previous = Thread.getDefaultUncaughtExceptionHandler();
        List<Throwable> reported = new CopyOnWriteArrayList<>();
        List<Throwable> unrelated = new CopyOnWriteArrayList<>();
        ExecutorService worker = Executors.newSingleThreadExecutor();
        try {
            env = new TestEnv();
            PluginTool tool = env.showTool();
            tool.addPlugin(DataTypeManagerPlugin.class.getName());
            DataTypeManagerPlugin plugin = env.getPlugin(DataTypeManagerPlugin.class);
            builder = new ProgramBuilder("enum-editor-mutation", ProgramBuilder._TOY);
            Program program = builder.getProgram();
            env.open(program);
            DataTypeManager manager = program.getDataTypeManager();
            Enum first;
            Enum second;
            int transaction = program.startTransaction("Create original script enums");
            try {
                first = createEnum(manager, "DLL_ID", 4);
                second = createEnum(manager, "DLL_ID16", 2);
            }
            finally {
                program.endTransaction(transaction, true);
            }
            program.flushEvents();
            waitForSwing();
            EnumEditorProvider provider = null;
            if (openEditor) {
                runSwingLater(() -> plugin.edit(first));
                provider = waitForComponentProvider(EnumEditorProvider.class);
                assertNotNull(provider);
                assertTrue(provider.isVisible());
                EnumEditorPanel panel = (EnumEditorPanel) provider.getComponent();
                assertEquals(706, (int) runSwing(() -> panel.getTable().getRowCount()));
            }
            verify(first);
            verify(second);
            // Capture only the exact reported failure; preserve every stack, forward unrelated
            // failures to the original test handler, and restore the process handler in finally.
            Thread.UncaughtExceptionHandler original = Thread.getDefaultUncaughtExceptionHandler();
            previous = original;
            Thread.setDefaultUncaughtExceptionHandler((thread, error) -> {
                System.err.println("ENUM_EDITOR_CAPTURE thread=" + thread.getName() +
                    " identity=" + System.identityHashCode(error));
                error.printStackTrace(System.err);
                if (isReportedFailure(error)) {
                    reported.add(error);
                }
                else {
                    unrelated.add(error);
                    if (original != null) {
                        original.uncaughtException(thread, error);
                    }
                }
            });
            Future<?> script = worker.submit(() -> {
                for (int round = 0; round < 16; round++) {
                    int tx = program.startTransaction("Reported remove/re-add script round");
                    try {
                        replace(first);
                        replace(second);
                    }
                    finally {
                        program.endTransaction(tx, true);
                    }
                }
            });
            script.get(90, TimeUnit.SECONDS);
            program.flushEvents();
            waitForSwing();
            assertTrue("Unrelated uncaught failure invalidates observation", unrelated.isEmpty());
            verify(first);
            verify(second);
            if (provider != null) {
                assertTrue(provider.isVisible());
            }
            System.out.println("ENUM_EDITOR_MUTATION open=" + openEditor +
                " rounds=16 first=706 second=706 reported=" + reported.size());
            assertTrue("Reported open-editor EnumDB copy failure", reported.isEmpty());
        }
        finally {
            Thread.setDefaultUncaughtExceptionHandler(previous);
            worker.shutdownNow();
            try {
                assertTrue(worker.awaitTermination(30, TimeUnit.SECONDS));
            }
            finally {
                try {
                    if (env != null) {
                        env.dispose();
                    }
                }
                finally {
                    if (builder != null) {
                        builder.dispose();
                    }
                }
            }
        }
    }

    private static Enum createEnum(DataTypeManager manager, String name, int size) {
        EnumDataType draft = new EnumDataType(name, size);
        for (int i = 0; i < 706; i++) {
            draft.add("entry_" + i, i);
        }
        return (Enum) manager.addDataType(draft, DataTypeConflictHandler.DEFAULT_HANDLER);
    }

    private static void replace(Enum value) {
        String[] names = value.getNames();
        assertEquals(706, names.length);
        for (String name : names) {
            long number = value.getValue(name);
            value.remove(name);
            value.add(name, number);
        }
    }

    private static void verify(Enum value) {
        assertEquals(706, value.getCount());
        for (int i = 0; i < 706; i++) {
            assertEquals(i, value.getValue("entry_" + i));
        }
    }

    private static boolean isReportedFailure(Throwable error) {
        if (!(error instanceof NoSuchElementException)) {
            return false;
        }
        List<String> required = List.of("ghidra.program.database.data.EnumDB.getValue",
            "ghidra.program.model.data.EnumDataType.replaceWith",
            "ghidra.program.database.data.EnumDB.copy",
            "ghidra.app.plugin.core.datamgr.editor.EnumEditorProvider$MyDataTypeManagerChangeListener.dataTypeChanged");
        Set<String> actual = new HashSet<>();
        for (StackTraceElement frame : error.getStackTrace()) {
            actual.add(frame.getClassName() + "." + frame.getMethodName());
        }
        return actual.containsAll(required);
    }
}
