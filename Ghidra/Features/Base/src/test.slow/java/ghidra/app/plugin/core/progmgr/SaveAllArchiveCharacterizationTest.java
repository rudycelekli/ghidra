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
package ghidra.app.plugin.core.progmgr;

import static org.junit.Assert.*;

import java.util.Arrays;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.widgets.OkDialog;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.services.*;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.dtarchive.DataTypeArchiveFactory;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.dtarchive.ProjectDataTypeArchive;
import ghidra.program.model.listing.Program;
import ghidra.test.*;
import ghidra.util.task.TaskMonitor;

/** Characterizes the public Save All action with real project datatype archives. */
public class SaveAllArchiveCharacterizationTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private PluginTool tool;
	private ProgramBuilder builder;
	private Program program;
	private ProjectDataTypeArchive archive;
	private DataTypeArchiveService archives;
	private CodeBrowserPlugin browser;
	private DockingActionIf saveAll;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(DataTypeManagerPlugin.class.getName());
		DomainFolder folder = tool.getProject().getProjectData().getRootFolder();
		builder = new ProgramBuilder("SaveAllProgram", ProgramBuilder._TOY);
		DomainFile programFile = folder.createFile("SaveAllProgram", builder.getProgram(),
			TaskMonitor.DUMMY);
		builder.dispose();
		program = tool.getService(ProgramManager.class).openProgram(programFile);
		assertNotNull(program);
		assertFalse(program.isChanged());
		ProjectDataTypeArchive created =
			DataTypeArchiveFactory.createProjectArchive(folder, "SaveAllArchive", this);
		DomainFile archiveFile = created.getDomainFile();
		created.release(this);
		archives = tool.getService(DataTypeArchiveService.class);
		assertNotNull(archives);
		archive = archives.openProjectArchive(archiveFile, Upgrade.NO, Recover.NO,
			TaskMonitor.DUMMY);
		assertTrue(archive.isChangeable());
		assertTrue(archive.canSave());
		assertFalse(archive.isChanged());
		assertTrue(Arrays.asList(tool.getDomainFiles()).contains(archiveFile));
		browser = getPlugin(tool, CodeBrowserPlugin.class);
		saveAll = getAction(tool, ProgramManagerPlugin.class.getSimpleName(), "Save All Files");
		assertNotNull(saveAll);
		env.showTool();
		waitForSwing();
	}

	@After
	public void tearDown() {
		if (archive != null && archives != null) {
			archives.closeArchive(archive);
		}
		if (env != null) {
			env.dispose();
		}
		if (builder != null) {
			builder.dispose();
		}
	}

	@Test
	public void testDirtyArchiveAloneDoesNotEnableSaveAll() {
		dirty(archive.getDataTypeManager(), "ArchiveOnly");
		assertTrue(archive.isChanged());
		assertFalse(program.isChanged());
		ActionContext context = runSwing(() -> browser.getProvider().getActionContext(null));
		assertTrue(saveAll.isValidContext(context));
		assertFalse(runSwing(() -> saveAll.isEnabledForContext(context)));
		System.out.println("ACTUAL_SAVE_ALL_ARCHIVE_ONLY: disabled=true archiveDirty=true");
	}

	@Test
	public void testMixedSaveAllLeavesProjectArchiveDirty() {
		dirty(archive.getDataTypeManager(), "ArchiveMixed");
		dirty(program.getDataTypeManager(), "ProgramMixed");
		assertTrue(archive.isChanged());
		assertTrue(program.isChanged());
		ActionContext context = runSwing(() -> browser.getProvider().getActionContext(null));
		assertTrue(runSwing(() -> saveAll.isEnabledForContext(context)));
		performAction(saveAll, browser.getProvider(), false);
		OkDialog dialog = waitForDialogComponent(OkDialog.class);
		assertEquals("Save All...", dialog.getTitle());
		pressButtonByText(dialog, "OK");
		waitForSwing();
		assertFalse(program.isChanged());
		assertTrue(archive.isChanged());
		assertNotNull(program.getDataTypeManager().getCategory(new CategoryPath("/ProgramMixed")));
		assertNotNull(archive.getDataTypeManager().getCategory(new CategoryPath("/ArchiveMixed")));
		System.out.println("ACTUAL_SAVE_ALL_MIXED: programDirty=false archiveDirty=true");
	}

	private void dirty(DataTypeManager manager, String name) {
		int transaction = manager.startTransaction("Add " + name);
		try {
			manager.createCategory(new CategoryPath("/" + name));
		}
		finally {
			manager.endTransaction(transaction, true);
		}
		waitForSwing();
	}
}
