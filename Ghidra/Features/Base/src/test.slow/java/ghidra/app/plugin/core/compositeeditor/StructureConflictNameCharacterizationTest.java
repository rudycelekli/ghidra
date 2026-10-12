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
package ghidra.app.plugin.core.compositeeditor;

import static org.junit.Assert.*;

import java.awt.Point;
import java.awt.Rectangle;

import javax.swing.JTable;

import org.junit.Test;

import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.*;
import ghidra.test.*;

/** Fork-only observation of actual editor drops onto separately named structures. */
public class StructureConflictNameCharacterizationTest extends AbstractGhidraHeadedIntegrationTest {

	@Test
	public void testConflictSuffixStructureCanContainBaseNamedStructure() throws Exception {
		check("foo.conflict");
	}

	@Test
	public void testOrdinaryDifferentNameControl() throws Exception {
		check("bar");
	}

	private void check(String targetName) throws Exception {
		TestEnv env = null;
		ProgramBuilder builder = null;
		StructureEditorProvider provider = null;
		try {
			env = new TestEnv();
			PluginTool tool = env.showTool();
			tool.addPlugin(DataTypeManagerPlugin.class.getName());
			DataTypeManagerPlugin plugin = env.getPlugin(DataTypeManagerPlugin.class);
			builder = new ProgramBuilder("structure-names", ProgramBuilder._TOY);
			env.open(builder.getProgram());
			DataTypeManager dtm = builder.getProgram().getDataTypeManager();
			Structure source;
			Structure target;
			int tx = dtm.startTransaction("Create two separately named structures");
			try {
				StructureDataType sourceDraft = new StructureDataType("foo", 0, dtm);
				sourceDraft.add(ByteDataType.dataType);
				source = (Structure) dtm.addDataType(sourceDraft, DataTypeConflictHandler.DEFAULT_HANDLER);
				target = (Structure) dtm.addDataType(new StructureDataType(targetName, 0, dtm),
					DataTypeConflictHandler.DEFAULT_HANDLER);
			}
			finally {
				dtm.endTransaction(tx, true);
			}
			assertNotSame(source, target);
			assertEquals("foo", source.getName());
			assertEquals(targetName, target.getName());
			assertEquals(1, source.getNumComponents());
			assertEquals(0, target.getNumComponents());
			StructureEditorProvider actual = runSwing(() -> new StructureEditorProvider(plugin, target, false));
			provider = actual;
			waitForSwing();
			StructureEditorModel model = (StructureEditorModel) actual.getModel();
			assertEquals(0, model.getNumComponents());
			assertEquals("", model.getStatus());
			JTable table = actual.getTable();
			assertTrue(runSwing(() -> table.getRowCount()) > 0);
			Point point = runSwing(() -> {
				Rectangle bounds = table.getCellRect(0, 0, true);
				return new Point(bounds.x + bounds.width / 2, bounds.y + bounds.height / 2);
			});
			assertEquals(0, (int) runSwing(() -> table.rowAtPoint(point)));
			runSwing(() -> actual.getComponent().addAtPoint(point, source), false);
			waitForSwing();
			System.out.println("STRUCTURE_NAME_DROP target=" + targetName + " source=foo components=" +
				model.getNumComponents() + " status=" + model.getStatus());
			assertEquals("", model.getStatus());
			assertEquals(1, model.getNumComponents());
			assertEquals("foo", model.getComponent(0).getDataType().getName());
			assertEquals(1, model.getComponent(0).getLength());
		}
		finally {
			if (provider != null) {
				StructureEditorProvider owned = provider;
				runSwing(() -> owned.dispose());
			}
			if (env != null) {
				env.dispose();
			}
			if (builder != null) {
				builder.dispose();
			}
		}
	}
}
