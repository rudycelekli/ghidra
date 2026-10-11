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

import org.junit.Test;

import ghidra.program.model.data.*;

/** Actual provider/action reproduction of issue #8922; no production changes. */
public class StructureEditorUnpackageTrailingUndefinedTest extends AbstractStructureEditorTest {

	@Test
	public void testUnpackageMiddleStructureWithTrailingUndefined() throws Exception {
		checkUnpackageMiddleStructure(2);
	}

	@Test
	public void testUnpackageMiddleStructureWithoutTrailingUndefined() throws Exception {
		checkUnpackageMiddleStructure(0);
	}

	private void checkUnpackageMiddleStructure(int trailingUndefined) throws Exception {
		program.withTransaction("Create issue reproduction", () -> {
			simpleStructure.setPackingEnabled(false);
			simpleStructure.deleteAll();
			simpleStructure.add(WordDataType.dataType, "word", "nested word");
			simpleStructure.add(ByteDataType.dataType, "byte", "nested byte");
			complexStructure.setPackingEnabled(false);
			complexStructure.deleteAll();
			complexStructure.add(ByteDataType.dataType, "before", null);
			complexStructure.add(simpleStructure, "nested", null);
			complexStructure.add(ByteDataType.dataType, "after", null);
			complexStructure.growStructure(trailingUndefined);
		});
		waitForSwing();
		init(complexStructure, pgmTestCat);
		Structure view = (Structure) model.getViewDataTypeManager().getResolvedViewComposite();
		assertEquals(5 + trailingUndefined, view.getLength());
		assertEquals("before", view.getComponentAt(0).getFieldName());
		assertTrue(view.getComponentAt(1).getDataType() instanceof Structure);
		assertEquals("after", view.getComponentAt(4).getFieldName());
		setSelection(new int[] { 1 });
		assertTrue(unpackageAction.isEnabled());
		invoke(unpackageAction);
		System.out.println("UNPACKAGE_ACTION_COMPLETED trailingUndefined=" + trailingUndefined);
		assertEquals(5 + trailingUndefined, view.getLength());
		assertEquals(4, view.getNumDefinedComponents());
		DataTypeComponent[] expected = view.getDefinedComponents();
		assertEquals(0, expected[0].getOffset());
		assertEquals("before", expected[0].getFieldName());
		assertEquals(1, expected[1].getOffset());
		assertTrue(expected[1].getDataType().isEquivalent(WordDataType.dataType));
		assertEquals("word", expected[1].getFieldName());
		assertEquals("nested word", expected[1].getComment());
		assertEquals(3, expected[2].getOffset());
		assertTrue(expected[2].getDataType().isEquivalent(ByteDataType.dataType));
		assertEquals("byte", expected[2].getFieldName());
		assertEquals("nested byte", expected[2].getComment());
		assertEquals(4, expected[3].getOffset());
		assertEquals("after", expected[3].getFieldName());
		for (int offset = 5; offset < 5 + trailingUndefined; offset++) {
			assertTrue(Undefined.isUndefined(view.getComponentAt(offset).getDataType()));
		}
	}
}
