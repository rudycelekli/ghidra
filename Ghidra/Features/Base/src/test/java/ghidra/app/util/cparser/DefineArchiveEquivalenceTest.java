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
package ghidra.app.util.cparser;

import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Iterator;

import org.junit.Test;

import ghidra.app.util.cparser.CPP.PreProcessor;
import ghidra.program.database.data.TransientDataTypeManager;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

public class DefineArchiveEquivalenceTest extends AbstractGhidraHeadlessIntegrationTest {
	@Test
	public void testDifferentArchiveValueIsNotReused() throws Exception {
		check("VALUE", 11, 9, 1);
	}

	@Test
	public void testDifferentArchiveWidthIsNotReused() throws Exception {
		check("VALUE", 65535, 9, 1);
	}

	@Test
	public void testEquivalentArchiveControl() throws Exception {
		check("VALUE", 9, 9, 1);
	}

	@Test
	public void testUnrelatedArchiveNameControl() throws Exception {
		check("OTHER", 11, 9, 1);
	}

	private void check(String oldName, long oldValue, long expected, int width) throws Exception {
		Path file = Files.createTempFile("ghidra-define-archive-", ".h");
		TransientDataTypeManager archive = new TransientDataTypeManager("archive");
		TransientDataTypeManager destination = new TransientDataTypeManager("destination");
		try {
			Files.writeString(file, "#define " + oldName + " " + oldValue + "\n");
			parse(file).getDefinitions().populateDefineEquates(null, archive);
			Enum existing = findEnum(archive, "define_" + oldName);
			assertNotNull("Actual archive enum must be populated", existing);
			assertEquals(oldValue, existing.getValue(oldName));
			Files.writeString(file, "#define VALUE " + expected + "\n");
			parse(file).getDefinitions().populateDefineEquates(new DataTypeManager[] { archive },
				destination);
			Enum result = findEnum(destination, "define_VALUE");
			assertNotNull("Actual destination enum must be populated", result);
			assertEquals("Same input path must identify the same category",
				existing.getCategoryPath(), result.getCategoryPath());
			System.out.println("DEFINE_ARCHIVE_PRIOR=" + oldName + ":" + oldValue +
				" RESULT=" + result.getValue("VALUE") + " WIDTH=" + result.getLength());
			assertEquals(expected, result.getValue("VALUE"));
			assertEquals(width, result.getLength());
		}
		finally {
			destination.close();
			archive.close();
			Files.deleteIfExists(file);
		}
	}

	private PreProcessor parse(Path file) throws Exception {
		PreProcessor processor = new PreProcessor(new String[0]);
		processor.setOutputStream(new ByteArrayOutputStream());
		assertTrue("Actual preprocessor must parse the header", processor.parse(file.toString()));
		return processor;
	}

	private Enum findEnum(DataTypeManager manager, String name) {
		Iterator<DataType> types = manager.getAllDataTypes();
		while (types.hasNext()) {
			DataType type = types.next();
			if (name.equals(type.getName())) {
				assertTrue(type instanceof Enum);
				return (Enum) type;
			}
		}
		return null;
	}
}
