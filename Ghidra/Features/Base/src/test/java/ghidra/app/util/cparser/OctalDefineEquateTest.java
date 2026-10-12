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
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Enum;
import ghidra.program.database.data.TransientDataTypeManager;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

public class OctalDefineEquateTest extends AbstractGhidraHeadlessIntegrationTest {
	@Test
	public void testOctalOrExpression() throws Exception {
		assertDefineValue("#define VALUE (010 | 1)\n", 9);
	}

	@Test
	public void testOctalShiftExpression() throws Exception {
		assertDefineValue("#define VALUE (010 << 1)\n", 16);
	}

	@Test
	public void testOctalAdditionExpression() throws Exception {
		assertDefineValue("#define VALUE (010 + 1)\n", 9);
	}

	@Test
	public void testExpandedOctalExpression() throws Exception {
		assertDefineValue("#define OCTAL 010\n#define VALUE (OCTAL | 1)\n", 9);
	}

	@Test
	public void testSingleOctalLiteralControl() throws Exception {
		assertDefineValue("#define VALUE 011\n", 9);
	}

	@Test
	public void testDecimalAndHexExpressionControl() throws Exception {
		assertDefineValue("#define VALUE (10 | 0x1)\n", 11);
	}

	private void assertDefineValue(String header, long expected) throws Exception {
		Path file = Files.createTempFile("ghidra-octal-define-", ".h");
		TransientDataTypeManager manager = new TransientDataTypeManager("octal");
		try {
			Files.writeString(file, header);
			PreProcessor processor = new PreProcessor(new String[0]);
			processor.setOutputStream(new ByteArrayOutputStream());
			assertTrue("Actual C preprocessor must parse the fixture", processor.parse(file.toString()));
			processor.getDefinitions().populateDefineEquates(null, manager);
			Iterator<DataType> types = manager.getAllDataTypes();
			Enum value = null;
			while (types.hasNext()) {
				DataType type = types.next();
				if (type.getName().equals("define_VALUE")) {
					assertTrue(type instanceof Enum);
					value = (Enum) type;
				}
			}
			assertNotNull("Actual define equate must be populated", value);
			assertEquals(expected, value.getValue("VALUE"));
		}
		finally {
			manager.close();
			Files.deleteIfExists(file);
		}
	}
}
