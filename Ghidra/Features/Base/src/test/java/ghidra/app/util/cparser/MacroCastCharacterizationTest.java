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

import java.nio.file.*;
import java.util.*;

import org.junit.Test;

import ghidra.framework.Application;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.*;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;

/** Fork-only observations of casted macro values through complete header imports. */
public class MacroCastCharacterizationTest extends AbstractGhidraHeadlessIntegrationTest {
	@Test public void testAliasHighBit16() throws Exception { check(2, "((INT)0x8000)", -32768); }
	@Test public void testAliasHighBit32() throws Exception { check(4, "((INT)0x80000000)", -2147483648L); }
	@Test public void testBuiltinAllBits16() throws Exception { check(2, "((int)0xffff)", -1); }
	@Test public void testBuiltinAllBits32() throws Exception { check(4, "((int)0xffffffff)", -1); }
	@Test public void testUnsignedHighBit16Control() throws Exception { check(2, "((unsigned int)0x8000)", 32768); }
	@Test public void testUnsignedHighBit32Control() throws Exception { check(4, "((unsigned int)0x80000000)", 2147483648L); }
	@Test public void testUncastHighBitControl() throws Exception { check(4, "0x80000000", 2147483648L); }
	@Test public void testPositiveCastControl() throws Exception { check(4, "((int)127)", 127); }

	private void check(int intSize, String expression, long expected) throws Exception {
		String name = "MacroCast-" + UUID.randomUUID();
		ProgramBuilder builder = new ProgramBuilder(name,
			intSize == 2 ? ProgramBuilder._X86_16_REAL_MODE : ProgramBuilder._X86);
		Path directory = Files.createTempDirectory("macro-cast-");
		Path output = Path.of(Application.getUserTempDirectory().getAbsolutePath(), name + "_CParser.out");
		try {
			DataTypeManager manager = builder.getProgram().getDataTypeManager();
			assertEquals(intSize, manager.getDataOrganization().getIntegerSize());
			Path header = directory.resolve("cast.h");
			Files.writeString(header, "typedef int INT;\n#define CAST_VALUE " + expression + "\n");
			CParserUtils.CParseResults result = CParserUtils.parseHeaderFiles(null,
				new String[] { header.toString() }, new String[0], new String[0], manager, TaskMonitor.DUMMY);
			assertTrue("Complete public header import must succeed: " + result.cParseMessages(), result.successful());
			DataType alias = null;
			ghidra.program.model.data.Enum value = null;
			Iterator<DataType> types = manager.getAllDataTypes();
			while (types.hasNext()) {
				DataType type = types.next();
				if (type.getName().equals("INT")) { assertNull(alias); alias = type; }
				if (type.getName().equals("define_CAST_VALUE")) {
					assertNull(value);
					assertTrue(type instanceof ghidra.program.model.data.Enum);
					value = (ghidra.program.model.data.Enum) type;
				}
			}
			assertTrue("Same-header INT typedef must actually be parsed", alias instanceof TypeDef);
			assertEquals(intSize, ((TypeDef) alias).getBaseDataType().getLength());
			assertNotNull("Actual macro equate must be persisted", value);
			long actual = value.getValue("CAST_VALUE");
			System.out.println("MACRO_CAST intSize=" + intSize + " expression=" + expression +
				" expected=" + expected + " actual=" + actual + " width=" + value.getLength());
			assertEquals(expected, actual);
		}
		finally {
			builder.dispose();
			Files.deleteIfExists(output);
			try (var files = Files.walk(directory)) {
				for (Path file : files.sorted(Comparator.reverseOrder()).toList()) { Files.delete(file); }
			}
		}
	}
}
