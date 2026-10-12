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
package ghidra.app.plugin.core.decompile;

import static org.junit.Assert.*;

import java.io.File;
import java.lang.reflect.Field;
import java.util.ArrayList;
import org.junit.Test;

import ghidra.app.decompiler.*;
import ghidra.app.plugin.core.decompile.actions.ConvertCharAction;
import ghidra.framework.Application;
import ghidra.framework.Platform;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.test.*;
import ghidra.util.task.TaskMonitor;

/** Fork-only characterization of genuine listing equates consumed by the native decompiler. */
public class QuotedEquateCharacterizationTest extends AbstractGhidraHeadedIntegrationTest {
	@Test
	public void testSingleQuoteCustomNameRemainsSymbol() throws Exception {
		check("'CUSTOM", false);
	}

	@Test
	public void testDoubleQuoteCustomNameRemainsSymbol() throws Exception {
		check("\"CUSTOM", false);
	}

	@Test
	public void testOrdinaryCustomNameControl() throws Exception {
		check("CUSTOM", false);
	}

	@Test
	public void testActualCharacterConversionControl() throws Exception {
		check(null, true);
	}

	private void check(String requestedName, boolean character) throws Exception {
		ProgramBuilder builder = new ProgramBuilder("equate", ProgramBuilder._X86);
		TestEnv env = null;
		DecompInterface decompiler = new DecompInterface();
		try {
			builder.createMemory("code", "0x1000", 0x100);
			builder.setBytes("0x1000", "b8 41 00 00 00 c3");
			builder.disassemble("0x1000", 6);
			Program program = builder.getProgram();
			Function function = program.getFunctionManager().getFunctionAt(builder.addr("0x1000"));
			if (function == null) {
				function = builder.createFunction("0x1000");
			}
			assertNotNull(function);
			assertEquals(6L, function.getBody().getNumAddresses());
			Instruction instruction = program.getListing().getInstructionAt(builder.addr("0x1000"));
			Scalar scalar = instruction.getScalar(1);
			assertNotNull("Real MOV immediate operand must be available", scalar);
			assertEquals(65L, scalar.getUnsignedValue());
			String name = requestedName;
			String characterLiteral = null;
			if (character) {
				env = new TestEnv();
				env.getTool().addPlugin(DecompilePlugin.class.getName());
				DecompilePlugin plugin = getPlugin(env.getTool(), DecompilePlugin.class);
				ConvertCharAction action = new ConvertCharAction(plugin);
				name = action.getEquateName(scalar, program);
				characterLiteral = action.getMenuDisplay(scalar, program);
				assertNotNull(name);
			}
			int transaction = program.startTransaction("Apply actual listing equate");
			try {
				function.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
				Equate equate = program.getEquateTable().createEquate(name, 65);
				equate.addReference(instruction.getAddress(), 1);
				assertEquals(name, equate.getDisplayName());
				assertEquals(name, program.getEquateTable().getEquate(name).getName());
				assertEquals(1, equate.getReferences(instruction.getAddress()).size());
			}
			finally {
				program.endTransaction(transaction, true);
			}
			assertTrue(decompiler.openProgram(program));
			DecompileResults result = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
			assertTrue(result.getErrorMessage(), result.decompileCompleted());
			assertNotNull(result.getHighFunction());
			assertNotNull(result.getDecompiledFunction());
			assertCurrentNative();
			ArrayList<EquateSymbol> symbols = new ArrayList<>();
			result.getHighFunction().getLocalSymbolMap().getSymbols().forEachRemaining(symbol -> {
				if (symbol instanceof EquateSymbol equate && equate.getValue() == 65) {
					symbols.add(equate);
				}
			});
			assertEquals("Actual native equate symbol must be returned", 1, symbols.size());
			EquateSymbol actual = symbols.get(0);
			String code = result.getDecompiledFunction().getC();
			System.out.println("ACTUAL_QUOTED_EQUATE requested=" + name + " character=" + character +
				" convert=" + actual.getConvert() + " name=" + actual.getName() + " c=" + code);
			assertEquals(character ? EquateSymbol.FORMAT_CHAR : EquateSymbol.FORMAT_DEFAULT,
				actual.getConvert());
			if (character) {
				assertTrue("Native rendered C must preserve actual character conversion",
					code.contains(characterLiteral));
			}
			else {
				assertEquals(name, actual.getName());
				assertTrue("Native rendered C must preserve custom equate", code.contains(name));
			}
		}
		finally {
			decompiler.dispose();
			if (env != null) {
				env.dispose();
			}
			builder.dispose();
		}
	}

	private void assertCurrentNative() throws Exception {
		Field path = DecompileProcessFactory.class.getDeclaredField("exepath");
		path.setAccessible(true); // Read-only current executable inspection.
		File actual = new File((String) path.get(null));
		File expected = new File(Application.getModuleRootDir("Decompiler").getFile(false),
			"build/os/" + Platform.CURRENT_PLATFORM.getDirectoryName() + "/decompile");
		assertEquals(expected.getCanonicalFile(), actual.getCanonicalFile());
		assertTrue(actual.isFile());
		System.out.println("QUOTED_EQUATE_CURRENT_NATIVE path=" + actual);
	}
}
