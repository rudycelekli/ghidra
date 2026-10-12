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
import java.util.Iterator;

import org.junit.Test;

import ghidra.app.decompiler.*;
import ghidra.framework.Application;
import ghidra.framework.Platform;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;

/** Fork-only observations of a genuine persisted ARM call-site signature override. */
public class ArmOverrideCapacityCharacterizationTest extends AbstractGhidraHeadlessIntegrationTest {
	@Test
	public void test129OverrideControl() throws Exception { check(129); }
	@Test
	public void test130Override() throws Exception { check(130); }
	@Test
	public void test185Override() throws Exception { check(185); }

	private void check(int count) throws Exception {
		ProgramBuilder builder = new ProgramBuilder("ArmOverrideCapacity", ProgramBuilder._ARM);
		DecompInterface decompiler = new DecompInterface();
		try {
			builder.createMemory("code", "0x1000", 0x200);
			// A32: PUSH {lr}; BL 0x1100; POP {pc}. Callee: BX lr.
			builder.setBytes("0x1000", "04 e0 2d e5 3d 00 00 eb 04 f0 9d e4");
			builder.setBytes("0x1100", "1e ff 2f e1");
			Function caller = builder.createEmptyFunction("caller", "0x1000", 12, VoidDataType.dataType);
			Function callee = builder.createEmptyFunction("callee", "0x1100", 4, VoidDataType.dataType);
			builder.disassemble("0x1000", 12);
			builder.disassemble("0x1100", 4);
			Program program = builder.getProgram();
			Address callsite = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1004);
			Instruction call = program.getListing().getInstructionAt(callsite);
			assertNotNull(call);
			assertTrue(call.getFlowType().isCall());
			assertArrayEquals(new Address[] { callee.getEntryPoint() }, call.getFlows());
			FunctionDefinitionDataType signature = new FunctionDefinitionDataType("override", program.getDataTypeManager());
			signature.setReturnType(VoidDataType.dataType);
			signature.setCallingConvention("__stdcall_softfp");
			signature.setVarArgs(true);
			ParameterDefinition[] parameters = new ParameterDefinition[count];
			for (int i = 0; i < count; i++) {
				parameters[i] = new ParameterDefinitionImpl("p" + i, IntegerDataType.dataType, null);
			}
			signature.setArguments(parameters);
			int transaction = program.startTransaction("public call-site override");
			try { HighFunctionDBUtil.writeOverride(caller, callsite, signature); }
			finally { program.endTransaction(transaction, true); }
			Namespace space = HighFunction.findOverrideSpace(caller);
			assertNotNull(space);
			int persisted = 0;
			SymbolIterator symbols = program.getSymbolTable().getSymbols(space);
			while (symbols.hasNext()) {
				Symbol symbol = symbols.next();
				DataTypeSymbol override = HighFunctionDBUtil.readOverride(symbol);
				if (override != null) {
					assertEquals(callsite, symbol.getAddress());
					FunctionDefinition stored = (FunctionDefinition) override.getDataType();
					assertEquals(count, stored.getArguments().length);
					assertTrue(stored.hasVarArgs());
					assertEquals("__stdcall_softfp", stored.getCallingConventionName());
					persisted++;
				}
			}
			assertEquals(1, persisted);
			assertTrue(decompiler.openProgram(program));
			Field path = DecompileProcessFactory.class.getDeclaredField("exepath");
			path.setAccessible(true); // Read-only current executable inspection.
			File actual = new File((String) path.get(null));
			File expected = new File(Application.getModuleRootDir("Decompiler").getFile(false),
				"build/os/" + Platform.CURRENT_PLATFORM.getDirectoryName() + "/decompile");
			assertEquals(expected.getCanonicalFile(), actual.getCanonicalFile());
			System.out.println("ARM_OVERRIDE_PRODUCER count=" + count + " persisted=" + persisted +
				" callsite=" + callsite + " native=" + actual);
			DecompileResults result = decompiler.decompileFunction(caller, 60, TaskMonitor.DUMMY);
			if (!result.decompileCompleted()) {
				assertTrue("Only the reported parameter assignment failure is a target outcome: " + result.getErrorMessage(),
					result.getErrorMessage().contains("Cannot assign parameter address"));
			}
			System.out.println("ARM_OVERRIDE_OUTCOME count=" + count + " completed=" + result.decompileCompleted() +
				" error=" + result.getErrorMessage());
			assertTrue("Actual override must decompile", result.decompileCompleted());
			int calls = 0;
			Iterator<PcodeOpAST> operations = result.getHighFunction().getPcodeOps(callsite);
			while (operations.hasNext()) {
				PcodeOpAST op = operations.next();
				if (op.getOpcode() == PcodeOp.CALL) {
					assertEquals(count + 1, op.getNumInputs());
					calls++;
				}
			}
			assertEquals(1, calls);
		}
		finally {
			decompiler.dispose();
			builder.dispose();
		}
	}
}
