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
package ghidra.program.model.lang;

import static org.junit.Assert.*;

import java.util.Arrays;

import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

/** Fork-only observations of actual ARM dynamic scalar parameter storage. */
public class ArmParameterCapacityCharacterizationTest extends AbstractGhidraHeadlessIntegrationTest {
	@Test
	public void testHardFloat129Control() throws Exception { check("__stdcall", 129); }
	@Test
	public void testSoftFloat129Control() throws Exception { check("__stdcall_softfp", 129); }
	@Test
	public void testHardFloat130Parameters() throws Exception { check("__stdcall", 130); }
	@Test
	public void testSoftFloat130Parameters() throws Exception { check("__stdcall_softfp", 130); }
	@Test
	public void testHardFloat185Parameters() throws Exception { check("__stdcall", 185); }
	@Test
	public void testSoftFloat185Parameters() throws Exception { check("__stdcall_softfp", 185); }

	private void check(String convention, int count) throws Exception {
		ProgramBuilder builder = new ProgramBuilder("ArmParameterCapacity", ProgramBuilder._ARM);
		try {
			Program program = builder.getProgram();
			PrototypeModel model = program.getCompilerSpec().getCallingConvention(convention);
			assertNotNull(model);
			DataType[] types = new DataType[count + 1];
			Arrays.fill(types, IntegerDataType.dataType.clone(program.getDataTypeManager()));
			types[0] = VoidDataType.dataType;
			assertEquals(4, types[1].getLength());
			VariableStorage[] storage = model.getStorageLocations(program, types, false, true);
			assertEquals(count + 1, storage.length);
			assertTrue(storage[0].isVoidStorage());
			int assigned = 0;
			for (int ordinal = 0; ordinal < count; ordinal++) {
				VariableStorage actual = storage[ordinal + 1];
				if (actual.isUnassignedStorage()) {
					continue;
				}
				assigned++;
				assertEquals(4, actual.size());
				assertEquals(1, actual.getVarnodes().length);
				if (ordinal < 4) {
					assertEquals(program.getRegister("r" + ordinal).getAddress(),
						actual.getVarnodes()[0].getAddress());
				}
				else {
					assertTrue(actual.isStackStorage());
					assertEquals((ordinal - 4) * 4L, actual.getStackOffset());
				}
			}
			System.out.println("ARM_PARAMETER_STORAGE convention=" + convention + " count=" +
				count + " assigned=" + assigned);
			assertEquals("All declared scalar parameters require storage", count, assigned);
		}
		finally {
			builder.dispose();
		}
	}
}
