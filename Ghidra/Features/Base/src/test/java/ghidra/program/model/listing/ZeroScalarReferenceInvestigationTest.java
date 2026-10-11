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
package ghidra.program.model.listing;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

import db.Transaction;
import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

public class ZeroScalarReferenceInvestigationTest extends AbstractGenericTest {
	@Test
	public void testZeroOffsetMemoryReference() throws Exception {
		check(0, true);
	}

	@Test
	public void testNonzeroOffsetMemoryReferenceControl() throws Exception {
		check(1, true);
	}

	@Test
	public void testZeroWithoutReferenceControl() throws Exception {
		check(0, false);
	}

	@Test
	public void testNonzeroWithoutReferenceControl() throws Exception {
		check(1, false);
	}

	private void check(int offset, boolean referenced) throws Exception {
		ProgramBuilder builder = new ProgramBuilder("Zero scalar", ProgramBuilder._X86_16_REAL_MODE);
		try {
			builder.createMemory("code", "0000:0100", 4);
			builder.createMemory("data", "2000:0000", 2);
			builder.setBytes("0000:0100", offset == 0 ? "8b 06 00 00" : "8b 06 01 00");
			builder.disassemble("0000:0100", 4, false);
			ProgramDB program = builder.getProgram();
			Address from = program.getAddressFactory().getAddress("0000:0100");
			Address target = program.getAddressFactory().getAddress(offset == 0 ? "2000:0000" : "2000:0001");
			Instruction instruction = program.getListing().getInstructionAt(from);
			assertNotNull(instruction);
			assertEquals("MOV", instruction.getMnemonicString());
			List<Object> raw = instruction.getDefaultOperandRepresentationList(1);
			assertNotNull(raw);
			assertEquals(1, raw.stream().filter(Scalar.class::isInstance).count());
			assertFalse(raw.stream().anyMatch(Address.class::isInstance));
			Scalar scalar = (Scalar) raw.stream().filter(Scalar.class::isInstance).findFirst().get();
			assertEquals(offset, scalar.getUnsignedValue());
			try (Transaction tx = program.openTransaction("Create authentic operand reference")) {
				program.getReferenceManager().removeAllReferencesFrom(from);
				if (referenced) {
					program.getSymbolTable().createLabel(target, "segment_target", SourceType.USER_DEFINED);
					Reference ref = program.getReferenceManager().addMemoryReference(from, target,
						RefType.READ, SourceType.USER_DEFINED, 1);
					program.getReferenceManager().setPrimary(ref, true);
				}
			}
			assertEquals(referenced, instruction.getPrimaryReference(1) != null);
			String formatted = CodeUnitFormat.DEFAULT.getOperandRepresentationString(instruction, 1);
			System.out.println("ZERO_SCALAR_ACTUAL offset=" + offset + " referenced=" + referenced +
				" raw=" + raw + " formatted=" + formatted);
			if (referenced) {
				assertTrue(formatted, formatted.contains("segment_target"));
			}
			else {
				assertFalse(formatted, formatted.contains("segment_target"));
			}
		}
		finally {
			builder.dispose();
		}
	}
}
