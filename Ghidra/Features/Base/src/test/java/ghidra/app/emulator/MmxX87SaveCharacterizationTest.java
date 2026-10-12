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
package ghidra.app.emulator;

import static org.junit.Assert.*;

import java.io.File;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import org.junit.Test;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.framework.Application;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;

/** Fork-only MMX/x87 state observations through decoded instructions and FNSAVE. */
public class MmxX87SaveCharacterizationTest extends AbstractGhidraHeadlessIntegrationTest {

	@Test
	public void testPxorFirstRegister() throws Exception {
		check("PXOR", new byte[] { (byte) 0x0f, (byte) 0xef, (byte) 0xc0 }, 0, 0x0L);
	}

	@Test
	public void testPxorLastRegister() throws Exception {
		check("PXOR", new byte[] { (byte) 0x0f, (byte) 0xef, (byte) 0xff }, 7, 0x0L);
	}

	@Test
	public void testMovdRegisterTransfer() throws Exception {
		check("MOVD", new byte[] { (byte) 0x0f, (byte) 0x6e, (byte) 0xd0 }, 2, 0x12345678L);
	}

	@Test
	public void testPackedByteArithmetic() throws Exception {
		check("PADDB", new byte[] { (byte) 0x0f, (byte) 0xfc, (byte) 0xe5 }, 4, 0x20202020202020bL);
	}

	@Test
	public void testReversedMovqDestination() throws Exception {
		check("MOVQ", new byte[] { (byte) 0x0f, (byte) 0x7f, (byte) 0xee }, 6, 0x101010101010106L);
	}

	@Test
	public void testMovqMemoryReadControl() throws Exception {
		check("MOVQ", new byte[] { (byte) 0x0f, (byte) 0x7f, (byte) 0x05, (byte) 0xf9, (byte) 0x1f, (byte) 0x00, (byte) 0x00 }, -1, 0x0L);
	}

	@Test
	public void testEmmsControl() throws Exception {
		check("EMMS", new byte[] { (byte) 0x0f, (byte) 0x77 }, -1, 0x0L);
	}

	private void check(String mnemonic, byte[] operation, int destination, long result)
			throws Exception {
		ProgramBuilder builder = new ProgramBuilder("mmx-save", ProgramBuilder._X64);
		EmulatorHelper emulator = null;
		try {
			builder.createMemory("code", "0x1000", 0x100);
			builder.createMemory("fpu-save", "0x2000", 108);
			builder.createMemory("mmx-store", "0x3000", 8);
			byte[] instructions = new byte[operation.length + 6];
			System.arraycopy(operation, 0, instructions, 0, operation.length);
			instructions[operation.length] = (byte) 0xdd;
			instructions[operation.length + 1] = (byte) 0x35;
			ByteBuffer.wrap(instructions).order(ByteOrder.LITTLE_ENDIAN)
				.putInt(operation.length + 2, 0x2000 - (0x1000 + instructions.length));
			builder.setBytes("0x1000", instructions);
			builder.disassemble("0x1000", instructions.length);
			Program program = builder.getProgram();
			assertTrue(program.getLanguage() instanceof SleighLanguage);
			File actualSla = ((SleighLanguage) program.getLanguage()).getLanguageDescription()
				.getLanguageFile().getSlaFile().getFile(false);
			File expectedSla = new File(Application.getModuleRootDir("x86").getFile(false),
				"data/languages/x86-64.sla");
			assertEquals(expectedSla.getCanonicalFile(), actualSla.getCanonicalFile());
			assertTrue(actualSla.isFile());
			System.out.println("MMX_CURRENT_SLA mnemonic=" + mnemonic + " path=" + actualSla);
			assertEquals(mnemonic, program.getListing().getInstructionAt(builder.addr("0x1000"))
				.getMnemonicString());
			assertEquals("FNSAVE", program.getListing()
				.getInstructionAt(builder.addr("0x1000").add(operation.length)).getMnemonicString());
			emulator = new EmulatorHelper(program);
			for (int i = 0; i < 8; i++) {
				BigInteger seed = BigInteger.valueOf(0x1234 + i).shiftLeft(64)
					.or(BigInteger.valueOf(0x0101010101010101L + i));
				emulator.writeRegister("ST" + i, seed);
			}
			for (String name : new String[] { "FPUControlWord", "FPUStatusWord", "FPUTagWord",
				"FPUDataPointer", "FPUInstructionPointer", "FPULastInstructionOpcode" }) {
				emulator.writeRegister(name, 0);
			}
			emulator.writeRegister("RAX", 0x12345678L);
			emulator.writeRegister(emulator.getPCRegister(), 0x1000L);
			assertTrue(emulator.getLastError(), emulator.step(TaskMonitor.DUMMY));
			assertEquals(builder.addr("0x1000").add(operation.length), emulator.getExecutionAddress());
			assertTrue(emulator.getLastError(), emulator.step(TaskMonitor.DUMMY));
			assertEquals(builder.addr("0x1000").add(instructions.length), emulator.getExecutionAddress());
			byte[] saved = emulator.readMemory(builder.addr("0x2000"), 108);
			assertNotNull(saved);
			ByteBuffer image = ByteBuffer.wrap(saved).order(ByteOrder.LITTLE_ENDIAN);
			for (int i = 0; i < 8; i++) {
				assertEquals("FNSAVE low bits for register " + i,
					i == destination ? result : 0x0101010101010101L + i, image.getLong(28 + i * 10));
				if (i != destination) {
					assertEquals("Unwritten high bits for register " + i, 0x1234 + i,
						Short.toUnsignedInt(image.getShort(28 + i * 10 + 8)));
				}
			}
			if (destination >= 0) {
				int actual = Short.toUnsignedInt(image.getShort(28 + destination * 10 + 8));
				System.out.println("MMX_SAVE mnemonic=" + mnemonic + " destination=" + destination +
					" expectedHigh=65535 actualHigh=" + actual + " lowBits=true untouched=true");
				assertEquals("MMX writes set only the corresponding x87 high bits", 0xffff, actual);
			}
			else {
				if (mnemonic.equals("MOVQ")) {
					assertEquals(0x0101010101010101L, ByteBuffer
						.wrap(emulator.readMemory(builder.addr("0x3000"), 8))
						.order(ByteOrder.LITTLE_ENDIAN).getLong());
				}
				System.out.println("MMX_SAVE mnemonic=" + mnemonic +
					" destination=-1 highBits=unchanged lowBits=true untouched=true");
			}
		}
		finally {
			if (emulator != null) {
				emulator.dispose();
			}
			builder.dispose();
		}
	}
}
