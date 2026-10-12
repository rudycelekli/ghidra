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
import java.util.Locale;
import org.junit.Test;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.framework.Application;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Instruction;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;

/** MMX destination state observed through decoded instructions and the saved x87 image. */
public class MmxX87StateTest extends AbstractGhidraHeadlessIntegrationTest {

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

	@Test
	public void testSignedMaximumConditionalWrite() throws Exception {
		check("PMAXSW", new byte[] { 0x0f, (byte) 0xee, (byte) 0xdc }, 3, 0x0101010101010105L);
	}

	@Test
	public void testUnsignedMaximumConditionalWrite() throws Exception {
		check("PMAXUB", new byte[] { 0x0f, (byte) 0xde, (byte) 0xdc }, 3, 0x0101010101010105L);
	}

	@Test
	public void testSignedMinimumUnchangedLowBits() throws Exception {
		check("PMINSW", new byte[] { 0x0f, (byte) 0xea, (byte) 0xdc }, 3, 0x0101010101010104L);
	}

	@Test
	public void testUnsignedMinimumUnchangedLowBits() throws Exception {
		check("PMINUB", new byte[] { 0x0f, (byte) 0xda, (byte) 0xdc }, 3, 0x0101010101010104L);
	}

	@Test
	public void testEveryRegisterDestinationMapping() throws Exception {
		for (int i = 0; i < 8; i++) {
			check("PXOR", new byte[] { 0x0f, (byte) 0xef, (byte) (0xc0 + 9 * i) }, i, 0);
		}
	}

	@Test
	public void testEveryReversedDestinationMapping() throws Exception {
		for (int i = 0; i < 8; i++) {
			check("MOVQ", new byte[] { 0x0f, 0x7f, (byte) (0xc8 + i) }, i,
				0x0101010101010102L);
		}
	}

	@Test
	public void testMemorySourceWrite() throws Exception {
		check("MOVQ", new byte[] { 0x0f, 0x6f, 0x05, (byte) 0xf9, 0x1f, 0x00, 0x00 }, 0, 0);
	}

	@Test
	public void testMovdReadControl() throws Exception {
		check("MOVD", new byte[] { 0x0f, 0x7e, (byte) 0xc8 }, -1, 0);
	}

	@Test
	public void testMaskReadControl() throws Exception {
		check("PMOVMSKB", new byte[] { 0x0f, (byte) 0xd7, (byte) 0xc1 }, -1, 0);
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
			Instruction instruction = program.getListing().getInstructionAt(builder.addr("0x1000"));
			assertEquals(mnemonic, instruction.getMnemonicString());
			assertEquals(operation.length, instruction.getLength());
			assertArrayEquals(operation, instruction.getBytes());
			if (destination >= 0) {
				assertEquals("MM" + destination,
					instruction.getDefaultOperandRepresentation(0).toUpperCase(Locale.ROOT));
			}
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
				if (mnemonic.equals("MOVD")) {
					assertEquals(0x01010102L, emulator.readRegister("RAX").longValue());
				}
				if (mnemonic.equals("PMOVMSKB")) {
					assertEquals(0L, emulator.readRegister("RAX").longValue());
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
