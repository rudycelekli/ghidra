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
package ghidra.javaclass.test;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.junit.Test;

import db.Transaction;
import generic.test.AbstractGenericTest;
import ghidra.javaclass.format.DescriptorDecoder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Data;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;

public class JavaCharListingValueTest extends AbstractGenericTest {
	@Test
	public void testJvmHighBitCharacter() throws Exception {
		check("JVM:BE:32:default", '\u8000', false);
	}

	@Test
	public void testJvmMaximumCharacter() throws Exception {
		check("JVM:BE:32:default", '\uffff', false);
	}

	@Test
	public void testJvmSurrogateCodeUnit() throws Exception {
		check("JVM:BE:32:default", '\ud800', false);
	}

	@Test
	public void testDalvikHighBitCharacter() throws Exception {
		check("Dalvik:LE:32:DEX_Base", '\u8000', false);
	}

	@Test
	public void testJvmLowerBoundaryCharacter() throws Exception {
		check("JVM:BE:32:default", '\u7fff', false);
	}

	@Test
	public void testAsciiCharacter() throws Exception {
		check("JVM:BE:32:default", 'A', false);
	}

	@Test
	public void testExistingWideCharacterMaximum() throws Exception {
		check("Dalvik:LE:32:DEX_Base", '\uffff', true);
	}

	@Test
	public void testUnreadableCharacterHasNoValue() throws Exception {
		ProgramDB program = program("JVM:BE:32:default");
		try {
			Data data;
			try (Transaction tx = program.openTransaction("Create uninitialized Java char")) {
				Address address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
				program.getMemory().createUninitializedBlock("data", address, 2, false);
				data = program.getListing().createData(address,
					DescriptorDecoder.getDataTypeOfDescriptor("C", program.getDataTypeManager()));
			}
			assertEquals(2, data.getLength());
			assertNull(data.getValue());
		}
		finally {
			program.release(this);
		}
	}

	private ProgramDB program(String languageId) throws Exception {
		Language language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(languageId));
		ProgramDB program = new ProgramDB("Java char listing values", language,
			language.getDefaultCompilerSpec(), this);
		try {
			assertEquals(2, program.getDataTypeManager().getDataOrganization().getCharSize());
			assertFalse(program.getDataTypeManager().getDataOrganization().isSignedChar());
			return program;
		}
		catch (Error e) {
			program.release(this);
			throw e;
		}
	}

	private void check(String languageId, char expected, boolean wide) throws Exception {
		ProgramDB program = program(languageId);
		try {
			byte[] bytes = ByteBuffer.allocate(2)
				.order(program.getLanguage().isBigEndian() ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN)
				.putChar(expected).array();
			Data data;
			try (Transaction tx = program.openTransaction("Create Java char data")) {
				Address address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
				program.getMemory().createInitializedBlock("data", address,
					new ByteArrayInputStream(bytes), bytes.length, TaskMonitor.DUMMY, false);
				DataType type = wide ? WideCharDataType.dataType
						: DescriptorDecoder.getDataTypeOfDescriptor("C", program.getDataTypeManager());
				data = program.getListing().createData(address, type);
			}
			assertEquals(2, data.getLength());
			assertEquals(Character.valueOf(expected), data.getValue());
			assertArrayEquals(bytes, data.getBytes());
		}
		finally {
			program.release(this);
		}
	}
}
