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
package ghidra.program.model.data;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.junit.Test;

import db.Transaction;
import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.RGB16EncodingSettingsDefinition.RGB16Encoding;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Data;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;

public class RGB16ListingValueTest extends AbstractGenericTest {
	@Test
	public void testPureGreenLittleEndian() throws Exception {
		check(false, RGB16Encoding.RGB_565, 0x07e0, 0xff00ff00, "G:3Fh");
	}

	@Test
	public void testPureRedBigEndianHasNoGreen() throws Exception {
		check(true, RGB16Encoding.RGB_565, 0xf800, 0xffff0000, "G:0h");
	}

	@Test
	public void testLeastGreenBitLittleEndian() throws Exception {
		check(false, RGB16Encoding.RGB_565, 0x0020, 0xff000400, "G:1h");
	}

	@Test
	public void testPureGreenBigEndianRepresentation() throws Exception {
		check(true, RGB16Encoding.RGB_565, 0x07e0, 0xff00ff00, "G:3Fh");
	}

	@Test
	public void testRgb555GreenControl() throws Exception {
		check(false, RGB16Encoding.RGB_555, 0x03e0, 0xff00ff00, "G:1Fh");
	}

	@Test
	public void testArgb1555GreenControl() throws Exception {
		check(true, RGB16Encoding.ARGB_1555, 0x83e0, 0xff00ff00, "G:1Fh");
	}

	@Test
	public void testPureBlueControl() throws Exception {
		check(false, RGB16Encoding.RGB_565, 0x001f, 0xff0000ff, "G:0h");
	}

	@Test
	public void testUninitializedColorHasNoValue() throws Exception {
		ProgramDB program = program(false);
		try {
			Data data;
			try (Transaction tx = program.openTransaction("Create unreadable color")) {
				Address address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
				program.getMemory().createUninitializedBlock("color", address, 2, false);
				data = program.getListing().createData(address, RGB16ColorDataType.datatype);
			}
			assertNull(data.getValue());
			assertEquals("??", data.getDefaultValueRepresentation());
		}
		finally {
			program.release(this);
		}
	}

	private void check(boolean bigEndian, RGB16Encoding encoding, int pixel, int argb,
			String greenRepresentation) throws Exception {
		ProgramDB program = program(bigEndian);
		try {
			byte[] bytes = ByteBuffer.allocate(2)
				.order(bigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN)
				.putShort((short) pixel).array();
			Data data;
			try (Transaction tx = program.openTransaction("Create actual color listing")) {
				Address address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
				program.getMemory().createInitializedBlock("color", address,
					new ByteArrayInputStream(bytes), bytes.length, TaskMonitor.DUMMY, false);
				DataType type = encoding == RGB16Encoding.RGB_565 ? RGB16ColorDataType.datatype
						: RGB16ColorDataType.createRGB16Typedef(encoding);
				data = program.getListing().createData(address, type);
			}
			assertEquals(2, data.getLength());
			assertArrayEquals(bytes, data.getBytes());
			// These are the actual icon and text consumed by the Listing operand field.
			ColorIcon icon = (ColorIcon) data.getValue();
			assertNotNull(icon);
			assertEquals(argb, icon.getRGBValue());
			String representation = data.getDefaultValueRepresentation();
			assertTrue(representation, representation.startsWith(encoding.name() + " "));
			assertTrue(representation, representation.contains(greenRepresentation));
		}
		finally {
			program.release(this);
		}
	}

	private ProgramDB program(boolean bigEndian) throws Exception {
		Language language = DefaultLanguageService.getLanguageService()
			.getLanguage(new LanguageID("Toy:" + (bigEndian ? "BE" : "LE") + ":32:default"));
		return new ProgramDB("RGB16 listing", language, language.getDefaultCompilerSpec(), this);
	}
}
