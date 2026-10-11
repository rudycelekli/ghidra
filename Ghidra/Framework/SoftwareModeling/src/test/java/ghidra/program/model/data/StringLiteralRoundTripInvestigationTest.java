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

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import org.junit.Test;

import generic.test.AbstractGTest;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.data.RenderUnicodeSettingsDefinition.RENDER_ENUM;
import ghidra.program.model.mem.ByteMemBufferImpl;

public class StringLiteralRoundTripInvestigationTest extends AbstractGTest {
	@Test
	public void testLiteralSupplementaryUtf16RoundTrip() throws Exception {
		for (boolean bigEndian : new boolean[] { false, true }) {
			check(new UnicodeDataType(), "a\ud83d\ude00z", bigEndian,
				bigEndian ? StandardCharsets.UTF_16BE : StandardCharsets.UTF_16LE);
		}
	}

	@Test
	public void testLiteralSupplementaryUtf8RoundTrip() throws Exception {
		check(new StringUTF8DataType(), "a\ud83d\ude00z", false, StandardCharsets.UTF_8);
	}

	@Test
	public void testLiteralBmpUtf16RoundTrip() throws Exception {
		check(new UnicodeDataType(), "a\u03a9z", false, StandardCharsets.UTF_16LE);
	}

	@Test
	public void testAsciiRoundTrip() throws Exception {
		check(new StringDataType(), "hello", false, StandardCharsets.US_ASCII);
	}

	private void check(AbstractStringDataType type, String value, boolean bigEndian,
			Charset charset) throws Exception {
		byte[] original = value.getBytes(charset);
		SettingsBuilder settings = new SettingsBuilder().set(RENDER_ENUM.ALL);
		String representation = type.getRepresentation(buffer(bigEndian, original), settings, original.length);
		assertTrue("Actual rendered representation must contain the original literal characters", representation.contains(value));
		System.out.println("STRING_LITERAL_RENDERED type=" + type.getName() + " chars=" + value.length());
		assertArrayEquals(original, type.encodeRepresentation(representation, buffer(bigEndian, original), settings, original.length));
	}

	private ByteMemBufferImpl buffer(boolean bigEndian, byte[] bytes) {
		GenericAddressSpace space = new GenericAddressSpace("test", 32, AddressSpace.TYPE_RAM, 1);
		return new ByteMemBufferImpl(space.getAddress(0), bytes, bigEndian);
	}
}
