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

import org.junit.Test;

import ghidra.app.util.cparser.C.CParser;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Enum;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

/** Characterizes declared-width enums through the public header parser. */
public class DeclaredWideEnumCharacterizationTest extends AbstractGhidraHeadlessIntegrationTest {

	@Test
	public void testWideUnsignedAndImplicitNext() throws Exception {
		check("unsigned long long", "WIDE=0x100000000ULL, NEXT", new String[] { "WIDE", "NEXT" },
			new long[] { 4294967296L, 4294967297L });
	}

	@Test
	public void testWideSignedNegative() throws Exception {
		check("long long", "VALUE=-0x100000001LL", new String[] { "VALUE" },
			new long[] { -4294967297L });
	}

	@Test
	public void testShiftedWideConstant() throws Exception {
		check("unsigned long long", "VALUE=1ULL << 40", new String[] { "VALUE" },
			new long[] { 1099511627776L });
	}

	@Test
	public void testHighSignedConstant() throws Exception {
		check("long long", "VALUE=0x7fffffff00000000LL", new String[] { "VALUE" },
			new long[] { 9223372032559808512L });
	}

	@Test
	public void testSignedMinimum() throws Exception {
		check("long long", "VALUE=(-9223372036854775807LL - 1)", new String[] { "VALUE" },
			new long[] { Long.MIN_VALUE });
	}

	@Test
	public void testImplicitCrossesSignedIntBoundary() throws Exception {
		check("unsigned long long", "FIRST=0x7fffffff, SECOND", new String[] { "FIRST", "SECOND" },
			new long[] { 2147483647L, 2147483648L });
	}

	@Test
	public void testSmallEightByteControl() throws Exception {
		check("unsigned long long", "FIRST=42, SECOND", new String[] { "FIRST", "SECOND" },
			new long[] { 42L, 43L });
	}

	@Test
	public void testOrdinaryIntControl() throws Exception {
		check("int", "FIRST=-1, SECOND, LAST=2147483647", new String[] { "FIRST", "SECOND", "LAST" },
			new long[] { -1L, 0L, 2147483647L });
	}

	@Test
	public void testUnsignedMaximumRawBitsControl() throws Exception {
		check("unsigned long long", "VALUE=0xffffffffffffffffULL", new String[] { "VALUE" },
			new long[] { -1L });
	}

	private void check(String underlying, String members, String[] names, long[] expected)
			throws Exception {
		CParser parser = new CParser();
		try {
			DataType parsed = parser.parse("enum Wide : " + underlying + " { " + members + " };");
			assertTrue(parsed instanceof Enum);
			Enum result = (Enum) parsed;
			assertEquals(underlying.equals("int") ? 4 : 8, result.getLength());
			assertEquals(names.length, result.getCount());
			for (int i = 0; i < names.length; i++) {
				long actual = result.getValue(names[i]);
				System.out.println("ENUM_WIDTH member=" + names[i] + " expected=" + expected[i] +
					" actual=" + actual + " length=" + result.getLength());
				assertEquals(names[i], expected[i], actual);
			}
		}
		finally {
			parser.getDataTypeManager().close();
		}
	}
}
