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

import java.io.ByteArrayOutputStream;
import java.util.Base64;

import org.junit.Test;

import ghidra.program.model.pcode.PackedEncode;
import ghidra.xml.*;

/** Original allocation and packed encoding remain identical without the opt-in. */
public class ArmBoundedAllocationCompatibilityTest extends AbstractProtoModelTest {
	@Test
	public void testOriginalBoundedEncodingAndStorage() throws Exception {
		buildArchitecture("ARM:LE:32:v7:default");
		XmlPullParser parser = XmlPullParserFactory.create(
			"<input><pentry minsize=\"1\" maxsize=\"500\" align=\"4\">" +
			"<addr space=\"stack\" offset=\"0\"/></pentry></input>",
			"bounded-compatibility", null, false);
		try {
			ParamListStandard resources = new ParamListStandard();
			resources.restoreXml(parser, cspec);
			ParameterPieces last = new ParameterPieces();
			assertEquals(125, resources.getStackEntry().getAddrBySlot(124, 4, 4, last));
			assertEquals(496, last.address.getOffset());
			ParameterPieces beyond = new ParameterPieces();
			assertEquals(125, resources.getStackEntry().getAddrBySlot(125, 4, 4, beyond));
			assertNull(beyond.address);
			ByteArrayOutputStream bytes = new ByteArrayOutputStream();
			resources.encode(new PackedEncode(bytes), true);
			System.out.println("ARM_BOUNDED_PACKED=" +
				Base64.getEncoder().encodeToString(bytes.toByteArray()));
		}
		finally {
			parser.dispose();
		}
	}
}
