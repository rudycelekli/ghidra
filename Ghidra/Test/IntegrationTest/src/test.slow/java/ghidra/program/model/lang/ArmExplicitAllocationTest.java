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
import java.util.Arrays;

import org.junit.*;

import ghidra.program.model.data.*;
import ghidra.program.model.lang.protorules.*;
import ghidra.program.model.pcode.PackedEncode;
import ghidra.program.model.pcode.XmlEncode;
import ghidra.xml.*;

/** Contracts for explicit allocation that retain the separate bounded recognition range. */
public class ArmExplicitAllocationTest extends AbstractProtoModelTest {
	private static final String REGISTER =
		"<pentry minsize=\"1\" maxsize=\"4\"><register name=\"r0\"/></pentry>";
	private static final String STACK =
		"<pentry minsize=\"1\" maxsize=\"500\" align=\"4\" allocation=\"unbounded\">" +
		"<addr space=\"stack\" offset=\"0\"/></pentry>";

	@Before
	public void setUp() throws Exception {
		buildArchitecture("ARM:LE:32:v7:default");
	}

	private ParamListStandard list(String xml) throws Exception {
		XmlPullParser parser = XmlPullParserFactory.create(xml, "allocation-contract", null, false);
		try {
			ParamListStandard result = new ParamListStandard();
			result.restoreXml(parser, cspec);
			return result;
		}
		finally {
			parser.dispose();
		}
	}

	private ParamEntry stack() throws Exception {
		return list("<input>" + STACK + "</input>").getStackEntry();
	}

	private ParameterPieces sentinel() {
		ParameterPieces result = new ParameterPieces();
		result.address = language.getRegister("r0").getAddress();
		result.type = CharDataType.dataType;
		result.hiddenReturnPtr = true;
		return result;
	}

	@Test
	public void testAllocationExceedsRecognitionWithoutExpandingIt() throws Exception {
		ParamEntry entry = stack();
		ParameterPieces result = sentinel();
		assertEquals(182, entry.getAllocationAddrBySlot(181, 4, 4, result));
		assertEquals(724, result.address.getOffset());
		assertEquals(500, entry.getSize());
		ParameterPieces recognized = new ParameterPieces();
		assertEquals(181, entry.getAddrBySlot(181, 4, 4, recognized));
		assertNull(recognized.address);
	}

	@Test
	public void testAlignmentAndRightJustification() throws Exception {
		ParamEntry entry = stack();
		ParameterPieces result = new ParameterPieces();
		assertEquals(4, entry.getAllocationAddrBySlot(1, 8, 8, result));
		assertEquals(8, result.address.getOffset());
		assertEquals(5, entry.getAllocationAddrBySlot(4, 1, 1, result, true));
		assertEquals(19, result.address.getOffset());
	}

	@Test
	public void testLastSignedStackByteAndOverflowRollback() throws Exception {
		ParamEntry entry = stack();
		ParameterPieces result = sentinel();
		assertEquals(536870912, entry.getAllocationAddrBySlot(536870911, 4, 4, result));
		assertEquals(2147483644L, result.address.getOffset());
		ParameterPieces before = sentinel();
		assertEquals(-1, entry.getAllocationAddrBySlot(536870912, 1, 1, before));
		assertEquals(language.getRegister("r0").getAddress(), before.address);
		assertSame(CharDataType.dataType, before.type);
		assertTrue(before.hiddenReturnPtr);
	}

	@Test
	public void testInvalidSizesAlignmentsAndSlotsPreserveResult() throws Exception {
		ParamEntry entry = stack();
		for (int[] args : new int[][] { { -1, 4, 4 }, { 0, 0, 4 }, { 0, -1, 4 },
			{ 0, 4, 0 }, { 0, 4, 3 }, { Integer.MAX_VALUE, 4, 4 } }) {
			ParameterPieces result = sentinel();
			assertEquals(Arrays.toString(args), -1,
				entry.getAllocationAddrBySlot(args[0], args[1], args[2], result));
			assertEquals(language.getRegister("r0").getAddress(), result.address);
			assertSame(CharDataType.dataType, result.type);
			assertTrue(result.hiddenReturnPtr);
		}
	}

	private byte[] packed(ParamListStandard list) throws Exception {
		ByteArrayOutputStream bytes = new ByteArrayOutputStream();
		list.encode(new PackedEncode(bytes), true);
		return bytes.toByteArray();
	}

	@Test
	public void testMissingAndExplicitBoundedOptionEncodeIdentically() throws Exception {
		String bounded = STACK.replace(" allocation=\"unbounded\"", "");
		ParamListStandard missing = list("<input>" + bounded + "</input>");
		ParamListStandard explicit = list("<input>" +
			bounded.replace("align=\"4\"", "align=\"4\" allocation=\"bounded\"") + "</input>");
		assertArrayEquals(packed(missing), packed(explicit));
		ParameterPieces oldResult = sentinel();
		ParameterPieces newResult = sentinel();
		assertEquals(missing.getStackEntry().getAddrBySlot(125, 4, 4, oldResult),
			missing.getStackEntry().getAllocationAddrBySlot(125, 4, 4, newResult));
		assertNull(oldResult.address);
		assertNull(newResult.address);
	}

	@Test
	public void testExplicitOptionSurvivesEncodingAndPrototypeCopy() throws Exception {
		ParamListStandard original = list("<input>" + STACK + "</input>");
		XmlEncode encoder = new XmlEncode(false);
		original.encode(encoder, true);
		assertTrue(encoder.toString().contains("allocation=\"unbounded\""));
		ParamListStandard restored = list(encoder.toString());
		assertTrue(original.isEquivalent(restored));
		assertTrue(restored.getStackEntry().isUnboundedAllocation());
		assertFalse(original.isEquivalent(list("<input>" +
			STACK.replace(" allocation=\"unbounded\"", "") + "</input>")));
		PrototypeModel copied = new PrototypeModel("allocation-copy",
			cspec.getDefaultCallingConvention());
		assertTrue(((ParamListStandard) copied.getInputResource()).getStackEntry()
			.isUnboundedAllocation());
	}

	@Test
	public void testOptionRejectedForOutputAndNonterminalEntries() throws Exception {
		for (String xml : new String[] { "<output>" + STACK + "</output>",
			"<input>" + STACK + REGISTER + "</input>",
			"<input>" + REGISTER.replace("maxsize=\"4\"", "maxsize=\"4\" allocation=\"unbounded\"") + "</input>",
			"<input>" + STACK.replace("unbounded", "unlimited") + "</input>",
			"<input>" + STACK.replace("align=\"4\"", "align=\"0\"") + "</input>",
			"<input>" + STACK.replace("minsize=\"1\"", "minsize=\"0\"") + "</input>" }) {
			try {
				list(xml);
				fail("Invalid allocation policy must be rejected: " + xml);
			}
			catch (XmlParseException expected) {
				// The schema and decoder reject unsupported allocation contracts.
			}
		}
	}

	@Test
	public void testPreconditionConsumptionRollsBackOnStackFailure() throws Exception {
		ParamListStandard resources = list("<input>" + REGISTER + STACK +
			"<rule><datatype name=\"any\"/><consume_extra storage=\"general\"/>" +
			"<goto_stack/></rule></input>");
		int[] status = { 0, 536870912 };
		ParameterPieces result = sentinel();
		int response = resources.assignAddress(IntegerDataType.dataType,
			new PrototypePieces(cspec.getDefaultCallingConvention(), null), 0, dtManager, status, result);
		// Fallback still legitimately uses r0 after the failed rule rolled back its precondition.
		assertEquals(AssignAction.SUCCESS, response);
		assertEquals(language.getRegister("r0").getAddress(), result.address);
		assertArrayEquals(new int[] { -1, 536870912 }, status);
	}

	@Test
	public void testSideeffectFailureRollsBackMainRegisterAssignment() throws Exception {
		ParamListStandard resources = list("<input>" + REGISTER + STACK +
			"<rule><datatype name=\"any\"/><join storage=\"general\"/>" +
			"<extra_stack/></rule></input>");
		int[] status = { 0, 536870912 };
		ParameterPieces result = sentinel();
		int response = resources.assignAddress(IntegerDataType.dataType,
			new PrototypePieces(cspec.getDefaultCallingConvention(), null), 0, dtManager, status, result);
		// The failed side effect must not consume r0 before normal fallback sees it.
		assertEquals(AssignAction.SUCCESS, response);
		assertEquals(language.getRegister("r0").getAddress(), result.address);
		assertArrayEquals(new int[] { -1, 536870912 }, status);
	}
	@Test
	public void testGotoFailurePreservesStatusAndMarkup() throws Exception {
		ParamListStandard resources = list("<input>" + REGISTER + STACK + "</input>");
		int[] status = { 0, 536870912 };
		ParameterPieces result = sentinel();
		assertEquals(AssignAction.FAIL, new GotoStack(resources).assignAddress(
			IntegerDataType.dataType, new PrototypePieces(cspec.getDefaultCallingConvention(), null),
			0, dtManager, status, result));
		assertArrayEquals(new int[] { 0, 536870912 }, status);
		assertEquals(language.getRegister("r0").getAddress(), result.address);
		assertSame(CharDataType.dataType, result.type);
		assertTrue(result.hiddenReturnPtr);
	}

	@Test
	public void testSplitAssignmentBeyondRecognitionRange() throws Exception {
		ParamListStandard resources = list("<input>" + REGISTER + STACK + "</input>");
		MultiSlotAssign action = new MultiSlotAssign(StorageClass.GENERAL, true, false, false,
			false, false, resources);
		int[] status = { 0, 181 };
		ParameterPieces result = new ParameterPieces();
		assertEquals(AssignAction.SUCCESS, action.assignAddress(LongLongDataType.dataType,
			new PrototypePieces(cspec.getDefaultCallingConvention(), null), 0, dtManager, status, result));
		assertArrayEquals(new int[] { -1, 182 }, status);
		assertNotNull(result.joinPieces);
		assertEquals(2, result.joinPieces.length);
		boolean register = false;
		boolean stack = false;
		for (var piece : result.joinPieces) {
			assertEquals(4, piece.getSize());
			register |= piece.getAddress().equals(language.getRegister("r0").getAddress());
			stack |= piece.getAddress().getAddressSpace().isStackSpace() && piece.getOffset() == 724;
		}
		assertTrue(register && stack);
	}

	@Test
	public void testSplitFailureRollsBackTemporaryRegisterConsumption() throws Exception {
		ParamListStandard resources = list("<input>" + REGISTER + STACK + "</input>");
		MultiSlotAssign action = new MultiSlotAssign(StorageClass.GENERAL, true, false, false,
			false, false, resources);
		int[] status = { 0, 536870912 };
		ParameterPieces result = sentinel();
		assertEquals(AssignAction.FAIL, action.assignAddress(LongLongDataType.dataType,
			new PrototypePieces(cspec.getDefaultCallingConvention(), null), 0, dtManager, status, result));
		assertArrayEquals(new int[] { 0, 536870912 }, status);
		assertEquals(language.getRegister("r0").getAddress(), result.address);
		assertSame(CharDataType.dataType, result.type);
		assertTrue(result.hiddenReturnPtr);
	}

}
