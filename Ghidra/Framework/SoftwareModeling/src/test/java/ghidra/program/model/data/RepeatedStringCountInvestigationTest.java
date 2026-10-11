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
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import db.Transaction;
import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Data;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;

/** Test-only investigation of the documented repeated-string count, not a production fix. */
public class RepeatedStringCountInvestigationTest extends AbstractGenericTest {

	@Test
	public void testDatatypeIsRegisteredBuiltin() {
		List<DataType> found = new ArrayList<>();
		BuiltInDataTypeManager.getDataTypeManager().findDataTypes("RepString", found);
		assertTrue("Current public builtin must actually be registered",
			found.stream().anyMatch(t -> t instanceof RepeatedStringDataType));
	}

	@Test
	public void testZeroCountHeaderOnly() throws Exception {
		checkListing(0);
	}

	@Test
	public void testTwoStringsUseLittleEndianCount() throws Exception {
		checkListing(2);
	}

	@Test
	public void testHighCountByteUsesLittleEndianCount() throws Exception {
		checkListing(256);
	}

	private void checkListing(int count) throws Exception {
		Language language = DefaultLanguageService.getLanguageService()
			.getLanguage(new LanguageID("x86:LE:64:default"));
		ProgramDB program = new ProgramDB("RepeatedString investigation", language,
			language.getDefaultCompilerSpec(), this);
		try {
			byte[] bytes = new byte[2048];
			bytes[0] = (byte) count;
			bytes[1] = (byte) (count >>> 8);
			for (int i = 0; i < count; i++) {
				bytes[2 + i * 2] = 'a';
			}
			Address address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
			Data data;
			try (Transaction tx = program.openTransaction("Create repeated string data")) {
				program.getMemory().createInitializedBlock("data", address,
					new ByteArrayInputStream(bytes), bytes.length, TaskMonitor.DUMMY, false);
				data = program.getListing().createData(address, new RepeatedStringDataType());
			}
			System.out.println("REPEAT_COUNT_LISTING_CREATED count=" + count + " components=" +
				data.getNumComponents() + " length=" + data.getLength());
			assertEquals(count + 1, data.getNumComponents());
			assertEquals(2 + count * 2, data.getLength());
			for (int i = 1; i <= count; i++) {
				assertEquals(2 + (i - 1) * 2, data.getComponent(i).getParentOffset());
				assertEquals("a", data.getComponent(i).getValue());
			}
		}
		finally {
			program.release(this);
		}
	}
}
