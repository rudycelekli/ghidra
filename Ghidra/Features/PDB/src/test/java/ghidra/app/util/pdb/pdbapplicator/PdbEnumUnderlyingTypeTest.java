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
package ghidra.app.util.pdb.pdbapplicator;

import static org.junit.Assert.*;

import java.io.IOException;
import java.math.BigInteger;

import org.junit.Test;

import db.Transaction;
import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.data.Enum;
import ghidra.test.*;
import ghidra.util.task.TaskMonitor;

public class PdbEnumUnderlyingTypeTest extends AbstractGhidraHeadlessIntegrationTest {
	@Test
	public void testSignedByteNegative() throws Exception {
		check(0x68, 0x8000, -1, 1);
	}

	@Test
	public void testSignedShortMinimum() throws Exception {
		check(0x11, 0x8001, Short.MIN_VALUE, 2);
	}

	@Test
	public void testSignedLongMinimum() throws Exception {
		check(0x12, 0x8003, Integer.MIN_VALUE, 4);
	}

	@Test
	public void testSignedQuadNegative() throws Exception {
		check(0x13, 0x8009, -1, 8);
	}

	@Test
	public void testSignedQuadPositive() throws Exception {
		check(0x13, 0x8009, 42, 8);
	}

	@Test
	public void testUnsignedShortMaximum() throws Exception {
		check(0x21, 0x8002, 65535, 2);
	}

	@Test
	public void testUnsignedByteMaximumControl() throws Exception {
		check(0x69, 0x8002, 255, 1);
	}

	@Test
	public void testSignedBytePositiveControl() throws Exception {
		check(0x68, 0x8000, 42, 1);
	}

	private void check(int underlying, int numericLeaf, long expected, int width) throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder("PdbEnum", true);
		try (DummyPdb700 pdb = new NamedPdb()) {
			builder.createMemory("data", "1000", 16);
			pdb.setDebugInfoAvailable(false);
			PdbByteWriter fields = new PdbByteWriter();
			fields.putUnsignedShort(FieldListMsType.PDB_ID);
			fields.putUnsignedShort(EnumerateMsType.PDB_ID);
			fields.putUnsignedShort(3); // public enumerator attributes
			fields.putNumeric(BigInteger.valueOf(expected), numericLeaf);
			fields.putNullTerminatedString("VALUE");
			fields.putPadding(0);
			AbstractMsType fieldList = TypeParser.parseRecord(pdb,
				new PdbByteReader(fields.get()), RecordNumber.typeRecordNumber(0x1000));
			assertTrue(fieldList instanceof FieldListMsType);
			assertTrue(pdb.setTypeRecord(0x1000, fieldList));
			PdbByteWriter enumBytes = new PdbByteWriter();
			enumBytes.putUnsignedShort(EnumMsType.PDB_ID);
			enumBytes.putUnsignedShort(1);
			enumBytes.putUnsignedShort(0);
			enumBytes.putUnsignedInt(underlying);
			enumBytes.putUnsignedInt(0x1000);
			enumBytes.putNullTerminatedString("ExampleEnum");
			enumBytes.putPadding(0);
			AbstractMsType enumRecord = TypeParser.parseRecord(pdb,
				new PdbByteReader(enumBytes.get()), RecordNumber.typeRecordNumber(0x1001));
			assertTrue(enumRecord instanceof EnumMsType);
			assertTrue(pdb.setTypeRecord(0x1001, enumRecord));
			assertSame(fieldList, pdb.getTypeProgramInterface().getRandomAccessRecord(0x1000));
			assertSame(enumRecord, pdb.getTypeProgramInterface().getRandomAccessRecord(0x1001));
			PdbApplicatorOptions options = new PdbApplicatorOptions();
			options.setProcessingControl(PdbApplicatorControl.DATA_TYPES_ONLY);
			DefaultPdbApplicator applicator = new DefaultPdbApplicator(pdb, builder.getProgram(),
				null, null, options, TaskMonitor.DUMMY, new MessageLog());
			try (Transaction tx = builder.getProgram().openTransaction("Apply parsed PDB enums")) {
				applicator.applyNoAnalysisState();
			}
			Enum result = (Enum) applicator.getCompletedDataType(RecordNumber.typeRecordNumber(0x1001));
			assertNotNull(result);
			assertEquals(width, result.getLength());
			assertEquals(expected, result.getValue("VALUE"));
			assertEquals(expected < 0, result.isSigned());
			assertArrayEquals(new String[] { "VALUE" }, result.getNames(expected));
		}
		finally {
			builder.dispose();
		}
	}

	private static class NamedPdb extends DummyPdb700 {
		NamedPdb() throws IOException, PdbException {
			super(0x1000, 0x1002, 0x1000, 0x1000);
			// Expose the same parsed record table to the mapper's direct TPI access.
			typeProgramInterface = new TypeProgramInterface800(this, RecordCategory.TYPE, -1) {
				{
					typeIndexMin = 0x1000;
					typeIndexMaxExclusive = 0x1002;
				}

				@Override
				public AbstractMsType getRandomAccessRecord(int recordNumber) {
					return NamedPdb.this.getTypeRecord(RecordNumber.typeRecordNumber(recordNumber));
				}
			};
		}

		@Override
		public String getFilename() {
			return "enum-fixture.pdb";
		}
	}
}
