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
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import db.Transaction;
import generic.complex.Complex;
import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Data;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;

public class ComplexListingValueTest extends AbstractGenericTest {
	@Test
	public void testFloatComponentsLittleEndian() throws Exception {
		check(Complex8DataType.dataType, false, 1.5, -2.25);
	}

	@Test
	public void testDoubleComponentsBigEndian() throws Exception {
		check(Complex16DataType.dataType, true, 1.5, -2.25);
	}

	@Test
	public void testFloatSignedZeroAndInfinity() throws Exception {
		check(Complex8DataType.dataType, true, -0.0, Double.NEGATIVE_INFINITY);
	}

	@Test
	public void testDoubleNaNAndInfinity() throws Exception {
		check(Complex16DataType.dataType, false, Double.NaN, Double.POSITIVE_INFINITY);
	}

	@Test
	public void testQuadPrecisionComponentsBothEndian() throws Exception {
		// IEEE binary128: exponent 0x3fff, fraction 1/2; negative exponent
		// 0x4000, fraction 1/8. These encode exactly 1.5 and -2.25.
		byte[] big = new byte[32];
		big[0] = 0x3f;
		big[1] = (byte) 0xff;
		big[2] = (byte) 0x80;
		big[16] = (byte) 0xc0;
		big[18] = 0x20;
		checkBytes(Complex32DataType.dataType, true, 1.5, -2.25, big);
		byte[] little = new byte[32];
		for (int component = 0; component < 2; component++) {
			for (int i = 0; i < 16; i++) {
				little[component * 16 + i] = big[component * 16 + 15 - i];
			}
		}
		checkBytes(Complex32DataType.dataType, false, 1.5, -2.25, little);
	}

	@Test
	public void testUninitializedComplexHasNoValue() throws Exception {
		ProgramDB program = program(false);
		try {
			Data data;
			try (Transaction tx = program.openTransaction("Create uninitialized complex")) {
				Address a = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
				program.getMemory().createUninitializedBlock("data", a, 8, false);
				data = program.getListing().createData(a, Complex8DataType.dataType);
			}
			assertNull(data.getValue());
			assertEquals("??", data.getDefaultValueRepresentation());
		}
		finally {
			program.release(this);
		}
	}

	@Test
	public void testComplexDatatypeIsAvailableBuiltin() {
		List<DataType> found = new ArrayList<>();
		BuiltInDataTypeManager.getDataTypeManager().findDataTypes("complex8", found);
		assertTrue(found.stream().anyMatch(t -> t instanceof Complex8DataType));
	}

	private ProgramDB program(boolean big) throws Exception {
		Language language = DefaultLanguageService.getLanguageService().getLanguage(
			new LanguageID(big ? "Toy:BE:32:default" : "Toy:LE:32:default"));
		return new ProgramDB("Complex listing values", language,
			language.getDefaultCompilerSpec(), this);
	}

	private void check(DataType type, boolean big, double real, double imaginary) throws Exception {
		ByteBuffer bytes = ByteBuffer.allocate(type.getLength())
			.order(big ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
		if (type.getLength() == 8) {
			bytes.putFloat((float) real).putFloat((float) imaginary);
		}
		else {
			bytes.putDouble(real).putDouble(imaginary);
		}
		checkBytes(type, big, real, imaginary, bytes.array());
	}

	private void checkBytes(DataType type, boolean big, double real, double imaginary,
			byte[] bytes) throws Exception {
		ProgramDB program = program(big);
		try {
			Data data;
			try (Transaction tx = program.openTransaction("Create complex listing data")) {
				Address a = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
				program.getMemory().createInitializedBlock("data", a,
					new ByteArrayInputStream(bytes), bytes.length, TaskMonitor.DUMMY, false);
				data = program.getListing().createData(a, type);
			}
			Complex value = (Complex) data.getValue();
			assertNotNull(value);
			assertEquals(Double.doubleToLongBits(real), Double.doubleToLongBits(value.getReal()));
			assertEquals(Double.doubleToLongBits(imaginary),
				Double.doubleToLongBits(value.getImaginary()));
			assertEquals(new Complex(real, imaginary).toString(), data.getDefaultValueRepresentation());
		}
		finally {
			program.release(this);
		}
	}
}
