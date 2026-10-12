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
package ghidra.app.util.exporter;

import static org.junit.Assert.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.junit.Test;
import ghidra.app.util.Option;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.reloc.Relocation;
import ghidra.test.*;
import ghidra.util.task.TaskMonitor;

/** Actual public original-file export with benign file-backed memory and relocations. */
public class OriginalFileRelocationCharacterizationTest extends AbstractGhidraHeadlessIntegrationTest {
	private static final byte[] FIRST = { 1,2,3,4,5,6,7,8 };
	private static final byte[] SECOND = { 33,34,35,36,37,38,39,40 };
	private static class Fixture implements AutoCloseable {
		final ProgramBuilder builder;
		final Program program;
		final Memory memory;
		final Path directory;
		Fixture() throws Exception {
			builder = new ProgramBuilder("OriginalFileRelocations", ProgramBuilder._TOY, null);
			program = builder.getProgram();
			memory = program.getMemory();
			try { directory = Files.createTempDirectory("original-export-relocations-"); }
			catch (Exception e) { builder.dispose(); throw e; }
		}
		Address address(long offset) { return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset); }
		FileBytes source(String name, long start, long originalOffset, byte[] bytes) throws Exception {
			int tx = program.startTransaction("Create real file-backed source");
			try (InputStream input = new ByteArrayInputStream(bytes)) {
				FileBytes file = memory.createFileBytes(name, originalOffset, bytes.length, input, TaskMonitor.DUMMY);
				memory.createInitializedBlock(name, address(start), file, 0, bytes.length, false);
				assertSame(file, memory.getAddressSourceInfo(address(start)).getMemoryBlockSourceInfo().getFileBytes().orElseThrow());
				assertEquals(originalOffset, memory.getAddressSourceInfo(address(start)).getFileOffset());
				return file;
			}
			finally { program.endTransaction(tx, true); }
		}
		void modify(long address, byte... bytes) throws Exception {
			int tx = program.startTransaction("Actual memory edit");
			try {
				memory.setBytes(address(address), bytes);
				byte[] actual = new byte[bytes.length];
				assertEquals(bytes.length, memory.getBytes(address(address), actual));
				assertArrayEquals(bytes, actual);
			}
			finally { program.endTransaction(tx, true); }
		}
		void relocation(long address, Relocation.Status status, byte... original) {
			int tx = program.startTransaction("Record actual relocation");
			try {
				program.getRelocationTable().add(address(address), status, 1, new long[] { 1 }, original, "benign_value");
				assertEquals(status, program.getRelocationTable().getRelocations(address(address)).get(0).getStatus());
			}
			finally { program.endTransaction(tx, true); }
		}
		void mapped(long start, long source, int length) throws Exception {
			int tx = program.startTransaction("Actual byte mapped memory");
			try { memory.createByteMappedBlock("mapped", address(start), address(source), length, false); }
			finally { program.endTransaction(tx, true); }
			assertTrue(memory.getAddressSourceInfo(address(start)).getMemoryBlockSourceInfo().getMappedRange().isPresent());
		}
		byte[][] export(String caseName, boolean multiple, boolean modifications) throws Exception {
			OriginalFileExporter exporter = new OriginalFileExporter();
			List<Option> options = exporter.getOptions(() -> program);
			boolean foundModifications = false, foundDirectory = false;
			for (Option option : options) {
				if (option.getName().equals("Export User Byte Modifications")) { option.setValue(modifications); foundModifications = true; }
				if (option.getName().equals("Save Multiple File Sources To Directory")) { option.setValue(multiple); foundDirectory = true; }
			}
			assertTrue(foundModifications);
			if (multiple) { assertTrue(foundDirectory); }
			exporter.setOptions(options);
			File output = directory.resolve("output").toFile();
			assertTrue("Actual exporter must complete", exporter.export(output, program, null, TaskMonitor.DUMMY));
			int count = multiple ? memory.getAllFileBytes().size() : 1;
			byte[][] actual = new byte[count][];
			for (int i = 0; i < count; i++) { actual[i] = Files.readAllBytes(multiple ? output.toPath().resolve("output." + i) : output.toPath()); }
			System.out.println("ORIGINAL_FILE_RELOCATION case=" + caseName + " sources=" + memory.getAllFileBytes().size() +
				" relocations=" + program.getRelocationTable().getSize() + " modifications=" + modifications +
				" output=" + String.join(",", Arrays.stream(actual).map(HexFormat.of()::formatHex).toList()));
			return actual;
		}
		@Override public void close() throws Exception {
			try {
				try (var paths = Files.walk(directory)) {
					for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) { Files.deleteIfExists(path); }
				}
			}
			finally { builder.dispose(); }
		}
	}
	@Test public void testDirectoryExportDoesNotUndoOtherSourceRelocation() throws Exception {
		try (Fixture f = new Fixture()) {
			f.source("first",0x1000,0,FIRST);f.source("second",0x2000,0,SECOND);
			f.modify(0x1002,(byte)99,(byte)98);f.relocation(0x1002,Relocation.Status.APPLIED,(byte)3,(byte)4);
			byte[][] actual = f.export("directory-foreign",true,true);
			assertArrayEquals(FIRST,actual[0]);
			assertTrue("Secondary source must not receive another source's relocation bytes", Arrays.equals(SECOND,actual[1]));
		}
	}
	@Test public void testPrimaryExportDoesNotUndoSecondarySourceRelocation() throws Exception {
		try (Fixture f = new Fixture()) {
			f.source("first",0x1000,0,FIRST);f.source("second",0x2000,0,SECOND);
			f.modify(0x2002,(byte)99,(byte)98);f.relocation(0x2002,Relocation.Status.APPLIED,(byte)35,(byte)36);
			assertTrue("Primary source must not receive another source's relocation bytes", Arrays.equals(FIRST,f.export("primary-foreign",false,true)[0]));
		}
	}
	@Test public void testNonzeroOriginalOffsetUsesRelativeOutputPosition() throws Exception {
		try (Fixture f = new Fixture()) {
			f.source("first",0x1000,64,FIRST);f.modify(0x1002,(byte)99,(byte)98);f.relocation(0x1002,Relocation.Status.APPLIED,(byte)3,(byte)4);
			assertEquals(66, f.memory.getAddressSourceInfo(f.address(0x1002)).getFileOffset());
			assertTrue("FileBytes original offset must not shift or extend exported bytes",Arrays.equals(FIRST,f.export("nonzero-offset",false,true)[0]));
		}
	}
	@Test public void testOwnRelocationPreservesIndependentUserEdit() throws Exception {
		try (Fixture f = new Fixture()) {
			f.source("first",0x1000,0,FIRST);f.modify(0x1002,(byte)99,(byte)98);f.modify(0x1007,(byte)77);f.relocation(0x1002,Relocation.Status.APPLIED,(byte)3,(byte)4);
			byte[] expected = FIRST.clone();expected[7]=77;assertArrayEquals(expected,f.export("own-source",false,true)[0]);
		}
	}
	@Test public void testByteMappedRelocationStillUndoesOwnSource() throws Exception {
		try (Fixture f = new Fixture()) {
			f.source("first",0x1000,0,FIRST);f.mapped(0x2000,0x1000,8);f.modify(0x2002,(byte)99,(byte)98);f.relocation(0x2002,Relocation.Status.APPLIED,(byte)3,(byte)4);
			assertEquals(2,f.memory.getAddressSourceInfo(f.address(0x2002)).getFileOffset());
			assertTrue(f.memory.getAddressSourceInfo(f.address(0x2002)).getMemoryBlockSourceInfo().getFileBytes().isEmpty());
			assertArrayEquals(FIRST,f.export("mapped-own",false,true)[0]);
		}
	}
	@Test public void testSkippedRelocationRetainsModifiedBytes() throws Exception {
		try (Fixture f = new Fixture()) {
			f.source("first",0x1000,0,FIRST);f.modify(0x1002,(byte)99,(byte)98);f.relocation(0x1002,Relocation.Status.SKIPPED,(byte)3,(byte)4);
			byte[] expected=FIRST.clone();expected[2]=99;expected[3]=98;assertArrayEquals(expected,f.export("skipped",false,true)[0]);
		}
	}
	@Test public void testModificationsDisabledExportsOriginalBytes() throws Exception {
		try (Fixture f = new Fixture()) {
			f.source("first",0x1000,0,FIRST);f.source("second",0x2000,0,SECOND);f.modify(0x1002,(byte)99);f.modify(0x2002,(byte)98);f.relocation(0x2002,Relocation.Status.APPLIED,(byte)35);
			byte[][] actual=f.export("unmodified",true,false);assertArrayEquals(FIRST,actual[0]);assertArrayEquals(SECOND,actual[1]);
		}
	}
	@Test public void testUnbackedRelocationDoesNotChangeFileBytes() throws Exception {
		try (Fixture f = new Fixture()) {
			f.source("first",0x1000,0,FIRST);
			int tx=f.program.startTransaction("Unbacked memory");
			try { f.memory.createInitializedBlock("unbacked",f.address(0x2000),8,(byte)0,TaskMonitor.DUMMY,false); }
			finally { f.program.endTransaction(tx,true); }
			f.relocation(0x2002,Relocation.Status.APPLIED,(byte)55,(byte)56);
			assertEquals(-1,f.memory.getAddressSourceInfo(f.address(0x2002)).getFileOffset());
			assertArrayEquals(FIRST,f.export("unbacked",false,true)[0]);
		}
	}
}
