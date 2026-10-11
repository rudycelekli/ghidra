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
package ghidra.file.formats.tar;

import static org.junit.Assert.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

import org.apache.commons.compress.archivers.tar.*;
import org.junit.*;
import org.junit.rules.TemporaryFolder;

import generic.test.AbstractGenericTest;
import ghidra.app.util.bin.*;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.fileinfo.FileType;
import ghidra.formats.gfilesystem.fileinfo.FileAttributeType;
import ghidra.util.task.TaskMonitor;

public class TarHardLinkTest extends AbstractGenericTest {
	@Rule
	public TemporaryFolder temporaryFolder = new TemporaryFolder();

	@Test
	public void testRootHardLinkContent() throws Exception {
		check("hard", "original", regular("target", "original"), hard("hard", "target"));
	}

	@Test
	public void testNestedHardLinkUsesArchiveRoot() throws Exception {
		check("nested/hard", "original", regular("target", "original"),
			regular("nested/target", "wrong"), hard("nested/hard", "target"));
	}

	@Test
	public void testHardLinkRetainsOriginalEntryAfterReplacement() throws Exception {
		check("hard", "original", regular("target", "original"), hard("hard", "target"),
			regular("target", "replacement"));
	}

	@Test
	public void testHardLinkChainRetainsOriginalEntry() throws Exception {
		check("second", "original", regular("target", "original"), hard("first", "target"),
			hard("second", "first"), regular("target", "replacement"));
	}

	@Test
	public void testMissingTargetRejectedOnRead() throws Exception {
		checkMissing(hard("hard", "missing"));
	}

	@Test
	public void testForwardTargetRejectedOnRead() throws Exception {
		checkMissing(hard("hard", "target"), regular("target", "later"));
	}

	@Test
	public void testMixedHardAndSymbolicLinkCycleRejected() throws Exception {
		TarArchiveEntry symbolic = new TarArchiveEntry("symbolic", TarConstants.LF_SYMLINK);
		symbolic.setLinkName("hard");
		checkMissing(new Item(symbolic, ""), hard("hard", "symbolic"));
	}

	@Test
	public void testHardLinkToSymbolicLinkRetainsInodeMetadata() throws Exception {
		TarArchiveEntry symbolic = new TarArchiveEntry("symbolic", TarConstants.LF_SYMLINK);
		symbolic.setLinkName("target");
		FileSystemService service = newService();
		try (TarFileSystem fs = create(service, archive(regular("target", "original"),
			new Item(symbolic, ""), hard("hard", "symbolic")));
			ByteProvider bytes = fs.getByteProvider(fs.lookup("hard"), TaskMonitor.DUMMY)) {
			GFile hard = fs.lookup("hard");
			assertEquals(FileType.SYMBOLIC_LINK, fs.getFileType(hard, TaskMonitor.DUMMY));
			assertEquals(fs.lookup("target"), fs.resolveSymlinks(hard));
			assertEquals("target".length(), hard.getLength());
			assertEquals("target", fs.getFileAttributes(hard, TaskMonitor.DUMMY).get(FileAttributeType.SYMLINK_DEST_ATTR, String.class, null));
			assertEquals((long) "target".length(), (long) fs.getFileAttributes(hard,
				TaskMonitor.DUMMY).get(FileAttributeType.SIZE_ATTR, Long.class, -1L));
			assertArrayEquals("original".getBytes(StandardCharsets.UTF_8),
				bytes.getInputStream(0).readAllBytes());
		}
		finally {
			service.clear();
			waitForCacheMaintenance(service);
		}
	}

	@Test
	public void testHardLinkedRelativeSymlinkUsesAliasParent() throws Exception {
		TarArchiveEntry symbolic = new TarArchiveEntry("nested/symbolic", TarConstants.LF_SYMLINK);
		symbolic.setLinkName("target");
		FileSystemService service = newService();
		try (TarFileSystem fs = create(service, archive(regular("nested/target", "old"),
			regular("other/target", "new"), new Item(symbolic, ""),
			hard("other/hard", "nested/symbolic")));
			ByteProvider bytes = fs.getByteProvider(fs.lookup("other/hard"), TaskMonitor.DUMMY)) {
			GFile hard = fs.lookup("other/hard");
			assertEquals(fs.lookup("other/target"), fs.resolveSymlinks(hard));
			assertEquals(FileType.SYMBOLIC_LINK, fs.getFileType(hard, TaskMonitor.DUMMY));
			assertEquals("target", fs.getFileAttributes(hard, TaskMonitor.DUMMY)
				.get(FileAttributeType.SYMLINK_DEST_ATTR, String.class, null));
			assertArrayEquals("new".getBytes(StandardCharsets.UTF_8),
				bytes.getInputStream(0).readAllBytes());
		}
		finally {
			service.clear();
			waitForCacheMaintenance(service);
		}
	}

	@Test
	public void testOrdinaryFile() throws Exception {
		check("target", "ordinary", regular("target", "ordinary"));
	}

	@Test
	public void testRelativeSymbolicLink() throws Exception {
		TarArchiveEntry entry = new TarArchiveEntry("nested/symbolic", TarConstants.LF_SYMLINK);
		entry.setLinkName("../target");
		check("nested/symbolic", "original", regular("target", "original"), new Item(entry, ""));
	}

	@Test
	public void testHardLinkWithStoredPaxDataUnchanged() throws Exception {
		TarArchiveEntry entry = new TarArchiveEntry("hard", TarConstants.LF_LINK);
		entry.setLinkName("target");
		entry.addPaxHeader("size", "6");
		check("hard", "stored", regular("target", "original"), new Item(entry, "stored"));
	}

	private record Item(TarArchiveEntry entry, String payload) {}

	private static Item regular(String name, String payload) {
		return new Item(new TarArchiveEntry(name), payload);
	}

	private static Item hard(String name, String target) {
		TarArchiveEntry entry = new TarArchiveEntry(name, TarConstants.LF_LINK);
		entry.setLinkName(target);
		return new Item(entry, "");
	}

	private static byte[] archive(Item... items) throws IOException {
		ByteArrayOutputStream bytes = new ByteArrayOutputStream();
		try (TarArchiveOutputStream tar = new TarArchiveOutputStream(bytes)) {
			for (Item item : items) {
				byte[] payload = item.payload().getBytes(StandardCharsets.UTF_8);
				item.entry().setSize(payload.length);
				tar.putArchiveEntry(item.entry());
				tar.write(payload);
				tar.closeArchiveEntry();
			}
		}
		return bytes.toByteArray();
	}

	private void check(String path, String expected, Item... items) throws Exception {
		FileSystemService service = newService();
		try (TarFileSystem fs = create(service, archive(items));
			ByteProvider bytes = fs.getByteProvider(fs.lookup(path), TaskMonitor.DUMMY)) {
			if (!expected.equals("stored") && (path.equals("hard") || path.equals("nested/hard") || path.equals("second"))) {
				assertEquals(expected.length(), fs.lookup(path).getLength());
				assertEquals(FileType.FILE, fs.getFileType(fs.lookup(path), TaskMonitor.DUMMY));
				assertEquals((long) expected.length(), (long) fs.getFileAttributes(fs.lookup(path), TaskMonitor.DUMMY).get(FileAttributeType.SIZE_ATTR, Long.class, -1L));
			}
			assertArrayEquals(expected.getBytes(StandardCharsets.UTF_8),
				bytes.getInputStream(0).readAllBytes());
		}
		finally {
			service.clear();
			waitForCacheMaintenance(service);
		}
	}

	private void checkMissing(Item... items) throws Exception {
		FileSystemService service = newService();
		try (TarFileSystem fs = create(service, archive(items))) {
			try (ByteProvider ignored = fs.getByteProvider(fs.lookup("hard"), TaskMonitor.DUMMY)) {
				fail("Missing prior hard-link target must not become an empty file");
			}
			catch (IOException expected) {
				assertNotNull(expected.getMessage());
			}
		}
		finally {
			service.clear();
			waitForCacheMaintenance(service);
		}
	}

	private FileSystemService newService() throws Exception {
		FileSystemService service = new FileSystemService(temporaryFolder.newFolder());
		waitForCacheMaintenance(service);
		return service;
	}

	private void waitForCacheMaintenance(FileSystemService service) {
		FileCache cache = (FileCache) getInstanceField("fileCache", service);
		waitForCondition(() -> !(Boolean) invokeInstanceMethod("isCleaning", cache));
	}

	private TarFileSystem create(FileSystemService service, byte[] archive) throws Exception {
		String md5 = HexFormat.of().formatHex(MessageDigest.getInstance("MD5").digest(archive));
		FSRL container = FSRLRoot.makeRoot("file").appendPath("/fixture.tar").withMD5(md5);
		return new TarFileSystemFactory().create(container.nestedFS("tar"),
			new ByteArrayProvider(archive, container), service, TaskMonitor.DUMMY);
	}
}
