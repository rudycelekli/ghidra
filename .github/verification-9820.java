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
package ghidra.framework.data;

import static org.junit.Assert.*;

import java.io.File;

import org.junit.*;

import ghidra.framework.model.*;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.Language;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

public class ProjectFileIndexFolderChangeTest extends AbstractGhidraHeadedIntegrationTest {
	private DefaultProjectData project;
	private File directory;
	private DomainFolder root;

	@Before
	public void setUp() throws Exception {
		directory = createTempDirectory(getName());
		ProjectLocator locator = new ProjectLocator(directory.getAbsolutePath(), "Index");
		project = new DefaultProjectData(locator, null, true);
		root = project.getRootFolder();
	}

	@After
	public void tearDown() {
		if (project != null) {
			project.close();
		}
		if (directory != null) {
			assertTrue(FileUtilities.deleteDir(directory));
		}
	}

	@Test
	public void testCachedIdsSurviveParentRename() throws Exception {
		DomainFolder parent = root.createFolder("before");
		DomainFile direct = createFile(parent, "direct");
		DomainFile nested = createFile(parent.createFolder("nested"), "child");
		String directId = cache(direct);
		String nestedId = cache(nested);
		parent.setName("after");
		assertNull(project.getFile("/before/direct"));
		assertNull(project.getFile("/before/nested/child"));
		assertLookup(directId, "/after/direct");
		assertLookup(nestedId, "/after/nested/child");
	}

	@Test
	public void testCachedIdsSurviveParentMove() throws Exception {
		DomainFolder parent = root.createFolder("source");
		DomainFolder destination = root.createFolder("destination");
		DomainFile direct = createFile(parent, "direct");
		DomainFile nested = createFile(parent.createFolder("nested"), "child");
		String directId = cache(direct);
		String nestedId = cache(nested);
		destination.getFolders();
		parent.moveTo(destination);
		assertNull(project.getFile("/source/direct"));
		assertLookup(directId, "/destination/source/direct");
		assertLookup(nestedId, "/destination/source/nested/child");
	}

	@Test
	public void testFileRenameKeepsIdLookup() throws Exception {
		DomainFile file = createFile(root, "before");
		String id = cache(file);
		file.setName("after");
		assertNull(project.getFile("/before"));
		assertLookup(id, "/after");
	}

	@Test
	public void testUnrelatedFileIsUnaffectedByFolderRename() throws Exception {
		DomainFile untouched = createFile(root, "untouched");
		String id = cache(untouched);
		root.createFolder("before").setName("after");
		assertLookup(id, "/untouched");
	}

	@Test
	public void testDeletedFileHasNoIdLookup() throws Exception {
		DomainFile file = createFile(root, "removed");
		String id = cache(file);
		file.delete();
		assertNull(project.getFileByID(id));
	}

	@Test
	public void testReusedOldPathDoesNotReturnReplacementFile() throws Exception {
		DomainFile original = createFile(root, "before");
		String id = cache(original);
		original.setName("after");
		DomainFile replacement = createFile(root, "before");
		assertNotEquals(id, replacement.getFileID());
		assertLookup(id, "/after");
		assertLookup(replacement.getFileID(), "/before");
	}

	@Test
	public void testReusedOldPathDoesNotResetOriginalIdOnLaterRename() throws Exception {
		DomainFolder parent = root.createFolder("before");
		DomainFile original = createFile(parent, "direct");
		String id = cache(original);
		parent.getFiles();
		DomainFolder renamed = parent.setName("after");
		DomainFile replacement = createFile(root.createFolder("before"), "direct");
		String replacementId = replacement.getFileID();
		renamed.getFile("direct").setName("renamed");
		assertEquals(id, project.getFile("/after/renamed").getFileID());
		assertLookup(id, "/after/renamed");
		assertLookup(replacementId, "/before/direct");
	}

	@Test
	public void testFolderRenameUpdatesIndexBeforeLookup() throws Exception {
		DomainFolder parent = root.createFolder("before");
		DomainFolder sibling = root.createFolder("beforeSibling");
		DomainFile direct = createFile(parent, "direct");
		DomainFile nested = createFile(parent.createFolder("nested"), "child");
		DomainFile unrelated = createFile(sibling, "untouched");
		String directId = cache(direct);
		String nestedId = cache(nested);
		String unrelatedId = cache(unrelated);
		root.getFolders();
		parent.getFiles();
		parent.setName("after");
		assertIndexedPath(directId, "/after/direct");
		assertIndexedPath(nestedId, "/after/nested/child");
		assertIndexedPath(unrelatedId, "/beforeSibling/untouched");
	}

	@Test
	public void testFolderMoveUpdatesIndexBeforeLookup() throws Exception {
		assertMoveUpdatesIndex(true);
	}

	@Test
	public void testFolderMoveToUnvisitedDestinationUpdatesIndexBeforeLookup() throws Exception {
		assertMoveUpdatesIndex(false);
	}

	private void assertMoveUpdatesIndex(boolean visitDestination) throws Exception {
		DomainFolder parent = root.createFolder("source");
		DomainFolder destination = root.createFolder("destination");
		DomainFile direct = createFile(parent, "direct");
		DomainFile nested = createFile(parent.createFolder("nested"), "child");
		String directId = cache(direct);
		String nestedId = cache(nested);
		root.getFolders();
		parent.getFiles();
		if (visitDestination) {
			destination.getFolders();
		}
		assertTrue(((GhidraFolder) root).getFolderData().visited());
		assertEquals(visitDestination, ((GhidraFolder) destination).getFolderData().visited());
		parent.moveTo(destination);
		assertIndexedPath(directId, "/destination/source/direct");
		assertIndexedPath(nestedId, "/destination/source/nested/child");
	}

	private void assertIndexedPath(String id, String expectedPath) throws Exception {
		java.lang.reflect.Field indexField = DefaultProjectData.class.getDeclaredField("fileIndex");
		indexField.setAccessible(true);
		Object index = indexField.get(project);
		java.lang.reflect.Field pathsField = index.getClass().getDeclaredField("fileIdToPathIndex");
		pathsField.setAccessible(true);
		java.util.Map<?, ?> paths = (java.util.Map<?, ?>) pathsField.get(index);
		assertEquals("Index must update before lookup can repair it", expectedPath, paths.get(id));
	}

	private String cache(DomainFile file) {
		String id = file.getFileID();
		assertNotNull(id);
		assertEquals(file, project.getFileByID(id));
		return id;
	}

	private void assertLookup(String id, String path) {
		DomainFile file = project.getFileByID(id);
		assertNotNull("Existing file must remain findable by stable ID: " + path, file);
		assertEquals(path, file.getPathname());
		assertEquals(id, file.getFileID());
		assertEquals(project.getFile(path), file);
	}

	private DomainFile createFile(DomainFolder folder, String name) throws Exception {
		Language language = getSLEIGH_X86_LANGUAGE();
		ProgramDB program = new ProgramDB(name, language, language.getDefaultCompilerSpec(), this);
		try {
			return folder.createFile(name, program, TaskMonitor.DUMMY);
		}
		finally {
			program.release(this);
		}
	}
}
