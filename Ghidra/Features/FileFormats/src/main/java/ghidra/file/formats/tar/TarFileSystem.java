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

import static ghidra.formats.gfilesystem.fileinfo.FileAttributeType.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.io.FilenameUtils;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TAR file system implementation.
 * <p>
 * The factory supports detecting both compressed (gz/bz2/xz) and uncompressed tar files,
 * and keys both on the tar filename extension as well as the data in the file.
 */
@FileSystemInfo(
	type = "tar",
	description = "TAR",
	priority = FileSystemInfo.PRIORITY_HIGH,
	factory = TarFileSystemFactory.class,
	extensions = { "tar", "tgz", "tbz2" }
)
public class TarFileSystem extends AbstractFileSystem<TarMetadata> {

	private ByteProvider provider;
	private int fileCount;
	private final Map<GFile, GFile> hardLinkTargets = new HashMap<>();

	/**
	 * Creates a new TarFileSystem instance.
	 *
	 * @param fsrl {@link FSRLRoot} of the new filesystem.
	 * @param provider {@link ByteProvider} container file
	 * @param fsService reference to the {@link FileSystemService}.
	 */
	public TarFileSystem(FSRLRoot fsrl, ByteProvider provider, FileSystemService fsService) {
		super(fsrl, fsService);

		this.provider = provider;
	}

	ByteProvider getProvider() {
		return provider;
	}

	void mount(TaskMonitor monitor) throws IOException, CancelledException {
		Map<String, GFile> archiveEntries = new HashMap<>();
		try (TarArchiveInputStream tarInput =
			new TarArchiveInputStream(provider.getInputStream(0))) {
			TarArchiveEntry tarEntry;
			while ((tarEntry = tarInput.getNextEntry()) != null) {
				monitor.setMessage(tarEntry.getName());
				monitor.checkCancelled();

				int fileNum = fileCount++;
				String linkName = tarEntry.getLinkName();
				TarMetadata tmd = new TarMetadata(tarEntry, fileNum);
				boolean zeroDataHardLink = tarEntry.isLink() && tarEntry.getSize() == 0;
				GFile hardLinkTarget = zeroDataHardLink
						? archiveEntries.get(FilenameUtils.normalize("/" + linkName, true)) : null;
				long logicalSize =
					hardLinkTarget != null ? hardLinkTarget.getLength() : tarEntry.getSize();
				GFile newFile = !tarEntry.isSymbolicLink()
						? fsIndex.storeFile(tarEntry.getName(), fileCount, tarEntry.isDirectory(),
							logicalSize, tmd)
						: fsIndex.storeSymlink(tarEntry.getName(), fileCount, linkName,
							linkName.length(), tmd);

				if (zeroDataHardLink) {
					// Hard links refer to the prior archive entry, not a path resolved later.
					hardLinkTargets.put(newFile, hardLinkTarget);
					if (hardLinkTarget != null &&
						getFileType(hardLinkTarget, monitor) == FileType.SYMBOLIC_LINK) {
						// A hard-linked symlink retains its literal contents, interpreted
						// relative to the new pathname's parent when followed.
						fsIndex.updateSymlinkPath(newFile, fsIndex.getSymlinkPath(hardLinkTarget));
					}
				}
				archiveEntries.put(FilenameUtils.normalize("/" + tarEntry.getName(), true), newFile);

				if (!zeroDataHardLink && !tarEntry.isSymbolicLink() &&
					tarEntry.getSize() < FileCache.MAX_INMEM_FILESIZE) {
					// because tar files are sequential access, we cache smaller files if they
					// will fit in a in-memory ByteProvider
					try (ByteProvider bp =
						fsService.getDerivedByteProvider(fsFSRL.getContainer(), newFile.getFSRL(),
							newFile.getPath(), tarEntry.getSize(), () -> tarInput, monitor)) {
						fsIndex.updateFSRL(newFile,
							newFile.getFSRL().withMD5(bp.getFSRL().getMD5()));
					}
				}
			}
		}
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();
		fsIndex.clear();
		hardLinkTargets.clear();
		if (provider != null) {
			provider.close();
			provider = null;
		}
	}

	@Override
	public boolean isClosed() {
		return provider == null;
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		TarMetadata tmd = fsIndex.getMetadata(file);
		if (tmd == null) {
			return FileAttributes.EMPTY;
		}
		TarArchiveEntry blob = tmd.tarArchiveEntry;
		GFile attributeTarget = file;
		while (hardLinkTargets.containsKey(attributeTarget) &&
			hardLinkTargets.get(attributeTarget) != null) {
			attributeTarget = hardLinkTargets.get(attributeTarget);
		}
		TarMetadata targetMetadata = fsIndex.getMetadata(attributeTarget);
		TarArchiveEntry linkEntry =
			targetMetadata != null ? targetMetadata.tarArchiveEntry : blob;
		return FileAttributes.of(
			FileAttribute.create(NAME_ATTR, FilenameUtils.getName(blob.getName())),
			FileAttribute.create(PATH_ATTR,
				FilenameUtils.getFullPathNoEndSeparator(blob.getName())),
			FileAttribute.create(SIZE_ATTR,
				hardLinkTargets.containsKey(file) ? file.getLength() : blob.getSize()),
			FileAttribute.create(MODIFIED_DATE_ATTR, blob.getLastModifiedDate()),
			FileAttribute.create(FILE_TYPE_ATTR, getFileType(file, monitor)),
			FileAttribute.create(USER_NAME_ATTR, blob.getUserName()),
			FileAttribute.create(GROUP_NAME_ATTR, blob.getGroupName()),
			FileAttribute.create(USER_ID_ATTR, blob.getLongUserId()),
			FileAttribute.create(GROUP_ID_ATTR, blob.getLongGroupId()),
			FileAttribute.create(UNIX_ACL_ATTR, (long) blob.getMode()),
			linkEntry.isSymbolicLink()
					? FileAttribute.create(SYMLINK_DEST_ATTR, linkEntry.getLinkName())
					: null);
	}

	private FileType tarToFileType(TarArchiveEntry tae) {
		if (tae.isDirectory()) {
			return FileType.DIRECTORY;
		}
		if (tae.isSymbolicLink()) {
			return FileType.SYMBOLIC_LINK;
		}
		if (tae.isFile()) {
			return FileType.FILE;
		}
		return FileType.UNKNOWN;
	}

	@Override
	public FileType getFileType(GFile f, TaskMonitor monitor) {
		while (hardLinkTargets.containsKey(f)) {
			f = hardLinkTargets.get(f);
			if (f == null) {
				return FileType.UNKNOWN;
			}
		}
		TarMetadata tmd = fsIndex.getMetadata(f);
		return tmd != null ? tarToFileType(tmd.tarArchiveEntry) : FileType.UNKNOWN;
	}

	@Override
	public GFile resolveSymlinks(GFile file) throws IOException {
		try {
			return resolveLinks(file, TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			throw new IOException(e);
		}
	}

	private GFile resolveLinks(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		GFile resolvedFile = fsIndex.resolveSymlinks(file);
		Set<GFile> visited = new HashSet<>();
		while (hardLinkTargets.containsKey(resolvedFile)) {
			monitor.checkCancelled();
			if (!visited.add(resolvedFile)) {
				throw new IOException("Cyclic TAR hard-link target for " + resolvedFile);
			}
			GFile target = hardLinkTargets.get(resolvedFile);
			if (target == null) {
				throw new IOException("Missing prior TAR hard-link target for " + resolvedFile);
			}
			resolvedFile = fsIndex.resolveSymlinks(target);
		}
		return resolvedFile;
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {

		GFile contentFile = resolveLinks(file, monitor);
		TarMetadata tmd = fsIndex.getMetadata(contentFile);
		if (tmd == null) {
			throw new IOException("Unknown file " + file);
		}

		ByteProvider fileBP = fsService.getDerivedByteProvider(provider.getFSRL(),
			contentFile.getFSRL(), contentFile.getPath(), tmd.tarArchiveEntry.getSize(), () -> {
				TarArchiveInputStream tarInput = new TarArchiveInputStream(provider.getInputStream(0));

				int fileNum = 0;
				TarArchiveEntry tarEntry;
				while ((tarEntry = tarInput.getNextEntry()) != null) {
					if (fileNum == tmd.fileNum) {
						if (!tmd.tarArchiveEntry.getName().equals(tarEntry.getName())) {
							throw new IOException(
								"Mismatch between filenum and tarEntry for " + contentFile);
						}
						return tarInput;
					}
					fileNum++;
				}
				throw new IOException("Could not find requested file " + contentFile);
			}, monitor);

		return fileBP;
	}
}

