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
package ghidra.program.database.dtarchive;

import static org.junit.Assert.*;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.jar.*;

import javax.tools.ToolProvider;

import org.junit.Test;

import ghidra.GhidraClassLoader;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.model.data.*;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.*;
import ghidra.util.classfinder.ClassSearcher;

/** Fork-only discovery: real extension startup in an isolated JVM, never parent caches. */
public class BuiltInCollisionCharacterizationTest extends AbstractGhidraHeadlessIntegrationTest {
	private static StartupErrorLogger startupLogger;

	@Override
	protected ApplicationConfiguration createApplicationConfiguration() {
		ApplicationConfiguration configuration = super.createApplicationConfiguration();
		if (startupLogger != null) {
			configuration.setInitializeLogging(false);
		}
		return configuration;
	}

	@Test
	public void testIncompatibleExtensionCollisionIsCurrentlySilent() throws Exception {
		runIsolatedExtension("byte", true);
	}

	@Test
	public void testUniqueExtensionIsDiscoveredAndResolved() throws Exception {
		runIsolatedExtension("fixture_unique_byte", false);
	}

	private void runIsolatedExtension(String name, boolean collision) throws Exception {
		Path dir = Files.createTempDirectory("builtin-extension-characterization");
		Process process = null;
		try {
			Path source = dir.resolve("fixture/FixtureByteDataType.java");
			Files.createDirectories(source.getParent());
			Files.writeString(source, """
				package fixture;
				import ghidra.program.model.data.*;
				public class FixtureByteDataType extends ByteDataType {
				    public FixtureByteDataType() { this(null); }
				    public FixtureByteDataType(DataTypeManager dtm) { super(dtm); }
				    @Override public String getName() { return "%s"; }
				    @Override public FixtureByteDataType clone(DataTypeManager dtm) {
				        return dtm == getDataTypeManager() ? this : new FixtureByteDataType(dtm);
				    }
				}
				""".formatted(name));
			var compiler = ToolProvider.getSystemJavaCompiler();
			assertNotNull("Integration tests require a JDK", compiler);
			ByteArrayOutputStream diagnostics = new ByteArrayOutputStream();
			String classpath = System.getProperty("java.class.path");
			int compileExit = compiler.run(null, diagnostics, diagnostics,
				"-classpath", classpath, "-d", dir.toString(), source.toString());
			assertEquals(diagnostics.toString(), 0, compileExit);
			Path jar = dir.resolve("FixtureBuiltInExtension.jar");
			try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar))) {
				out.putNextEntry(new JarEntry("fixture/FixtureByteDataType.class"));
				Files.copy(dir.resolve("fixture/FixtureByteDataType.class"), out);
				out.closeEntry();
			}
			Path output = dir.resolve("child-output.txt");
			process = new ProcessBuilder(
				Paths.get(System.getProperty("java.home"), "bin", "java").toString(),
				"-D" + SystemUtilities.TESTING_PROPERTY + "=true",
				"-D" + SystemUtilities.HEADLESS_PROPERTY + "=true",
				"-D" + GhidraClassLoader.CP_EXT + "=" + jar,
				"-classpath", classpath + File.pathSeparator + jar,
				getClass().getName(), name, Boolean.toString(collision))
				.redirectErrorStream(true).redirectOutput(output.toFile()).start();
			assertTrue("Isolated startup timed out", process.waitFor(90, TimeUnit.SECONDS));
			String text = Files.readString(output);
			System.out.print(text);
			assertEquals(text, 0, process.exitValue());
			assertTrue(text, text.contains("ACTUAL_EXTENSION_CHARACTERIZED:" + name));
		}
		finally {
			if (process != null && process.isAlive()) {
				process.destroyForcibly();
				process.waitFor(10, TimeUnit.SECONDS);
			}
			try (var paths = Files.walk(dir)) {
				for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
					Files.deleteIfExists(path);
				}
			}
		}
	}

	public static void main(String[] args) {
		try {
			startupLogger = new StartupErrorLogger();
			Msg.setErrorLogger(startupLogger);
			new BuiltInCollisionCharacterizationTest().characterize(args[0],
				Boolean.parseBoolean(args[1]), startupLogger);
			System.exit(0);
		}
		catch (Throwable failure) {
			failure.printStackTrace(System.out);
			System.exit(1);
		}
	}

	private static class StartupErrorLogger extends SpyErrorLogger {
		private List<String> errors = new CopyOnWriteArrayList<>();

		@Override
		public void error(Object originator, Object message) {
			errors.add(String.valueOf(message));
			super.error(originator, message);
		}

		@Override
		public void error(Object originator, Object message, Throwable throwable) {
			errors.add(String.valueOf(message));
			super.error(originator, message, throwable);
			if (throwable != null) {
				throwable.printStackTrace(System.out);
			}
		}
	}

	private void characterize(String name, boolean collision, StartupErrorLogger logger) {
		List<BuiltInDataType> discovered = ClassSearcher.getInstances(BuiltInDataType.class,
			new BuiltInDataTypeClassExclusionFilter());
		BuiltInDataType extension = discovered.stream()
			.filter(dt -> dt.getClass().getName().equals("fixture.FixtureByteDataType"))
			.findFirst().orElseThrow(() -> new AssertionError("Real extension was not discovered"));
		assertEquals(name, extension.getName());
		List<BuiltInDataType> sameName = discovered.stream()
			.filter(dt -> name.equals(dt.getName())).toList();
		assertEquals(collision ? 2 : 1, sameName.size());
		if (collision) {
			assertFalse("Actual extension is incompatible with the existing named type",
				sameName.get(0).isEquivalent(sameName.get(1)));
		}
		BuiltInDataTypeManager dtm = BuiltInDtArchiveDB.getDataTypeArchive().getDataTypeManager();
		List<DataType> resolved = new ArrayList<>();
		dtm.findDataTypes(name, resolved);
		assertEquals(1, resolved.size());
		assertEquals(sameName.get(0).getClass(), resolved.get(0).getClass());
		assertTrue("Actual archive startup unexpectedly reported errors: " + logger.errors,
			logger.errors.isEmpty());
		System.out.println("ACTUAL_EXTENSION_CHARACTERIZED:" + name +
			" discovered=" + sameName.size() + " resolved=" + resolved.get(0).getClass().getName() +
			" collision=" + collision + " diagnosticAbsent=true");
	}
}
