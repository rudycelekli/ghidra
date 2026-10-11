import java.io.*;
import java.nio.file.*;
import java.util.Random;
import java.util.jar.*;

/** Fork-only characterization of the real JarFile producer used by JarEntryNode. */
public class ResourceShortReadProbe {
    public static void main(String[] args) throws Exception {
        if (args.length != 1 || !args[0].matches("[0-9a-f]{40}")) {
            throw new AssertionError("Actual checked-out candidate head required");
        }
        byte[] expected = new byte[65536];
        new Random(4271961).nextBytes(expected);
        Path jarPath = Files.createTempFile("resource-short-read-probe", ".jar");
        try {
            try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jarPath))) {
                JarEntry entry = new JarEntry("payload.bin");
                entry.setMethod(JarEntry.DEFLATED);
                out.putNextEntry(entry);
                out.write(expected);
                out.closeEntry();
            }
            try (JarFile jar = new JarFile(jarPath.toFile());
                    InputStream in = jar.getInputStream(jar.getJarEntry("payload.bin"))) {
                byte[] first = new byte[expected.length];
                int count = in.read(first);
                if (count <= 0 || count >= expected.length) {
                    throw new AssertionError("Native positive DEFLATE short read was not established");
                }
                for (int i = 0; i < count; i++) {
                    if (first[i] != expected[i]) {
                        throw new AssertionError("Real producer prefix did not match entry bytes");
                    }
                }
                System.out.printf("{\"candidate_head\":\"%s\",\"java_runtime\":\"%s\",\"producer\":\"%s\",\"entry_method\":%d,\"logical_size\":%d,\"first_read\":%d,\"positive_short_read\":%s,\"prefix_valid\":true}%n",
                    args[0], System.getProperty("java.runtime.version"), in.getClass().getName(),
                    jar.getJarEntry("payload.bin").getMethod(), expected.length, count,
                    count > 0 && count < expected.length);
            }
        }
        finally {
            Files.deleteIfExists(jarPath);
        }
    }
}
