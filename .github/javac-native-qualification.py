"""Real JDK/JPype qualification only; does not mutate candidate source."""
import argparse, hashlib, importlib.util, json, os, pathlib, subprocess, tempfile
import jpype, jpype.imports

parser = argparse.ArgumentParser()
parser.add_argument("--source", required=True, type=pathlib.Path)
parser.add_argument("--phase", required=True, choices=["baseline", "fixed"])
parser.add_argument("--outcome", required=True, choices=["success", "error"])
a = parser.parse_args()
source = a.source.read_text()
receipt = {"phase": a.phase, "outcome": a.outcome,
           "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
           "jpype_version": jpype.__version__, "native": True}
with tempfile.TemporaryDirectory() as directory:
    root = pathlib.Path(directory)
    dependency = root / "Dependency.java"
    dependency.write_text("package owned; public class Dependency { public static int value() { return 42; } }")
    subprocess.run(["javac", "-source", "21", "-target", "21", "-d", str(root / "classes"), str(dependency)], check=True)
    jar = root / "unique-owned-dependency.jar"
    subprocess.run(["jar", "--create", "--file", str(jar), "-C", str(root / "classes"), "."], check=True)
    jpype.startJVM(classpath=[str(jar)])
    from java.lang import System
    receipt["java_version"] = str(System.getProperty("java.version"))
    def handles():
        found = []
        for fd in pathlib.Path("/proc/self/fd").iterdir():
            try:
                if os.readlink(fd) == str(jar):
                    found.append(fd.name)
            except FileNotFoundError:
                pass
        return sorted(found)
    receipt["before_handles"] = handles()
    assert not receipt["before_handles"], receipt
    if a.phase == "fixed":
        marker = "        fman = compiler.getStandardFileManager(None, None, None)"
        assert source.count(marker) == 1
        before, after = source.split(marker)
        source = before + "        with compiler.getStandardFileManager(None, None, None) as fman:" + "\n".join("    " + line if line else line for line in after.split("\n"))
    module = root / "javac_under_test.py"
    module.write_text(source)
    spec = importlib.util.spec_from_file_location("javac_under_test", module)
    javac = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(javac)
    consumer = root / "Consumer.java"
    body = "return owned.Dependency.value();" if a.outcome == "success" else "return owned.Dependency.value() + missingSymbol;"
    consumer.write_text("public class Consumer { public static int value() { " + body + " } }")
    output = root / "output.jar"
    try:
        javac.java_compile(consumer, output)
        receipt["exception"] = None
    except ValueError as error:
        receipt["exception"] = type(error).__name__
        receipt["diagnostics"] = str(error)
    receipt["after_handles"] = handles()
    if a.outcome == "success":
        assert receipt["exception"] is None and output.is_file(), receipt
        # Loading occurs after descriptor observation so classloader JAR caching
        # cannot contaminate the ownership measurement.
        from java.net import URLClassLoader
        from java.io import File
        with URLClassLoader([File(str(output)).toURI().toURL()]) as loader:
            value = loader.loadClass("Consumer").getMethod("value").invoke(None)
            receipt["compiled_value"] = int(value)
            assert receipt["compiled_value"] == 42
    else:
        assert receipt["exception"] == "ValueError" and "missingSymbol" in receipt["diagnostics"], receipt
        assert not output.exists()
    receipt["status"] = "observed"
    print(json.dumps(receipt, indent=2))
    jpype.shutdownJVM()
