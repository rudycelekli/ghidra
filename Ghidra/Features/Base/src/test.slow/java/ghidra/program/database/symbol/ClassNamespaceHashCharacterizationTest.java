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
package ghidra.program.database.symbol;

import static org.junit.Assert.*;
import java.util.*;
import org.junit.*;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

/** Real public namespace producers and the collections used by class recovery. */
public class ClassNamespaceHashCharacterizationTest extends AbstractGhidraHeadedIntegrationTest {
    private ProgramDB program;
    private int transaction = -1;

    @Before public void setUp() throws Exception {
        program = createDefaultProgram("ClassNamespaceHash", ProgramBuilder._TOY, this);
        transaction = program.startTransaction("Public namespace producers");
    }

    @After public void tearDown() {
        if (program != null) {
            try { if (transaction != -1) { program.endTransaction(transaction, false); } }
            finally { program.release(this); }
        }
    }

    private GhidraClass createClass() throws Exception {
        return program.getSymbolTable().createClass(program.getGlobalNamespace(),
            "RecoveredClass", SourceType.USER_DEFINED);
    }

    private Namespace canonical(Namespace created) {
        Namespace result = (Namespace) program.getSymbolTable()
            .getSymbol(created.getID()).getObject();
        assertNotSame("Exercise distinct public producer objects", created, result);
        assertEquals(created, result);
        assertEquals(result, created);
        assertEquals(created.getID(), result.getID());
        assertSame(created.getSymbol(), result.getSymbol());
        return result;
    }

    @Test public void testEquivalentClassMapLookup() throws Exception {
        GhidraClass created = createClass();
        Namespace retrieved = canonical(created);
        Map<Namespace, String> recoveredClasses = new HashMap<>();
        recoveredClasses.put(created, "existing recovered class");
        assertEquals("Equivalent class must find its existing recovery entry",
            "existing recovered class", recoveredClasses.get(retrieved));
        assertEquals(created.hashCode(), retrieved.hashCode());
        assertEquals(created.getSymbol().hashCode(), created.hashCode());
    }

    @Test public void testEquivalentClassSetRemoval() throws Exception {
        GhidraClass created = createClass();
        Namespace retrieved = canonical(created);
        Set<Namespace> pendingClasses = new HashSet<>();
        pendingClasses.add(created);
        assertTrue("Equivalent class must remove its pending entry", pendingClasses.remove(retrieved));
        assertTrue(pendingClasses.isEmpty());
    }

    @Test public void testOrdinaryNamespaceAndLibraryControls() throws Exception {
        SymbolTable symbols = program.getSymbolTable();
        Namespace ordinary = symbols.createNameSpace(program.getGlobalNamespace(),
            "Ordinary", SourceType.USER_DEFINED);
        Namespace library = symbols.createExternalLibrary("Library", SourceType.USER_DEFINED);
        for (Namespace created : List.of(ordinary, library)) {
            Namespace retrieved = canonical(created);
            Map<Namespace, String> entries = new HashMap<>();
            entries.put(created, "retained");
            assertEquals("retained", entries.get(retrieved));
            assertEquals(created.hashCode(), retrieved.hashCode());
            Set<Namespace> pending = new HashSet<>();
            pending.add(created);
            assertTrue(pending.remove(retrieved));
            assertTrue(pending.isEmpty());
        }
    }
}
