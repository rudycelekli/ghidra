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
package ghidra.app.util;

import static org.junit.Assert.*;
import java.util.*;
import org.junit.*;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

/** Real namespace creation and public qualified-symbol lookup. */
public class TemplateOperatorLookupCharacterizationTest extends AbstractGhidraHeadedIntegrationTest {
    private ProgramDB program;
    private int transaction = -1;
    private static final String TEMPLATE = "basic_ostream<char,std::char_traits<char>_>";

    @Before public void setUp() throws Exception {
        program = createDefaultProgram("TemplateOperatorLookup", ProgramBuilder._TOY, this);
        transaction = program.startTransaction("Public symbol producers");
    }

    @After public void tearDown() {
        if (program != null) {
            try { if (transaction != -1) { program.endTransaction(transaction, false); } }
            finally { program.release(this); }
        }
    }

    private Symbol create(List<String> namespaces, String name) throws Exception {
        SymbolTable table = program.getSymbolTable();
        Namespace parent = program.getGlobalNamespace();
        for (String component : namespaces) {
            parent = table.createNameSpace(parent, component, SourceType.USER_DEFINED);
            assertEquals(component, parent.getName());
        }
        Symbol symbol = table.createLabel(program.getAddressFactory().getDefaultAddressSpace()
            .getAddress(0x1000), name, parent, SourceType.USER_DEFINED);
        assertEquals(name, symbol.getName());
        assertEquals(parent.getID(), symbol.getParentNamespace().getID());
        assertTrue(table.getSymbols(name, parent).contains(symbol));
        return symbol;
    }

    private void lookup(List<String> namespaces, String name) throws Exception {
        Symbol expected = create(namespaces, name);
        String path = String.join("::", namespaces) + "::" + name;
        List<Symbol> actual = NamespaceUtils.getSymbols(path, program);
        System.out.println("TEMPLATE_OPERATOR_LOOKUP name=" + name + " path=" + path +
            " directId=" + expected.getID() + " matches=" + actual.size());
        assertEquals("Qualified lookup must preserve template namespace before " + name,
            1, actual.size());
        assertEquals(expected.getID(), actual.get(0).getID());
        assertEquals(expected.getAddress(), actual.get(0).getAddress());
    }

    @Test public void testTemplateShiftLeft() throws Exception {
        lookup(List.of("std", TEMPLATE), "operator<<");
    }
    @Test public void testTemplateShiftRight() throws Exception {
        lookup(List.of("std", TEMPLATE), "operator>>");
    }
    @Test public void testTemplateLessEqual() throws Exception {
        lookup(List.of("std", TEMPLATE), "operator<=");
    }
    @Test public void testTemplateGreaterEqual() throws Exception {
        lookup(List.of("std", TEMPLATE), "operator>=");
    }
    @Test public void testBalancedTemplateOrdinarySymbol() throws Exception {
        lookup(List.of("std", TEMPLATE), "flush");
    }
    @Test public void testOrdinaryNamespaceOperator() throws Exception {
        lookup(List.of("ordinary"), "operator<<");
    }
    @Test public void testMissingSymbolStaysMissing() throws Exception {
        create(List.of("std", TEMPLATE), "flush");
        assertTrue(NamespaceUtils.getSymbols("std::" + TEMPLATE + "::missing", program).isEmpty());
        System.out.println("TEMPLATE_OPERATOR_LOOKUP control=missing matches=0");
    }
    @Test public void testExistingUnbalancedFallbackLookup() throws Exception {
        String path = "A::operator<=::B<C<int>::<unnamed-tag>>::E";
        List<String> fallback = List.of("A", "operator<=", "B<C<int>", "<unnamed-tag>>", "E");
        assertEquals(fallback, SymbolPathParser.parse(path));
        lookup(fallback.subList(0, 4), "E");
    }
}
