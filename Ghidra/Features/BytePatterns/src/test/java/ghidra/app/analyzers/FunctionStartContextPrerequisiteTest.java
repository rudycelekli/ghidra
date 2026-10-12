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
package ghidra.app.analyzers;

import static org.junit.Assert.*;
import java.math.BigInteger;
import org.junit.*;
import org.xml.sax.helpers.DefaultHandler;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.xml.*;

/** Actual XML parsing and effective processor-context prerequisites, without mode mutation. */
public class FunctionStartContextPrerequisiteTest extends AbstractGhidraHeadlessIntegrationTest {
    private ProgramDB program;
    private int transaction = -1;
    private Address address;
    private Register vle;
    private FunctionStartAnalyzer analyzer;

    @Before public void setUp() throws Exception {
        Language language = DefaultLanguageService.getLanguageService().getLanguage(
            new LanguageID("PowerPC:BE:64:VLE-32addr"));
        program = new ProgramDB("Context-prerequisite", language, language.getDefaultCompilerSpec(), this);
        transaction = program.startTransaction("Actual context fixture");
        address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
        vle = program.getProgramContext().getRegister("vle");
        assertNotNull(vle);
        assertTrue(vle.isProcessorContext());
        assertEquals(1, vle.getBitLength());
        program.getProgramContext().setValue(vle, address, address.add(0xf), BigInteger.ONE);
        analyzer = new FunctionStartAnalyzer();
    }
    @After public void tearDown() {
        if (program != null) {
            try { if (transaction >= 0) { program.endTransaction(transaction, false); } }
            finally { program.release(this); }
        }
    }
    private void restore(FunctionStartAnalyzer.FunctionStartAction action, String attributes) throws Exception {
        XmlPullParser parser = XmlPullParserFactory.create("<funcstart " + attributes + "/>",
            "Actual funcstart context XML", new DefaultHandler(), false);
        // Malformed requirements intentionally log errors. The unchanged analyzer also logs
        // unknown attributes when the same regression fixture runs against the baseline.
        setErrorsExpected(true);
        try { action.restoreXml(parser); }
        finally {
            try { setErrorsExpected(false); }
            finally { parser.dispose(); }
        }
    }
    private boolean accepts(String attributes) throws Exception {
        FunctionStartAnalyzer.FunctionStartAction action = analyzer.new FunctionStartAction();
        restore(action, attributes);
        BigInteger before = program.getProgramContext().getValue(vle, address, false);
        boolean result = action.checkPreRequisites(program, address);
        assertEquals("Prerequisite must not change processor mode", before,
            program.getProgramContext().getValue(vle, address, false));
        return result;
    }
    @Test public void testAbsentRequirementPreservesExistingPath() throws Exception {
        assertTrue(accepts(""));
    }
    @Test public void testKnownMatchingContext() throws Exception {
        assertTrue(accepts("context-register=\"vle\" context-value=\"1\""));
    }
    @Test public void testKnownDifferentContextRejected() throws Exception {
        assertFalse(accepts("context-register=\"vle\" context-value=\"0\""));
    }
    @Test public void testIncompletePairsRejected() throws Exception {
        assertFalse(accepts("context-register=\"vle\""));
        assertFalse(accepts("context-value=\"1\""));
    }
    @Test public void testMalformedValueRejected() throws Exception {
        assertFalse(accepts("context-register=\"vle\" context-value=\"bad\""));
    }
    @Test public void testUnknownRegisterRejected() throws Exception {
        assertFalse(accepts("context-register=\"missingContextRegister\" context-value=\"1\""));
    }
    @Test public void testNonContextRegisterRejected() throws Exception {
        Register r1 = program.getProgramContext().getRegister("r1");
        assertNotNull(r1);
        assertFalse(r1.isProcessorContext());
        assertFalse(accepts("context-register=\"r1\" context-value=\"1\""));
    }
    @Test public void testNegativeAndOversizedValuesRejected() throws Exception {
        assertFalse(accepts("context-register=\"vle\" context-value=\"-1\""));
        assertFalse(accepts("context-register=\"vle\" context-value=\"2\""));
        assertFalse(accepts("context-register=\"vle\" context-value=\"18446744073709551617\""));
    }
    @Test public void testXmlNumericNotation() throws Exception {
        assertTrue(accepts("context-register=\"vle\" context-value=\"0x1\""));
        assertTrue(accepts("context-register=\"vle\" context-value=\"01\""));
    }
    @Test public void testCaseDistinctDuplicateAttributesRejected() throws Exception {
        assertFalse(accepts("context-register=\"vle\" context-value=\"1\" CONTEXT-VALUE=\"bad\""));
        assertFalse(accepts("context-register=\"vle\" CONTEXT-REGISTER=\"vle\" context-value=\"1\""));
    }
    @Test public void testReusedActionRequirementReset() throws Exception {
        FunctionStartAnalyzer.FunctionStartAction action = analyzer.new FunctionStartAction();
        restore(action, "context-register=\"vle\" context-value=\"0\"");
        assertFalse(action.checkPreRequisites(program, address));
        restore(action, "");
        assertTrue(action.checkPreRequisites(program, address));
    }
    @Test public void testRawRegisterMasksDistinguishedFromEffectiveContext() {
        RegisterValue rawUnknown = new RegisterValue(vle);
        assertFalse(rawUnknown.hasValue());
        assertNull(rawUnknown.getUnsignedValue());
        Register base = vle.getBaseRegister();
        assertTrue(base.getBitLength() > 1);
        RegisterValue rawPartial = new RegisterValue(base, BigInteger.ONE, BigInteger.ONE);
        assertFalse(rawPartial.hasValue());
        assertNull(rawPartial.getUnsignedValue());
        RegisterValue effective = program.getProgramContext().getRegisterValue(vle, address);
        assertTrue(effective.hasValue());
        assertEquals(BigInteger.ONE, effective.getUnsignedValue());
    }
}
