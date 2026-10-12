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
package ghidra.app.plugin.core.decompile;

import static org.junit.Assert.*;
import java.util.*;
import org.junit.*;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.*;
import ghidra.framework.plugintool.ServiceProviderStub;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.bean.field.AnnotatedTextFieldElement;
import utility.function.Callback;
import docking.widgets.fieldpanel.Layout;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import java.awt.event.MouseEvent;
import java.math.BigInteger;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;

/** Actual native typed-pointer tokens and their public Java navigation consumer. */
public class TypedFunctionPointerTokenCharacterizationTest extends AbstractGhidraHeadlessIntegrationTest {
    private ProgramBuilder builder;
    private Program program;
    private DecompInterface decompiler;
    private Function target;
    private DataType callback;
    @Before public void setUp() throws Exception {
        builder = new ProgramBuilder("TypedFunctionToken", ProgramBuilder._X64, "gcc", null);
        program = builder.getProgram();
        builder.setExecute(builder.createMemory(".text", "1000", 0x3000), true);
        builder.setBytes("2000", "c3", true);
        target = builder.createEmptyFunction("ActualCallback", "2000", 1, VoidDataType.dataType);
        FunctionDefinitionDataType definition = new FunctionDefinitionDataType("CallbackSignature");
        definition.setReturnType(VoidDataType.dataType);
        callback = new PointerDataType(definition, 8);
        decompiler = new DecompInterface();
        assertTrue(decompiler.openProgram(program));
    }
    @After public void tearDown() {
        try { if (decompiler != null) { decompiler.dispose(); } }
        finally { if (builder != null) { builder.dispose(); } }
    }
    private Function function(String name, String bytes, DataType parameter) throws Exception {
        builder.setBytes("1000", bytes, true);
        return builder.createEmptyFunction(name, "1000", bytes.split(" ").length,
            VoidDataType.dataType, parameter == null ? new Parameter[0] :
            new Parameter[] { new ParameterImpl("destination", parameter, program) });
    }
    private List<ClangNode> tokens(Function function) {
        program.flushEvents();
        decompiler.flushCache();
        DecompileResults result = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
        assertTrue(result.getErrorMessage(), result.decompileCompleted());
        assertNotNull(result.getHighFunction());
        assertNotNull(result.getCCodeMarkup());
        System.out.println("TYPED_FN_C caller=" + function.getName() + " code=" +
            result.getDecompiledFunction().getC().replace('\n', ' '));
        List<ClangNode> nodes = new ArrayList<>();
        result.getCCodeMarkup().flatten(nodes);
        observeActualPanelNavigation(function, result, nodes);
        return nodes;
    }
    private static class RecordingNavigation implements DecompilerCallbackHandler {
        String method = "NONE", destination = "NONE";
        public void decompileDataChanged(DecompileData data) { }
        public void contextChanged() { }
        public void setStatusMessage(String message) { }
        public void locationChanged(ProgramLocation location) { }
        public void selectionChanged(ProgramSelection selection) { }
        public void annotationClicked(AnnotatedTextFieldElement element, boolean newWindow) { }
        public void goToLabel(String label, boolean newWindow) { method="LABEL"; destination=label; }
        public void goToAddress(Address address, boolean newWindow) { method="ADDRESS"; destination=address.toString(); }
        public void goToScalar(long value, boolean newWindow) { method="SCALAR"; destination=Long.toHexString(value); }
        public void exportLocation() { }
        public void goToFunction(Function function, boolean newWindow) { method="FUNCTION"; destination=function.getEntryPoint().toString(); }
        public void doWhenNotBusy(Callback callback) { }
    }
    private void observeActualPanelNavigation(Function caller, DecompileResults result, List<ClangNode> nodes) {
        RecordingNavigation recording = new RecordingNavigation();
        DecompilerController[] owner = new DecompilerController[1];
        try {
            runSwing(() -> {
                owner[0] = new DecompilerController(new ServiceProviderStub(), recording, new DecompileOptions(), null);
                owner[0].setDecompileData(new DecompileData(program, caller,
                    new ProgramLocation(program, caller.getEntryPoint()), result, null, null, null));
                DecompilerPanel panel=owner[0].getDecompilerPanel();
                for (ClangNode node : nodes) {
                    if (!(node instanceof ClangToken token) ||
                        (!token.getText().equals(target.getName()) && !token.getText().equals(caller.getName()))) { continue; }
                    Varnode vn=token.getVarnode();
                    HighVariable high=token.getHighVariable();
                    HighSymbol symbol=token.getHighSymbol(result.getHighFunction());
                    System.out.println("TYPED_FN_TOKEN caller="+caller.getName()+" text="+token.getText()+
                        " class="+token.getClass().getSimpleName()+" parent="+token.Parent().getClass().getSimpleName()+
                        " op="+(token.getPcodeOp()==null ? "NONE" : token.getPcodeOp().getMnemonic())+
                        " varnode="+(vn==null ? "NONE" : vn.getAddress())+
                        " high="+(high==null ? "NONE" : high.getClass().getSimpleName())+
                        " symbol="+(symbol==null ? "NONE" : symbol.getName())+
                        " storage="+(symbol==null ? "NONE" : symbol.getStorage().getMinAddress()));
                    boolean clicked=false;
                    for (BigInteger index=BigInteger.ZERO; index.compareTo(panel.getFieldPanel().getLayoutModel().getNumIndexes())<0 && !clicked; index=index.add(BigInteger.ONE)) {
                        Layout layout=panel.getFieldPanel().getLayoutModel().getLayout(index);
                        for (int fieldIndex=0; fieldIndex<layout.getNumFields() && !clicked; fieldIndex++) {
                            Field field=layout.getField(fieldIndex);
                            if (!(field instanceof ClangTextField textField)) { continue; }
                            for (int column=0; column<field.getText().length(); column++) {
                                FieldLocation location=new FieldLocation(index, fieldIndex, 0, column);
                                if (textField.getToken(location)!=token) { continue; }
                                recording.method="NONE"; recording.destination="NONE";
                                MouseEvent click=new MouseEvent(panel.getFieldPanel(), MouseEvent.MOUSE_PRESSED,
                                    System.currentTimeMillis(), 0, 0, 0, 2, false, MouseEvent.BUTTON1);
                                panel.buttonPressed(location, field, click);
                                System.out.println("TYPED_FN_CLICK caller="+caller.getName()+" text="+token.getText()+
                                    " class="+token.getClass().getSimpleName()+" callback="+recording.method+
                                    " destination="+recording.destination);
                                clicked=true;break;
                            }
                        }
                    }
                    assertTrue("Actual native token must exist in actual panel layout", clicked);
                }
            });
        }
        finally { if (owner[0]!=null) { runSwing(() -> owner[0].dispose()); } }
    }
    private ClangFuncNameToken named(List<ClangNode> nodes, String name) {
        List<ClangFuncNameToken> matches = nodes.stream()
            .filter(n -> n instanceof ClangFuncNameToken)
            .map(n -> (ClangFuncNameToken)n).filter(n -> n.getText().equals(name)).toList();
        assertEquals("Actual native function-name token must be present exactly once: " + name, 1, matches.size());
        return matches.get(0);
    }
    private void observe(String name, ClangFuncNameToken token) {
        Function resolved = DecompilerUtils.getFunction(program, token);
        System.out.println("TYPED_FN_OBSERVATION case=" + name + " text=" + token.getText() +
            " op=" + (token.getPcodeOp() == null ? "NONE" : token.getPcodeOp().getMnemonic()) +
            " resolved=" + (resolved == null ? "NONE" : resolved.getName()));
    }
    @Test public void testTypedPointerStoreResolvesActualTarget() throws Exception {
        Function caller = function("StoreCallback", "48 c7 07 00 20 00 00 c3", new PointerDataType(callback, 8));
        assertTrue(caller.getParameter(0).getDataType() instanceof Pointer);
        ClangFuncNameToken token = named(tokens(caller), target.getName());
        observe("typed-store", token);
        assertEquals("Typed function-pointer store token must resolve its target", target,
            DecompilerUtils.getFunction(program, token));
    }
    @Test public void testTypedCallbackArgumentResolvesActualTarget() throws Exception {
        builder.setBytes("3000", "c3", true);
        builder.createEmptyFunction("ActualDispatcher", "3000", 1, VoidDataType.dataType,
            new ParameterImpl("callback", callback, program));
        Function caller = function("PassCallback", "bf 00 20 00 00 e8 f6 1f 00 00 c3", null);
        List<ClangNode> nodes = tokens(caller);
        ClangFuncNameToken token = named(nodes, target.getName());
        observe("typed-argument", token);
        assertEquals("Typed callback argument token must resolve callback rather than dispatcher", target,
            DecompilerUtils.getFunction(program, token));
    }
    @Test public void testIntegerAddressCoincidenceRetainsInteger() throws Exception {
        Function caller = function("StoreInteger", "48 c7 07 00 20 00 00 c3",
            new PointerDataType(UnsignedLongLongDataType.dataType, 8));
        List<ClangNode> nodes = tokens(caller);
        assertFalse(nodes.stream().anyMatch(n -> n instanceof ClangFuncNameToken &&
            ((ClangFuncNameToken)n).getText().equals(target.getName())));
        assertTrue(nodes.stream().anyMatch(n -> n instanceof ClangToken && ((ClangToken)n).getText().contains("2000")));
        System.out.println("TYPED_FN_CONTROL case=integer preserved=true");
    }
    @Test public void testDirectCallResolvesActualTarget() throws Exception {
        Function caller = function("CallCallback", "e8 fb 0f 00 00 c3", null);
        ClangFuncNameToken token = named(tokens(caller), target.getName());
        observe("direct-call", token);
        assertEquals(target, DecompilerUtils.getFunction(program, token));
    }
    @Test public void testPrototypeResolvesContainingFunction() throws Exception {
        Function caller = function("PrototypeControl", "c3", null);
        ClangFuncNameToken token = named(tokens(caller), caller.getName());
        observe("prototype", token);
        assertEquals(caller, DecompilerUtils.getFunction(program, token));
    }
    @Test public void testUnknownTypedPointerDoesNotInventFunction() throws Exception {
        Function caller = function("UnknownCallback", "48 c7 07 00 25 00 00 c3", new PointerDataType(callback, 8));
        List<ClangNode> nodes = tokens(caller);
        assertFalse(nodes.stream().anyMatch(n -> n instanceof ClangFuncNameToken &&
            !((ClangFuncNameToken)n).getText().equals(caller.getName())));
        System.out.println("TYPED_FN_CONTROL case=unknown preserved=true");
    }
}
