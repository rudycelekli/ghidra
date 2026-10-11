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

import java.util.List;
import java.io.File;
import java.lang.reflect.Field;

import ghidra.framework.Application;
import ghidra.framework.Platform;
import ghidra.app.decompiler.DecompileProcessFactory;

import org.junit.Test;

import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.ClangTextField;
import ghidra.app.plugin.core.decompile.actions.*;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.EquateSymbol;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateReference;
import ghidra.app.cmd.equate.SetEquateCmd;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;

public class DecompilerEquateReconversionInvestigationTest extends AbstractDecompilerTest {
	@Override
	protected Program getProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("equate-reconversion", ProgramBuilder._X86);
		builder.createMemory("code", "1000", 0x100);
		builder.setBytes("1000", "B8 05 00 00 AA C3");
		builder.disassemble("1000", 6);
		builder.createEmptyFunction("unsignedConstant", "1000", 6, UnsignedIntegerDataType.dataType);
		builder.withTransaction(() -> {
			Instruction instruction = builder.getProgram().getListing().getInstructionAt(builder.addr("1000"));
			Scalar scalar = instruction.getScalar(1);
			assertEquals(0xaa000005L, scalar.getUnsignedValue());
			// The public command used by ConvertCommand for the listing's
			// Convert To Unsigned Decimal action stores an operand reference.
			SetEquateCmd command = new SetEquateCmd(Long.toString(scalar.getUnsignedValue()),
				instruction.getAddress(), 1, scalar.getValue());
			assertTrue(command.getStatusMsg(), command.applyTo(builder.getProgram()));
		});
		return builder.getProgram();
	}

	@Test
	public void testListingDecimalEquateKeepsUnsignedValue() throws Exception {
		openDecimalListingEquate("control");
		assertScalarValue();
	}

	@Test
	public void testListingEquateCanBeConvertedAgain() throws Exception {
		openDecimalListingEquate("reconversion");
		ConvertHexAction action = new ConvertHexAction(decompiler);
		DecompilerActionContext context = context();
		assertTrue(action.isEnabledForContext(context));
		modifyProgram(p -> action.actionPerformed(context));
		waitForDecompiler();
		ClangTextField line = getLineContaining("0xaa000005");
		setDecompilerLocation(line.getLineNumber(), line.getText().indexOf("0xaa000005"));
		assertEquals("0xaa000005", getToken().getText());
		assertScalarValue();
	}

	private DecompilerActionContext context() {
		return new DecompilerActionContext(provider, getHighFunction().getFunction().getEntryPoint(), false);
	}

	private void openDecimalListingEquate(String label) throws Exception {
		decompile("1000");
		Field executablePath = DecompileProcessFactory.class.getDeclaredField("exepath");
		executablePath.setAccessible(true);
		File actualExecutable = new File((String) executablePath.get(null));
		File builtExecutable = new File(Application.getModuleRootDir("Decompiler").getFile(false),
			"build/os/" + Platform.CURRENT_PLATFORM.getDirectoryName() + "/decompile");
		assertEquals(builtExecutable.getCanonicalFile(), actualExecutable.getCanonicalFile());
		assertTrue(actualExecutable.isFile());
		System.out.println("EQUATE_CURRENT_NATIVE_EXECUTABLE test=" + label + " path=" + actualExecutable);
		ClangTextField line = getLineContaining("2852126725");
		setDecompilerLocation(line.getLineNumber(), line.getText().indexOf("2852126725"));
		ClangToken token = getToken();
		assertEquals("2852126725", token.getText());
		assertTrue(token.getHighVariable().getSymbol() instanceof EquateSymbol);
		List<Equate> equates = program.getEquateTable().getEquates(addr("1000"));
		assertEquals(1, equates.size());
		assertEquals(0xaa000005L, equates.get(0).getValue() & 0xffffffffL);
		List<EquateReference> references = equates.get(0).getReferences(addr("1000"));
		assertEquals(1, references.size());
		assertEquals(0, references.get(0).getDynamicHashValue());
		assertTrue(references.get(0).getOpIndex() >= 0);
		System.out.println("EQUATE_LISTING_DECIMAL_READY test=" + label + " value=2852126725 hash=0");
	}

	private void assertScalarValue() {
		assertEquals(0xaa000005L, getToken().getVarnode().getOffset() & 0xffffffffL);
		assertEquals(4, getToken().getVarnode().getSize());
	}
}
