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
package docking;

import static org.junit.Assert.*;

import java.awt.*;
import java.awt.event.InputEvent;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;

import javax.imageio.ImageIO;
import javax.swing.*;

import org.junit.*;

import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.test.*;

public class WindowMenuOverflowCharacterizationTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private PluginTool tool;
	private List<FixtureProvider> providers = new ArrayList<>();

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.showTool();
		runSwing(() -> {
			tool.getToolFrame().setBounds(20, 20, 1000, 650);
			for (int i = 0; i < 60; i++) {
				FixtureProvider provider = new FixtureProvider(String.format("Overflow Provider %03d", i), null);
				providers.add(provider);
				tool.addComponentProvider(provider, false);
			}
			for (int i = 0; i < 3; i++) {
				FixtureProvider provider = new FixtureProvider("Grouped Provider " + i, "Fixture Group");
				providers.add(provider);
				tool.addComponentProvider(provider, false);
			}
		});
		waitForCondition(() -> runSwing(() -> {
			JMenu menu = findWindowMenu();
			return menu != null && menu.getItemCount() >= 60;
		}));
	}

	@After
	public void tearDown() {
		if (env != null) {
			env.dispose();
		}
	}

	@Test
	public void testActualProviderMenuExceedsLowScreenBounds() throws Exception {
		JMenu menu = runSwing(this::findWindowMenu);
		runSwing(() -> {
			menu.doClick();
		});
		waitForCondition(() -> runSwing(() -> menu.getPopupMenu().isShowing()));
		Rectangle usable = runSwing(this::usableBounds);
		assertEquals("Hosted display must use the reviewed low-height screen", 768,
			tool.getToolFrame().getGraphicsConfiguration().getBounds().height);
		Rectangle popup = runSwing(() -> screenBounds(menu.getPopupMenu()));
		JMenuItem first = runSwing(() -> findItem(menu, "Overflow Provider 000"));
		JMenuItem last = runSwing(() -> findItem(menu, "Overflow Provider 059"));
		assertNotNull(first);
		assertNotNull(last);
		Rectangle firstBounds = runSwing(() -> screenBounds(first));
		Rectangle lastBounds = runSwing(() -> screenBounds(last));
		assertTrue("First provider must be physically on-screen", usable.contains(firstBounds));
		assertFalse("Last provider starts outside the visible viewport", usable.contains(lastBounds));
		assertTrue("Actual popup exceeds usable screen height", popup.height > usable.height);
		Path evidence = Paths.get(System.getenv("WINDOW_MENU_EVIDENCE_DIR"));
		Files.createDirectories(evidence);
		Files.writeString(evidence.resolve("window-menu-measurements.txt"),
			"usable=" + usable + "\npopup=" + popup + "\nfirst=" + firstBounds +
			"\nlast=" + lastBounds + "\nproviderCount=" + providers.size() + "\n");
		Robot robot = new Robot();
		ImageIO.write(robot.createScreenCapture(usable), "png",
			evidence.resolve("window-menu-low-screen.png").toFile());
		robot.mouseMove(firstBounds.x + firstBounds.width / 2, firstBounds.y + firstBounds.height / 2);
		robot.mousePress(InputEvent.BUTTON1_DOWN_MASK);
		robot.mouseRelease(InputEvent.BUTTON1_DOWN_MASK);
		waitForCondition(() -> runSwing(() -> providers.get(0).isVisible()));
		JMenu reopened = runSwing(this::findWindowMenu);
		runSwing(() -> {
			reopened.doClick();
		});
		waitForCondition(() -> runSwing(() -> reopened.getPopupMenu().isShowing()));
		JMenuItem lastAfterReopen = runSwing(() -> findItem(reopened, "Overflow Provider 059"));
		assertNotNull(lastAfterReopen);
		robot.mouseMove(firstBounds.x + firstBounds.width / 2, usable.y + usable.height / 2);
		robot.mouseWheel(100);
		waitForCondition(() -> runSwing(() -> usable.contains(screenBounds(lastAfterReopen))));
		Rectangle scrolledLast = runSwing(() -> screenBounds(lastAfterReopen));
		Files.writeString(evidence.resolve("window-menu-scrolled-measurements.txt"),
			"laf=" + UIManager.getLookAndFeel().getClass().getName() +
			"\npopupUI=" + reopened.getPopupMenu().getUI().getClass().getName() +
			"\nlastAfterWheel=" + scrolledLast + "\n");
		ImageIO.write(robot.createScreenCapture(usable), "png",
			evidence.resolve("window-menu-after-scroll.png").toFile());
		robot.mouseMove(scrolledLast.x + scrolledLast.width / 2,
			scrolledLast.y + scrolledLast.height / 2);
		robot.mousePress(InputEvent.BUTTON1_DOWN_MASK);
		robot.mouseRelease(InputEvent.BUTTON1_DOWN_MASK);
		waitForCondition(() -> runSwing(() -> providers.get(59).isVisible()));
	}

	@Test
	public void testDeclaredProviderGroupAndActivationArePreserved() {
		JMenu menu = runSwing(this::findWindowMenu);
		JMenu group = runSwing(() -> (JMenu) findItem(menu, "Fixture Group"));
		assertNotNull(group);
		assertEquals(4L, runSwing(() -> java.util.Arrays.stream(group.getMenuComponents())
			.filter(JMenuItem.class::isInstance).count()).longValue());
		assertNotNull(runSwing(() -> findItem(group, "Show All")));
		JMenuItem item = runSwing(() -> findItem(group, "Grouped Provider 0"));
		assertNotNull(item);
		runSwing(() -> {
			item.doClick();
		});
		waitForCondition(() -> runSwing(() -> providers.get(60).isVisible()));
	}

	private JMenu findWindowMenu() {
		JMenuBar bar = ((JFrame) tool.getToolFrame()).getJMenuBar();
		for (int i = 0; i < bar.getMenuCount(); i++) {
			JMenu menu = bar.getMenu(i);
			if (menu != null && "Window".equals(menu.getText())) {
				return menu;
			}
		}
		return null;
	}

	private JMenuItem findItem(JMenu menu, String title) {
		for (Component component : menu.getMenuComponents()) {
			if (component instanceof JMenuItem item && title.equals(item.getText())) {
				return item;
			}
		}
		return null;
	}

	private Rectangle usableBounds() {
		GraphicsConfiguration gc = tool.getToolFrame().getGraphicsConfiguration();
		Rectangle bounds = new Rectangle(gc.getBounds());
		Insets insets = Toolkit.getDefaultToolkit().getScreenInsets(gc);
		bounds.x += insets.left;
		bounds.y += insets.top;
		bounds.width -= insets.left + insets.right;
		bounds.height -= insets.top + insets.bottom;
		return bounds;
	}

	private Rectangle screenBounds(Component component) {
		return new Rectangle(component.getLocationOnScreen(), component.getSize());
	}

	private class FixtureProvider extends ComponentProviderAdapter {
		private JPanel panel = new JPanel();

		FixtureProvider(String name, String group) {
			super(WindowMenuOverflowCharacterizationTest.this.tool, name, "Window Menu Characterization");
			if (group != null) {
				setWindowMenuGroup(group);
			}
		}

		@Override
		public JComponent getComponent() {
			return panel;
		}
	}
}
