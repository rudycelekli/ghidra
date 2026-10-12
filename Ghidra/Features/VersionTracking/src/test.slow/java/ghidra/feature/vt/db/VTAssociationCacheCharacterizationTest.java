/* ###
 * IP: GHIDRA
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
 */
package ghidra.feature.vt.db;

import static org.junit.Assert.*;
import org.junit.*;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.VTTestEnv;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

/** Fork-only observations using owned programs and public association producers. */
public class VTAssociationCacheCharacterizationTest extends AbstractGhidraHeadedIntegrationTest {
    private static String priorTimeout;

    @BeforeClass
    public static void boundExistingWatchdog() {
        priorTimeout = System.getProperty("ghidra.test.property.timeout.milliseconds");
        System.setProperty("ghidra.test.property.timeout.milliseconds", "60000");
    }

    @AfterClass
    public static void restoreExistingWatchdog() {
        if (priorTimeout == null) { System.clearProperty("ghidra.test.property.timeout.milliseconds"); }
        else { System.setProperty("ghidra.test.property.timeout.milliseconds", priorTimeout); }
    }

    private VTTestEnv env;
    private Program source;
    private Program destination;
    private VTSessionDB session;
    private int transaction = -1;

    @Before
    public void setUp() throws Exception {
        setErrorGUIEnabled(false);
        env = new VTTestEnv();
        source = createProgram("CacheSource");
        destination = createProgram("CacheDestination");
        session = env.createSession(source, destination);
        transaction = session.startTransaction("Cache characterization");
    }

    private Program createProgram(String name) throws Exception {
        ProgramBuilder builder = new ProgramBuilder(name, ProgramBuilder._X86, env);
        try {
            builder.createMemory(".data", "0x1000", 0x1000);
            return builder.getProgram();
        }
        catch (Exception | Error failure) {
            if (builder.getProgram().isUsedBy(env)) { builder.getProgram().release(env); }
            throw failure;
        }
        finally { builder.dispose(); }
    }

    @After
    public void tearDown() throws Exception {
        try {
            if (transaction != -1) { session.endTransaction(transaction, false); }
        }
        finally {
            try { if (env != null) { env.dispose(); } }
            finally {
            if (source != null && source.isUsedBy(env)) { source.release(env); }
            if (destination != null && destination.isUsedBy(env)) { destination.release(env); }
            }
        }
    }

    private VTAssociation add(long src, long dst) {
        VTMatchInfo info = new VTMatchInfo(session.getManualMatchSet());
        info.setSourceAddress(source.getAddressFactory().getDefaultAddressSpace().getAddress(src));
        info.setDestinationAddress(destination.getAddressFactory().getDefaultAddressSpace().getAddress(dst));
        info.setSourceLength(1);
        info.setDestinationLength(1);
        info.setSimilarityScore(new VTScore(1));
        info.setConfidenceScore(new VTScore(1));
        info.setAssociationType(VTAssociationType.DATA);
        return session.getManualMatchSet().addMatch(info).getAssociation();
    }

    private VTAssociation competitor(boolean bySource, int index) {
        return add(bySource ? 0x1000 : 0x1000 + index * 0x10,
            bySource ? 0x1000 + index * 0x10 : 0x1000);
    }

    private void observe(boolean bySource, String action, VTAssociation association) {
        System.out.println("VT_CACHE side=" + (bySource ? "source" : "destination") +
            " action=" + action + " status=" + association.getStatus());
    }

    private void preexisting(boolean bySource, boolean clear) throws Exception {
        VTAssociation accepted = add(0x1000, 0x1000);
        VTAssociation blocked = competitor(bySource, 1);
        accepted.setAccepted();
        assertEquals(VTAssociationStatus.ACCEPTED, accepted.getStatus());
        assertEquals(VTAssociationStatus.BLOCKED, blocked.getStatus());
        VTAssociation later = competitor(bySource, 2);
        observe(bySource, clear ? "before-clear" : "after-block", later);
        if (clear) {
            accepted.clearStatus();
            assertEquals(VTAssociationStatus.AVAILABLE, accepted.getStatus());
            assertEquals(VTAssociationStatus.AVAILABLE, blocked.getStatus());
            assertEquals(VTAssociationStatus.AVAILABLE, later.getStatus());
        }
        else { assertEquals("Later competitor must remain blocked", VTAssociationStatus.BLOCKED, later.getStatus()); }
    }

    private void updated(boolean bySource, boolean reject) throws Exception {
        VTAssociation accepted = add(0x1000, 0x1000);
        accepted.setAccepted();
        VTAssociation blocked = competitor(bySource, 1);
        assertEquals(VTAssociationStatus.BLOCKED, blocked.getStatus());
        if (reject) { blocked.setRejected(); }
        else { blocked.setVoteCount(2); }
        assertEquals(VTAssociationStatus.ACCEPTED, accepted.getStatus());
        VTAssociation later = competitor(bySource, 2);
        observe(bySource, reject ? "after-reject" : "after-vote", later);
        assertEquals("Updated competitor must preserve accepted addresses", VTAssociationStatus.BLOCKED, later.getStatus());
    }

    private void clearAfterVote(boolean bySource) throws Exception {
        VTAssociation accepted = add(0x1000, 0x1000);
        accepted.setAccepted();
        VTAssociation blocked = competitor(bySource, 1);
        assertEquals(VTAssociationStatus.BLOCKED, blocked.getStatus());
        blocked.setVoteCount(2);
        VTAssociation later = competitor(bySource, 2);
        observe(bySource, "clear-after-vote", later);
        accepted.clearStatus();
        assertEquals(VTAssociationStatus.AVAILABLE, accepted.getStatus());
        assertEquals(VTAssociationStatus.AVAILABLE, blocked.getStatus());
        assertEquals(VTAssociationStatus.AVAILABLE, later.getStatus());
    }

    private void reload(boolean bySource) throws Exception {
        VTAssociation accepted = add(0x1000, 0x1000);
        accepted.setAccepted();
        session.endTransaction(transaction, true);
        transaction = -1;
        int change = session.startTransaction("Vote to undo");
        accepted.setVoteCount(7);
        session.endTransaction(change, true);
        assertTrue(session.canUndo());
        session.undo();
        transaction = session.startTransaction("After undo");
        assertEquals(VTAssociationStatus.ACCEPTED, accepted.getStatus());
        assertEquals(0, accepted.getVoteCount());
        VTAssociation later = competitor(bySource, 1);
        observe(bySource, "after-undo", later);
        assertEquals("Reload must retain accepted addresses", VTAssociationStatus.BLOCKED, later.getStatus());
    }

    private void normal(boolean bySource, boolean unrelatedUpdate) throws Exception {
        VTAssociation accepted = add(0x1000, 0x1000);
        accepted.setAccepted();
        if (unrelatedUpdate) { add(0x1080, 0x1080).setVoteCount(3); }
        VTAssociation later = competitor(bySource, 1);
        observe(bySource, unrelatedUpdate ? "unrelated-control" : "normal-control", later);
        assertEquals(VTAssociationStatus.BLOCKED, later.getStatus());
        accepted.clearStatus();
        assertEquals(VTAssociationStatus.AVAILABLE, later.getStatus());
    }

    @Test public void testPreexistingSource() throws Exception { preexisting(true, false); }
    @Test public void testPreexistingDestination() throws Exception { preexisting(false, false); }
    @Test public void testClearSource() throws Exception { preexisting(true, true); }
    @Test public void testClearDestination() throws Exception { preexisting(false, true); }
    @Test public void testVoteSource() throws Exception { updated(true, false); }
    @Test public void testVoteDestination() throws Exception { updated(false, false); }
    @Test public void testRejectSource() throws Exception { updated(true, true); }
    @Test public void testRejectDestination() throws Exception { updated(false, true); }
    @Test public void testClearAfterVoteSource() throws Exception { clearAfterVote(true); }
    @Test public void testClearAfterVoteDestination() throws Exception { clearAfterVote(false); }
    @Test public void testReloadSource() throws Exception { reload(true); }
    @Test public void testReloadDestination() throws Exception { reload(false); }
    @Test public void testNormalSource() throws Exception { normal(true, false); }
    @Test public void testNormalDestination() throws Exception { normal(false, false); }
    @Test public void testUnrelatedSource() throws Exception { normal(true, true); }
    @Test public void testUnrelatedDestination() throws Exception { normal(false, true); }
}
