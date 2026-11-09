package permanentbeta.core;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * The extension's tests, as a plain main: Ghidra ships no JUnit and the build stays offline. Exits non-zero on
 * the first failure. The pbeta-mcp replies in {@code mcp-replies.jsonl} were recorded from the real server on
 * the hook loop's v2 -> v3 store (corpus/hooks, /O2): the ambiguous {@code checksum} item and {@code log_event}.
 */
public final class SelfTest {
	private static final String CHECKSUM = "checksum:55971b52411e:b47be65fec8b";
	private static final String V3 = "b47be65fec8bea31b7f6ac64ae59417f3354d2a9b9512f22b5a2a304a7b01056";
	private static int passed;

	public static void main(String[] args) throws Exception {
		List<Runnable> tests = List.of(
			SelfTest::listsRecordedReviewItems,
			SelfTest::explainsCandidatesWithChecks,
			SelfTest::toolErrorIsThrownWithServerMessage,
			SelfTest::refusesToCallProposeMapping,
			SelfTest::serverExitIsAnError,
			SelfTest::mismatchedReplyIdIsAnError,
			SelfTest::programIsTheBuildOnlyByFullHash,
			SelfTest::parsesRvas,
			SelfTest::acceptAndRejectCommands,
			SelfTest::decisionNeedsReviewerAndStore,
			SelfTest::refusedDecisionSurfacesPbetaMessage,
			SelfTest::malformedItemIsRefused);
		for (Runnable t : tests) {
			t.run();
		}
		System.out.println("SelfTest: " + passed + " checks passed (" + tests.size() + " tests)");
	}

	// --- pbeta-mcp client --------------------------------------------------------------------------------------

	private static void listsRecordedReviewItems() {
		Session s = recorded();
		List<Review.Item> items = unchecked(() -> Review.parseItems(
			s.client.callTool("list_review_items", obj("status", "all"))));
		eq(2, items.size(), "two review items");
		Review.Item checksum = items.stream().filter(i -> i.id().equals(CHECKSUM)).findFirst().orElseThrow();
		eq("ambiguous", checksum.reason(), "reason");
		eq("0x1040", checksum.old(), "old rva");
		eq(V3, checksum.toBuild(), "to build");
		eq(List.of("0x1040", "0x1070"),
			checksum.candidates().stream().map(Review.CandidateSummary::newRva).toList(), "candidates");
		// The client sent initialize, the initialized notification and the call, in that order.
		List<String> sent = s.sent();
		eq("initialize", method(sent.get(0)), "first message");
		eq("notifications/initialized", method(sent.get(1)), "second message");
		eq("tools/call", method(sent.get(2)), "third message");
	}

	private static void explainsCandidatesWithChecks() {
		Session s = recorded();
		unchecked(() -> s.client.callTool("list_review_items", obj("status", "all")));
		Review.Detail d = unchecked(() -> Review.parseDetail(
			s.client.callTool("explain_review_item", obj("id", CHECKSUM))));
		eq(2, d.candidates().size(), "candidates");
		Review.Candidate c = d.candidates().get(1);
		eq("0x1070", c.newRva(), "second candidate");
		eq("deterministic mnemonic-hash", c.source(), "source");
		eq(2L, c.countedPasses(), "counted passes (callers, constants)");
		eq(0L, c.failures(), "failures");
		Review.Check size = c.checks().stream().filter(k -> k.name().equals("size-ratio")).findFirst().orElseThrow();
		check(!size.counted(), "size-ratio passes but does not count");
		check(d.explanation().contains("the engine will not pick"), "explanation");
		check(d.decisions().isEmpty(), "no decisions yet");
	}

	private static void toolErrorIsThrownWithServerMessage() {
		Session s = recorded();
		unchecked(() -> s.client.callTool("list_review_items", obj("status", "all")));
		unchecked(() -> s.client.callTool("explain_review_item", obj("id", CHECKSUM)));
		PbetaException e = throwsPbeta(() -> s.client.callTool("explain_review_item", obj("id", "nope")));
		check(e.getMessage().startsWith("no review item nope"), "server's message: " + e.getMessage());
	}

	/** Negative: the extension never proposes (or decides) through the server; nothing is even sent. */
	private static void refusesToCallProposeMapping() {
		Session s = recorded();
		int before = s.sent().size();
		PbetaException e = throwsPbeta(() -> s.client.callTool("propose_mapping", obj("old", "0x1040")));
		check(e.getMessage().contains("does not call propose_mapping"), e.getMessage());
		eq(before, s.sent().size(), "nothing sent");
	}

	private static void serverExitIsAnError() {
		Session s = session(lines(recordedReplies()).subList(0, 1)); // initialize only, then EOF
		PbetaException e = throwsPbeta(() -> s.client.callTool("list_builds", null));
		check(e.getMessage().startsWith("pbeta-mcp exited"), e.getMessage());
	}

	private static void mismatchedReplyIdIsAnError() {
		List<String> replies = new ArrayList<>(lines(recordedReplies()).subList(0, 1));
		replies.add("{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"content\":[]}}");
		Session s = session(replies);
		PbetaException e = throwsPbeta(() -> s.client.callTool("list_builds", null));
		check(e.getMessage().contains("expected 2"), e.getMessage());
	}

	// --- builds and RVAs ---------------------------------------------------------------------------------------

	/** Negative cases: no hash, another build's hash, or a prefix is not the build. */
	private static void programIsTheBuildOnlyByFullHash() {
		check(Builds.isBuild(V3, V3), "same hash");
		check(Builds.isBuild(V3.toUpperCase(), V3), "case-insensitive");
		check(!Builds.isBuild(null, V3), "no recorded hash");
		check(!Builds.isBuild("", V3), "empty hash");
		check(!Builds.isBuild("55971b52411e2c33ea60f40114f738daee37ee6044c9cfd6946c0420efcb4fd3", V3),
			"another build");
		check(!Builds.isBuild(V3.substring(0, 12), V3.substring(0, 12)), "a prefix is not a build id");
	}

	private static void parsesRvas() {
		eq(0x1040L, unchecked(() -> Builds.parseRva("0x1040")), "hex");
		eq(4160L, unchecked(() -> Builds.parseRva("4160")), "decimal");
		throwsPbeta(() -> Builds.parseRva("0xzz"));
		throwsPbeta(() -> Builds.parseRva(""));
		throwsPbeta(() -> Builds.parseRva("-1"));
	}

	// --- decisions through pbeta review ------------------------------------------------------------------------

	private static void acceptAndRejectCommands() {
		ReviewCommand cmd = new ReviewCommand("pbeta", "s.json", c -> new ReviewCommand.Result(0, "", ""));
		eq(List.of("pbeta", "review", "accept", CHECKSUM, "--reviewer", "ryan", "--store", "s.json", "--candidate",
			"0x1070"), unchecked(() -> cmd.acceptCommand(CHECKSUM, "ryan", "0x1070", false, " ")), "accept");
		eq(List.of("pbeta", "review", "accept", CHECKSUM, "--reviewer", "ryan", "--store", "s.json", "--candidate",
			"0x1070", "--force", "--note", "checked"),
			unchecked(() -> cmd.acceptCommand(CHECKSUM, "ryan", "0x1070", true, "checked")), "forced accept");
		eq(List.of("pbeta", "review", "reject", CHECKSUM, "--reviewer", "ryan", "--store", "s.json"),
			unchecked(() -> cmd.rejectCommand(CHECKSUM, "ryan", null)), "reject");
	}

	/** Negative: no decision without a reviewer, a store or an item. */
	private static void decisionNeedsReviewerAndStore() {
		ReviewCommand cmd = new ReviewCommand("pbeta", "s.json", c -> new ReviewCommand.Result(0, "", ""));
		throwsPbeta(() -> cmd.acceptCommand(CHECKSUM, " ", "0x1070", false, null));
		throwsPbeta(() -> cmd.rejectCommand("", "ryan", null));
		ReviewCommand noStore = new ReviewCommand("pbeta", "", c -> new ReviewCommand.Result(0, "", ""));
		throwsPbeta(() -> noStore.rejectCommand(CHECKSUM, "ryan", null));
	}

	/** Negative: pbeta refusing (here, a rejected candidate without --force) is an error carrying its message. */
	private static void refusedDecisionSurfacesPbetaMessage() {
		String msg = "error: candidate 0x1100 was rejected by verification; pass --force to accept it anyway";
		ReviewCommand cmd = new ReviewCommand("pbeta", "s.json", c -> new ReviewCommand.Result(2, "", msg));
		PbetaException e = throwsPbeta(() -> cmd.run(cmd.acceptCommand("log_event:x:y", "ryan", "0x1100", false, null)));
		check(e.getMessage().contains("exit 2") && e.getMessage().contains(msg), e.getMessage());
		ReviewCommand ok = new ReviewCommand("pbeta", "s.json", c -> new ReviewCommand.Result(0, "recorded\n", ""));
		eq("recorded", unchecked(() -> ok.run(List.of("pbeta"))), "output on success");
	}

	private static void malformedItemIsRefused() {
		throwsPbeta(() -> Review.parseItems(JsonParser.parseString("[{\"status\":\"open\"}]")));
		throwsPbeta(() -> Review.parseItems(JsonParser.parseString("{}")));
		throwsPbeta(() -> Review.parseDetail(JsonParser.parseString("[]")));
	}

	// --- helpers -----------------------------------------------------------------------------------------------

	private record Session(McpClient client, ByteArrayOutputStream out) {
		List<String> sent() {
			return lines(out.toString(StandardCharsets.UTF_8));
		}
	}

	private static Session recorded() {
		return session(lines(recordedReplies()));
	}

	private static Session session(List<String> replies) {
		ByteArrayInputStream in =
			new ByteArrayInputStream((String.join("\n", replies) + "\n").getBytes(StandardCharsets.UTF_8));
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		McpClient c = new McpClient(in, out, null);
		unchecked(() -> {
			c.initialize();
			return null;
		});
		return new Session(c, out);
	}

	private static String recordedReplies() {
		try (InputStream s = SelfTest.class.getResourceAsStream("mcp-replies.jsonl")) {
			if (s == null) {
				throw new AssertionError("mcp-replies.jsonl not on the classpath");
			}
			return new String(s.readAllBytes(), StandardCharsets.UTF_8);
		}
		catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	private static List<String> lines(String s) {
		return s.lines().filter(l -> !l.isBlank()).toList();
	}

	private static String method(String line) {
		return JsonParser.parseString(line).getAsJsonObject().get("method").getAsString();
	}

	private static JsonObject obj(String key, String value) {
		JsonObject o = new JsonObject();
		o.addProperty(key, value);
		return o;
	}

	private interface Body<T> {
		T run() throws PbetaException;
	}

	private static <T> T unchecked(Body<T> b) {
		try {
			return b.run();
		}
		catch (PbetaException e) {
			throw new AssertionError("unexpected: " + e.getMessage(), e);
		}
	}

	private static PbetaException throwsPbeta(Body<?> b) {
		try {
			b.run();
		}
		catch (PbetaException e) {
			passed++;
			return e;
		}
		throw new AssertionError("expected a PbetaException");
	}

	private static void eq(Object want, Object got, String what) {
		if (!want.equals(got)) {
			throw new AssertionError(what + ": expected " + want + ", got " + got);
		}
		passed++;
	}

	private static void check(boolean ok, String what) {
		if (!ok) {
			throw new AssertionError(what);
		}
		passed++;
	}
}
