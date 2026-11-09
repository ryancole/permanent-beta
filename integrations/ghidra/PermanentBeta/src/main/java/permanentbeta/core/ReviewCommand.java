package permanentbeta.core;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

/**
 * Records a review decision by running {@code pbeta review accept|reject}, the only thing that decides an item
 * (design §9.1). The extension never writes the store itself; pbeta's refusals (a candidate verification
 * rejected without force, a function another mapping claims, an item already decided) come back as they are.
 */
public final class ReviewCommand {
	/** Runs a command; replaceable in tests. */
	public interface Runner {
		Result run(List<String> command) throws PbetaException;
	}

	public record Result(int exitCode, String stdout, String stderr) {
	}

	private final String pbeta;
	private final String store;
	private final Runner runner;

	public ReviewCommand(String pbeta, String store, Runner runner) {
		this.pbeta = pbeta;
		this.store = store;
		this.runner = runner;
	}

	public ReviewCommand(String pbeta, String store) {
		this(pbeta, store, ReviewCommand::runProcess);
	}

	/** {@code candidate} may be null when the item has exactly one; {@code force} only after the reviewer said so. */
	public List<String> acceptCommand(String id, String reviewer, String candidate, boolean force, String note)
			throws PbetaException {
		List<String> cmd = base("accept", id, reviewer);
		if (candidate != null && !candidate.isBlank()) {
			cmd.add("--candidate");
			cmd.add(candidate.strip());
		}
		if (force) {
			cmd.add("--force");
		}
		addNote(cmd, note);
		return cmd;
	}

	public List<String> rejectCommand(String id, String reviewer, String note) throws PbetaException {
		List<String> cmd = base("reject", id, reviewer);
		addNote(cmd, note);
		return cmd;
	}

	/** Runs the command and returns pbeta's output; a non-zero exit is thrown with pbeta's message. */
	public String run(List<String> command) throws PbetaException {
		Result r = runner.run(command);
		if (r.exitCode() != 0) {
			String msg = r.stderr().strip();
			if (msg.isEmpty()) {
				msg = r.stdout().strip();
			}
			throw new PbetaException(
				"pbeta review refused (exit " + r.exitCode() + ")" + (msg.isEmpty() ? "" : ": " + msg));
		}
		return r.stdout().strip();
	}

	private List<String> base(String action, String id, String reviewer) throws PbetaException {
		if (pbeta == null || pbeta.isBlank()) {
			throw new PbetaException("set the pbeta executable in the Permanent Beta options");
		}
		if (store == null || store.isBlank()) {
			throw new PbetaException("set the review store in the Permanent Beta options");
		}
		if (id == null || id.isBlank()) {
			throw new PbetaException("no review item selected");
		}
		if (reviewer == null || reviewer.isBlank()) {
			throw new PbetaException("a decision needs a reviewer name");
		}
		List<String> cmd = new ArrayList<>(List.of(pbeta, "review", action, id, "--reviewer", reviewer.strip(),
			"--store", store));
		return cmd;
	}

	private static void addNote(List<String> cmd, String note) {
		if (note != null && !note.isBlank()) {
			cmd.add("--note");
			cmd.add(note.strip());
		}
	}

	private static Result runProcess(List<String> command) throws PbetaException {
		Process p;
		try {
			p = new ProcessBuilder(command).start();
		}
		catch (IOException e) {
			throw new PbetaException("could not start " + command.get(0) + ": " + e.getMessage(), e);
		}
		ExecutorService pool = Executors.newFixedThreadPool(2);
		try {
			p.getOutputStream().close();
			Future<String> out = pool.submit(() -> read(p.getInputStream()));
			Future<String> err = pool.submit(() -> read(p.getErrorStream()));
			if (!p.waitFor(60, TimeUnit.SECONDS)) {
				p.destroyForcibly();
				throw new PbetaException("pbeta review did not finish within 60 s");
			}
			return new Result(p.exitValue(), out.get(), err.get());
		}
		catch (IOException | ExecutionException e) {
			throw new PbetaException("running pbeta review: " + e.getMessage(), e);
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			p.destroyForcibly();
			throw new PbetaException("interrupted", e);
		}
		finally {
			pool.shutdownNow();
		}
	}

	private static String read(InputStream s) throws IOException {
		return new String(s.readAllBytes(), StandardCharsets.UTF_8);
	}
}
