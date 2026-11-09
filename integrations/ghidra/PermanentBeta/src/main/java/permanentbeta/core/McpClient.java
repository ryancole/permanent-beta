package permanentbeta.core;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.List;

import com.google.gson.*;

/**
 * A client for pbeta-mcp's protocol: JSON-RPC 2.0 over stdio, one message per line (design §11.2). The
 * extension uses it to read; the server itself has no tool that decides an item or writes a mapping, and this
 * client calls only the read tools ({@link #READ_TOOLS}).
 */
public final class McpClient implements AutoCloseable {
	/** The tools the extension may call. {@code propose_mapping} is deliberately not among them. */
	public static final List<String> READ_TOOLS =
		List.of("list_builds", "list_review_items", "explain_review_item", "get_candidates", "get_function");

	private static final int MAX_STDERR = 4000;

	private final BufferedReader in;
	private final Writer out;
	private final Process process;
	private final StringBuilder stderr = new StringBuilder();
	private int nextId = 1;

	/** Over the given streams (tests); {@code process} may be null. */
	public McpClient(InputStream fromServer, OutputStream toServer, Process process) {
		this.in = new BufferedReader(new InputStreamReader(fromServer, StandardCharsets.UTF_8));
		this.out = new BufferedWriter(new OutputStreamWriter(toServer, StandardCharsets.UTF_8));
		this.process = process;
	}

	/** Starts pbeta-mcp with {@code command} and performs the MCP handshake. */
	public static McpClient start(List<String> command) throws PbetaException {
		Process p;
		try {
			p = new ProcessBuilder(command).start();
		}
		catch (IOException e) {
			throw new PbetaException("could not start " + command.get(0) + ": " + e.getMessage(), e);
		}
		McpClient client = new McpClient(p.getInputStream(), p.getOutputStream(), p);
		client.drainStderr(p.getErrorStream());
		try {
			client.initialize();
		}
		catch (PbetaException e) {
			client.close();
			throw e;
		}
		return client;
	}

	public void initialize() throws PbetaException {
		JsonObject params = new JsonObject();
		params.addProperty("protocolVersion", "2025-06-18");
		params.add("capabilities", new JsonObject());
		JsonObject info = new JsonObject();
		info.addProperty("name", "permanent-beta-ghidra");
		info.addProperty("version", "0.0.1");
		params.add("clientInfo", info);
		request("initialize", params);
		JsonObject note = new JsonObject();
		note.addProperty("jsonrpc", "2.0");
		note.addProperty("method", "notifications/initialized");
		send(note);
	}

	/**
	 * Calls a read tool and returns its result, parsed as JSON when it is JSON. A tool error (isError) is
	 * thrown with the server's own message.
	 */
	public synchronized JsonElement callTool(String name, JsonObject arguments) throws PbetaException {
		if (!READ_TOOLS.contains(name)) {
			throw new PbetaException("the Ghidra extension does not call " + name);
		}
		JsonObject params = new JsonObject();
		params.addProperty("name", name);
		params.add("arguments", arguments == null ? new JsonObject() : arguments);
		JsonObject result = request("tools/call", params);
		String text = "";
		JsonArray content = result.has("content") && result.get("content").isJsonArray()
				? result.getAsJsonArray("content")
				: new JsonArray();
		if (!content.isEmpty() && content.get(0).isJsonObject()) {
			JsonElement t = content.get(0).getAsJsonObject().get("text");
			text = t == null || t.isJsonNull() ? "" : t.getAsString();
		}
		JsonElement isError = result.get("isError");
		if (isError != null && isError.isJsonPrimitive() && isError.getAsBoolean()) {
			throw new PbetaException(text.isEmpty() ? name + " failed" : text);
		}
		try {
			return JsonParser.parseString(text);
		}
		catch (JsonParseException e) {
			return new JsonPrimitive(text);
		}
	}

	private synchronized JsonObject request(String method, JsonObject params) throws PbetaException {
		int id = nextId++;
		JsonObject msg = new JsonObject();
		msg.addProperty("jsonrpc", "2.0");
		msg.addProperty("id", id);
		msg.addProperty("method", method);
		msg.add("params", params);
		send(msg);
		while (true) {
			String line;
			try {
				line = in.readLine();
			}
			catch (IOException e) {
				throw new PbetaException("reading from pbeta-mcp: " + e.getMessage() + stderrTail(), e);
			}
			if (line == null) {
				throw new PbetaException("pbeta-mcp exited" + stderrTail());
			}
			if (line.isBlank()) {
				continue;
			}
			JsonObject reply;
			try {
				reply = JsonParser.parseString(line).getAsJsonObject();
			}
			catch (RuntimeException e) {
				throw new PbetaException("pbeta-mcp sent something that isn't JSON-RPC: " + line, e);
			}
			JsonElement rid = reply.get("id");
			if (rid == null || rid.isJsonNull()) {
				continue; // a notification
			}
			if (!rid.isJsonPrimitive() || rid.getAsInt() != id) {
				throw new PbetaException("pbeta-mcp answered request " + rid + ", expected " + id);
			}
			if (reply.has("error")) {
				JsonElement err = reply.get("error");
				String m = err.isJsonObject() && err.getAsJsonObject().has("message")
						? err.getAsJsonObject().get("message").getAsString()
						: err.toString();
				throw new PbetaException("pbeta-mcp: " + m);
			}
			JsonElement result = reply.get("result");
			if (result == null || !result.isJsonObject()) {
				throw new PbetaException("pbeta-mcp: reply without a result: " + line);
			}
			return result.getAsJsonObject();
		}
	}

	private void send(JsonObject msg) throws PbetaException {
		try {
			out.write(msg.toString());
			out.write('\n');
			out.flush();
		}
		catch (IOException e) {
			throw new PbetaException("writing to pbeta-mcp: " + e.getMessage() + stderrTail(), e);
		}
	}

	/** Keeps the end of the server's stderr for error messages; it also stops a full pipe blocking it. */
	private void drainStderr(InputStream err) {
		Thread t = new Thread(() -> {
			try (BufferedReader r = new BufferedReader(new InputStreamReader(err, StandardCharsets.UTF_8))) {
				String line;
				while ((line = r.readLine()) != null) {
					synchronized (stderr) {
						stderr.append(line).append('\n');
						if (stderr.length() > MAX_STDERR) {
							stderr.delete(0, stderr.length() - MAX_STDERR);
						}
					}
				}
			}
			catch (IOException e) {
				// the process went away
			}
		}, "pbeta-mcp stderr");
		t.setDaemon(true);
		t.start();
	}

	private String stderrTail() {
		if (process != null) {
			try {
				process.waitFor(java.time.Duration.ofMillis(500));
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
		}
		synchronized (stderr) {
			String s = stderr.toString().strip();
			return s.isEmpty() ? "" : ": " + s;
		}
	}

	@Override
	public void close() {
		try {
			out.close();
		}
		catch (IOException e) {
			// closing anyway
		}
		if (process != null) {
			process.destroy();
		}
	}
}
