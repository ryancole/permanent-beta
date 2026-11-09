package permanentbeta.core;

import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * Review items as pbeta-mcp's {@code list_review_items} and {@code explain_review_item} return them. Read-only
 * views: nothing here decides anything. Strings that come from the analyzed binary (names, details) are data.
 */
public final class Review {
	private Review() {
	}

	/** One row of {@code list_review_items}. */
	public record Item(String id, String status, String reason, String hook, String old, String fromBuild,
			String toBuild, List<CandidateSummary> candidates) {
	}

	public record CandidateSummary(String newRva, String verdict) {
	}

	/** {@code explain_review_item}: the explanation, every candidate with evidence and checks, the decisions. */
	public record Detail(String explanation, List<Candidate> candidates, List<String> decisions) {
	}

	public record Candidate(String newRva, String source, String verdict, List<String> evidence,
			List<Check> checks) {
		/** Checks that passed and count as independent evidence. */
		public long countedPasses() {
			return checks.stream().filter(c -> c.counted() && "pass".equals(c.outcome())).count();
		}

		public long failures() {
			return checks.stream().filter(c -> "fail".equals(c.outcome())).count();
		}
	}

	public record Check(String name, String outcome, boolean counted, String detail) {
	}

	public static List<Item> parseItems(JsonElement json) throws PbetaException {
		if (json == null || !json.isJsonArray()) {
			throw new PbetaException("list_review_items: expected a list, got " + json);
		}
		List<Item> items = new ArrayList<>();
		for (JsonElement e : json.getAsJsonArray()) {
			JsonObject o = object(e, "review item");
			List<CandidateSummary> cands = new ArrayList<>();
			for (JsonElement c : array(o, "candidates")) {
				JsonObject co = object(c, "candidate");
				cands.add(new CandidateSummary(str(co, "new"), str(co, "verdict")));
			}
			items.add(new Item(required(o, "id"), str(o, "status"), str(o, "reason"), str(o, "hook"),
				str(o, "old"), required(o, "from_build"), required(o, "to_build"), List.copyOf(cands)));
		}
		return List.copyOf(items);
	}

	public static Detail parseDetail(JsonElement json) throws PbetaException {
		if (json == null || !json.isJsonObject() || !json.getAsJsonObject().has("item")) {
			throw new PbetaException("explain_review_item: unexpected result " + json);
		}
		JsonObject o = json.getAsJsonObject();
		JsonObject item = object(o.get("item"), "item");
		List<Candidate> cands = new ArrayList<>();
		for (JsonElement e : array(item, "candidates")) {
			JsonObject c = object(e, "candidate");
			JsonObject cand = object(c.get("candidate"), "candidate");
			List<String> evidence = new ArrayList<>();
			for (JsonElement ev : array(cand, "evidence")) {
				JsonObject eo = object(ev, "evidence");
				evidence.add(str(eo, "kind") + ": " + str(eo, "detail"));
			}
			List<Check> checks = new ArrayList<>();
			for (JsonElement ch : array(c, "checks")) {
				JsonObject k = object(ch, "check");
				JsonElement counted = k.get("counted");
				checks.add(new Check(str(k, "check"), str(k, "outcome"),
					counted != null && counted.isJsonPrimitive() && counted.getAsBoolean(), str(k, "detail")));
			}
			cands.add(new Candidate(required(cand, "new"), source(cand), str(c, "verdict"),
				List.copyOf(evidence), List.copyOf(checks)));
		}
		List<String> decisions = new ArrayList<>();
		for (JsonElement d : array(o, "decisions")) {
			decisions.add(decision(d));
		}
		return new Detail(str(o, "explanation"), List.copyOf(cands), List.copyOf(decisions));
	}

	/** A decision as one line: who, what, and the note. The full record stays in the store. */
	private static String decision(JsonElement d) {
		if (!d.isJsonObject()) {
			return d.toString();
		}
		JsonObject o = d.getAsJsonObject();
		String note = str(o, "note");
		return str(o, "reviewer") + ": " + str(o, "action") + (note.isEmpty() ? "" : " (" + note + ")");
	}

	private static String source(JsonObject candidate) {
		JsonElement s = candidate.get("source");
		if (s == null || !s.isJsonObject()) {
			return "";
		}
		JsonObject so = s.getAsJsonObject();
		String kind = str(so, "kind");
		for (String key : new String[] { "matcher", "model", "reviewer" }) {
			if (so.has(key)) {
				return kind + " " + str(so, key);
			}
		}
		return kind;
	}

	private static JsonObject object(JsonElement e, String what) throws PbetaException {
		if (e == null || !e.isJsonObject()) {
			throw new PbetaException(what + ": expected an object, got " + e);
		}
		return e.getAsJsonObject();
	}

	private static JsonArray array(JsonObject o, String key) {
		JsonElement e = o.get(key);
		return e != null && e.isJsonArray() ? e.getAsJsonArray() : new JsonArray();
	}

	private static String str(JsonObject o, String key) {
		JsonElement e = o.get(key);
		return e == null || e.isJsonNull() ? "" : e.isJsonPrimitive() ? e.getAsString() : e.toString();
	}

	private static String required(JsonObject o, String key) throws PbetaException {
		String s = str(o, key);
		if (s.isEmpty()) {
			throw new PbetaException("review item without " + key + ": " + o);
		}
		return s;
	}
}
