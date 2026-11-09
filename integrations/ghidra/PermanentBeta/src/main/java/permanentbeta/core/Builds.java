package permanentbeta.core;

/** Ties Ghidra programs to pbeta builds. A build id is the SHA-256 of the executable (design §9.1). */
public final class Builds {
	private Builds() {
	}

	/**
	 * True only when the program's recorded SHA-256 is this build id. A program without a recorded hash matches
	 * nothing: the extension refuses rather than guesses.
	 */
	public static boolean isBuild(String programSha256, String buildId) {
		if (programSha256 == null || buildId == null) {
			return false;
		}
		String a = programSha256.strip(), b = buildId.strip();
		return a.length() == 64 && a.equalsIgnoreCase(b);
	}

	/** An RVA as pbeta prints it ({@code "0x1040"}), or plain decimal. */
	public static long parseRva(String rva) throws PbetaException {
		if (rva == null || rva.isBlank()) {
			throw new PbetaException("no RVA");
		}
		String s = rva.strip();
		try {
			long v = s.startsWith("0x") || s.startsWith("0X") ? Long.parseUnsignedLong(s.substring(2), 16)
					: Long.parseLong(s);
			if (v < 0 || v > 0xFFFF_FFFFL) {
				throw new PbetaException("RVA out of range: " + rva);
			}
			return v;
		}
		catch (NumberFormatException e) {
			throw new PbetaException("not an RVA: " + rva, e);
		}
	}

	public static String shortId(String buildId) {
		return buildId == null ? "" : buildId.length() > 12 ? buildId.substring(0, 12) : buildId;
	}
}
