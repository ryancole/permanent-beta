package permanentbeta.core;

/** An error reported by pbeta or pbeta-mcp, with its own message, shown to the reviewer as it is. */
public final class PbetaException extends Exception {
	public PbetaException(String message) {
		super(message);
	}

	public PbetaException(String message, Throwable cause) {
		super(message, cause);
	}
}
