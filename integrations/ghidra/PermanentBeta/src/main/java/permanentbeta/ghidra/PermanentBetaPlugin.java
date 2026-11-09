package permanentbeta.ghidra;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.MiscellaneousPluginPackage;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.*;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.SystemUtilities;
import permanentbeta.core.*;

/**
 * Permanent Beta's review window (design §11.3). It reads review items through pbeta-mcp and records decisions
 * with {@code pbeta review}; it never decides an item, writes a mapping or touches the store itself.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = MiscellaneousPluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Permanent Beta review queue",
	description = "Lists Permanent Beta review items with their candidates, evidence and verification checks, "
		+ "navigates to and compares the old and new function, and records accept or reject decisions through "
		+ "the pbeta CLI.",
	servicesRequired = { GoToService.class, ProgramManager.class }
)
//@formatter:on
public class PermanentBetaPlugin extends ProgramPlugin implements OptionsChangeListener {
	static final String OPTIONS = "Permanent Beta";
	static final String OPT_PBETA = "pbeta executable";
	static final String OPT_MCP = "pbeta-mcp executable";
	static final String OPT_STORE = "Review store";
	static final String OPT_REVIEWER = "Reviewer";

	private final ReviewProvider provider;
	private McpClient client;

	public PermanentBetaPlugin(PluginTool tool) {
		super(tool);
		provider = new ReviewProvider(this);
	}

	@Override
	protected void init() {
		super.init();
		ToolOptions opts = tool.getOptions(OPTIONS);
		opts.registerOption(OPT_PBETA, "pbeta", null, "Path to pbeta.exe (or pbeta on PATH)");
		opts.registerOption(OPT_MCP, "pbeta-mcp", null, "Path to pbeta-mcp.exe (or pbeta-mcp on PATH)");
		opts.registerOption(OPT_STORE, "", null, "The review store pbeta repair wrote (--store), e.g. .pbeta\\store.json");
		opts.registerOption(OPT_REVIEWER, SystemUtilities.getUserName(), null,
			"Recorded with every decision (pbeta review --reviewer)");
		opts.addOptionsChangeListener(this);
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue, Object newValue) {
		closeClient();
		provider.refresh();
	}

	String option(String name) {
		return tool.getOptions(OPTIONS).getString(name, "").strip();
	}

	/** The pbeta-mcp connection, started on first use with only the store (it needs no analyses to read reviews). */
	synchronized McpClient client() throws PbetaException {
		if (client == null) {
			String store = option(OPT_STORE);
			if (store.isEmpty()) {
				throw new PbetaException(
					"Set the review store under Edit > Tool Options > Permanent Beta (the --store pbeta repair wrote).");
			}
			client = McpClient.start(List.of(option(OPT_MCP), "--store", store));
		}
		return client;
	}

	synchronized void closeClient() {
		if (client != null) {
			client.close();
			client = null;
		}
	}

	ReviewCommand reviewCommand() {
		return new ReviewCommand(option(OPT_PBETA), option(OPT_STORE));
	}

	/** An open program whose executable is this build, or null. */
	Program programFor(String buildId) {
		ProgramManager pm = tool.getService(ProgramManager.class);
		if (pm == null) {
			return null;
		}
		for (Program p : pm.getAllOpenPrograms()) {
			if (Builds.isBuild(p.getExecutableSHA256(), buildId)) {
				return p;
			}
		}
		return null;
	}

	/** Builds of the open programs, for messages. */
	List<String> openBuilds() {
		List<String> out = new ArrayList<>();
		ProgramManager pm = tool.getService(ProgramManager.class);
		if (pm != null) {
			for (Program p : pm.getAllOpenPrograms()) {
				out.add(p.getName() + " " + Builds.shortId(p.getExecutableSHA256()));
			}
		}
		return out;
	}

	Address address(Program p, String rva) throws PbetaException {
		return p.getImageBase().add(Builds.parseRva(rva));
	}

	Program requireProgram(String buildId, String which) throws PbetaException {
		Program p = programFor(buildId);
		if (p == null) {
			throw new PbetaException("No open program is the " + which + " build " + Builds.shortId(buildId)
				+ " (a program is matched by its executable's SHA-256). Open: " + openBuilds());
		}
		return p;
	}

	void goTo(String buildId, String rva, String which) throws PbetaException {
		Program p = requireProgram(buildId, which);
		Address a = address(p, rva);
		tool.getService(ProgramManager.class).setCurrentProgram(p);
		tool.getService(GoToService.class).goTo(new ProgramLocation(p, a), p);
	}

	void compare(String oldBuild, String oldRva, String newBuild, String newRva) throws PbetaException {
		FunctionComparisonService fc = tool.getService(FunctionComparisonService.class);
		if (fc == null) {
			throw new PbetaException("Function Comparison is not available in this tool");
		}
		Function oldF = function(requireProgram(oldBuild, "old"), oldRva);
		Function newF = function(requireProgram(newBuild, "new"), newRva);
		fc.createComparison(oldF, newF);
	}

	private Function function(Program p, String rva) throws PbetaException {
		Address a = address(p, rva);
		Function f = p.getFunctionManager().getFunctionAt(a);
		if (f == null) {
			throw new PbetaException("Ghidra has no function at " + a + " in " + p.getName()
				+ " (RVA " + rva + "); create one there, or use Go To");
		}
		return f;
	}

	@Override
	protected void dispose() {
		tool.getOptions(OPTIONS).removeOptionsChangeListener(this);
		closeClient();
		provider.dispose();
		super.dispose();
	}
}
