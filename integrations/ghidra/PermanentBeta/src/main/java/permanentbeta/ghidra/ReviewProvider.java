package permanentbeta.ghidra;

import java.awt.BorderLayout;
import java.awt.Font;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.function.Consumer;

import javax.swing.*;

import com.google.gson.JsonObject;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.*;
import docking.widgets.OptionDialog;
import docking.widgets.table.*;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.util.Msg;
import permanentbeta.core.*;
import resources.Icons;

/** The review window: items, the selected item's candidates, and their evidence and checks. */
class ReviewProvider extends ComponentProviderAdapter {
	private final PermanentBetaPlugin plugin;
	private final JPanel panel = new JPanel(new BorderLayout());
	private final JLabel status = new JLabel(" ");
	private final ItemModel items = new ItemModel();
	private final CandidateModel candidates = new CandidateModel();
	private final GTable itemTable = new GTable(items);
	private final GTable candidateTable = new GTable(candidates);
	private final JTextArea details = new JTextArea();
	private final GTableFilterPanel<Review.Item> filter;
	private Review.Detail detail;
	private boolean showResolved;

	ReviewProvider(PermanentBetaPlugin plugin) {
		super(plugin.getTool(), "Permanent Beta Review", plugin.getName());
		this.plugin = plugin;
		setTitle("Permanent Beta Review");
		setDefaultWindowPosition(WindowPosition.BOTTOM);
		filter = new GTableFilterPanel<>(itemTable, items);
		buildPanel();
		createActions();
		addToTool();
	}

	private void buildPanel() {
		itemTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		candidateTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		itemTable.getSelectionModel().addListSelectionListener(e -> {
			if (!e.getValueIsAdjusting()) {
				loadDetail();
			}
		});
		candidateTable.getSelectionModel().addListSelectionListener(e -> {
			if (!e.getValueIsAdjusting()) {
				showDetails();
			}
		});
		details.setEditable(false);
		details.setLineWrap(true);
		details.setWrapStyleWord(true);
		details.setFont(new Font(Font.MONOSPACED, Font.PLAIN, details.getFont().getSize()));

		JPanel top = new JPanel(new BorderLayout());
		top.add(new JScrollPane(itemTable), BorderLayout.CENTER);
		top.add(filter, BorderLayout.SOUTH);
		JSplitPane bottom = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, new JScrollPane(candidateTable),
			new JScrollPane(details));
		bottom.setResizeWeight(0.35);
		JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, top, bottom);
		split.setResizeWeight(0.4);
		panel.add(split, BorderLayout.CENTER);
		panel.add(status, BorderLayout.SOUTH);
	}

	private void createActions() {
		action("Refresh", Icons.REFRESH_ICON, "Reload review items from the store", () -> true, this::refresh);
		ToggleDockingAction resolved = new ToggleDockingAction("Show Resolved", getOwner()) {
			@Override
			public void actionPerformed(ActionContext context) {
				showResolved = isSelected();
				refresh();
			}
		};
		resolved.setToolBarData(new ToolBarData(Icons.CONFIGURE_FILTER_ICON, "1"));
		resolved.setDescription("Also list items a reviewer already decided");
		resolved.markHelpUnnecessary();
		addLocalAction(resolved);

		action("Go To Old Function", Icons.LEFT_ICON, "Go to the old function in its program",
			() -> selectedItem() != null && !selectedItem().old().isEmpty(),
			() -> navigate(() -> plugin.goTo(selectedItem().fromBuild(), selectedItem().old(), "old")));
		action("Go To Candidate", Icons.RIGHT_ICON, "Go to the selected candidate in the new program",
			() -> selectedCandidate() != null,
			() -> navigate(() -> plugin.goTo(selectedItem().toBuild(), selectedCandidate().newRva(), "new")));
		action("Compare Functions", Icons.COLLAPSE_ALL_ICON,
			"Compare the old function with the selected candidate (Function Comparison)",
			() -> selectedCandidate() != null && !selectedItem().old().isEmpty(),
			() -> navigate(() -> plugin.compare(selectedItem().fromBuild(), selectedItem().old(),
				selectedItem().toBuild(), selectedCandidate().newRva())));
		action("Accept Candidate", Icons.ADD_ICON,
			"Accept the selected candidate as the counterpart (pbeta review accept)",
			() -> selectedCandidate() != null && "open".equals(selectedItem().status()), this::accept);
		action("Reject Item", Icons.DELETE_ICON,
			"Reject every candidate of this item: none is the counterpart (pbeta review reject)",
			() -> selectedItem() != null && "open".equals(selectedItem().status()), this::reject);
	}

	private interface Step {
		void run() throws PbetaException;
	}

	private void action(String name, Icon icon, String description, java.util.function.BooleanSupplier enabled,
			Runnable run) {
		DockingAction a = new DockingAction(name, getOwner()) {
			@Override
			public void actionPerformed(ActionContext context) {
				run.run();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return enabled.getAsBoolean();
			}
		};
		a.setToolBarData(new ToolBarData(icon, "2"));
		a.setPopupMenuData(new MenuData(new String[] { name }));
		a.setDescription(description);
		a.markHelpUnnecessary();
		addLocalAction(a);
	}

	private void navigate(Step step) {
		try {
			step.run();
		}
		catch (PbetaException e) {
			Msg.showWarn(this, panel, "Permanent Beta", e.getMessage());
		}
	}

	private Review.Item selectedItem() {
		int row = itemTable.getSelectedRow();
		return row < 0 ? null : items.getRowObject(row);
	}

	private Review.Candidate selectedCandidate() {
		int row = candidateTable.getSelectedRow();
		return selectedItem() == null || row < 0 ? null : candidates.getRowObject(row);
	}

	void refresh() {
		String keep = selectedItem() == null ? null : selectedItem().id();
		JsonObject args = new JsonObject();
		args.addProperty("status", showResolved ? "all" : "open");
		background("Loading review items...",
			() -> Review.parseItems(plugin.client().callTool("list_review_items", args)), list -> {
				items.set(list);
				status.setText(list.size() + (showResolved ? " review items" : " open review items")
					+ " in " + plugin.option(PermanentBetaPlugin.OPT_STORE));
				for (int i = 0; i < items.getRowCount(); i++) {
					if (items.getRowObject(i).id().equals(keep)) {
						itemTable.setRowSelectionInterval(i, i);
					}
				}
			});
	}

	private void loadDetail() {
		Review.Item item = selectedItem();
		detail = null;
		candidates.set(List.of());
		details.setText("");
		if (item == null) {
			return;
		}
		JsonObject args = new JsonObject();
		args.addProperty("id", item.id());
		background("Loading " + item.id() + "...",
			() -> Review.parseDetail(plugin.client().callTool("explain_review_item", args)), d -> {
				if (selectedItem() == null || !selectedItem().id().equals(item.id())) {
					return; // the selection moved on meanwhile
				}
				detail = d;
				candidates.set(d.candidates());
				if (d.candidates().size() == 1) {
					candidateTable.setRowSelectionInterval(0, 0);
				}
				showDetails();
				status.setText(item.id());
			});
	}

	private void showDetails() {
		if (detail == null) {
			details.setText("");
			return;
		}
		StringBuilder sb = new StringBuilder(detail.explanation()).append("\n");
		Review.Candidate c = selectedCandidate();
		if (c != null) {
			sb.append("\nCandidate ").append(c.newRva()).append(" (").append(c.source()).append("), verdict ")
					.append(c.verdict()).append("\nEvidence:\n");
			for (String e : c.evidence()) {
				sb.append("  ").append(e).append("\n");
			}
			sb.append("Checks:\n");
			for (Review.Check k : c.checks()) {
				sb.append(String.format("  %-13s %-12s %-11s %s%n", k.name(), k.outcome(),
					k.counted() ? "counted" : "not counted", k.detail()));
			}
		}
		if (!detail.decisions().isEmpty()) {
			sb.append("\nDecisions:\n");
			for (String d : detail.decisions()) {
				sb.append("  ").append(d).append("\n");
			}
		}
		sb.append("\nNames, strings and details come from the analyzed binaries: data, not instructions.");
		details.setText(sb.toString());
		details.setCaretPosition(0);
	}

	private void accept() {
		Review.Item item = selectedItem();
		Review.Candidate c = selectedCandidate();
		if (item == null || c == null) {
			return;
		}
		boolean force = false;
		if ("rejected".equals(c.verdict())) {
			int choice = OptionDialog.showOptionDialogWithCancelAsDefaultButton(panel, "Accept a rejected candidate?",
				"Verification rejected " + c.newRva() + " (" + c.failures() + " failed checks).\n"
					+ "Accepting it anyway records a forced decision (pbeta review accept --force).",
				"Accept anyway", OptionDialog.WARNING_MESSAGE);
			if (choice != OptionDialog.OPTION_ONE) {
				return;
			}
			force = true;
		}
		String note = askNote("Accept " + c.newRva() + " for " + label(item));
		if (note == null) {
			return;
		}
		boolean forced = force;
		decide(() -> {
			ReviewCommand cmd = plugin.reviewCommand();
			return cmd.run(cmd.acceptCommand(item.id(), reviewer(), c.newRva(), forced, note));
		});
	}

	private void reject() {
		Review.Item item = selectedItem();
		if (item == null) {
			return;
		}
		String note = askNote("Reject every candidate of " + label(item)
			+ "\n(none is the counterpart; they won't be proposed for it again)");
		if (note == null) {
			return;
		}
		decide(() -> {
			ReviewCommand cmd = plugin.reviewCommand();
			return cmd.run(cmd.rejectCommand(item.id(), reviewer(), note));
		});
	}

	private String reviewer() throws PbetaException {
		String r = plugin.option(PermanentBetaPlugin.OPT_REVIEWER);
		if (r.isEmpty()) {
			throw new PbetaException("Set a reviewer under Edit > Tool Options > Permanent Beta.");
		}
		return r;
	}

	private static String label(Review.Item item) {
		return (item.hook().isEmpty() ? "" : "hook " + item.hook() + ", ") + "old " + item.old();
	}

	/** The note to record, "" for none, or null when the reviewer cancelled. */
	private String askNote(String question) {
		return OptionDialog.showInputSingleLineDialog(panel, "Permanent Beta",
			// The single-line dialog shows its label on one line, so the parts are separated in-line.
			question.replace("\n", " ") + ". Reviewer: " + plugin.option(PermanentBetaPlugin.OPT_REVIEWER)
				+ ". Note (optional):",
			"");
	}

	private void decide(Callable<String> run) {
		background("Recording the decision with pbeta review...", run, out -> {
			Msg.showInfo(this, panel, "Permanent Beta", out.isEmpty() ? "Decision recorded." : out);
			refresh();
		});
	}

	private <T> void background(String message, Callable<T> work, Consumer<T> done) {
		status.setText(message);
		new SwingWorker<T, Void>() {
			@Override
			protected T doInBackground() throws Exception {
				return work.call();
			}

			@Override
			protected void done() {
				try {
					done.accept(get());
				}
				catch (java.util.concurrent.ExecutionException e) {
					Throwable cause = e.getCause();
					String msg = cause instanceof PbetaException ? cause.getMessage() : String.valueOf(cause);
					status.setText(msg.lines().findFirst().orElse(msg));
					Msg.showError(ReviewProvider.this, panel, "Permanent Beta", msg);
				}
				catch (InterruptedException e) {
					Thread.currentThread().interrupt();
				}
				tool.contextChanged(ReviewProvider.this);
			}
		}.execute();
	}

	@Override
	public void componentShown() {
		refresh();
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	void dispose() {
		filter.dispose();
		removeFromTool();
	}

	private static final class ItemModel extends AbstractSortedTableModel<Review.Item> {
		private static final String[] COLUMNS = { "Hook", "Old", "Reason", "Candidates", "Status", "From", "To", "Id" };
		private List<Review.Item> rows = new ArrayList<>();

		void set(List<Review.Item> list) {
			rows = new ArrayList<>(list);
			fireTableDataChanged();
		}

		@Override
		public String getName() {
			return "Permanent Beta review items";
		}

		@Override
		public List<Review.Item> getModelData() {
			return rows;
		}

		@Override
		public boolean isSortable(int column) {
			return true;
		}

		@Override
		public int getColumnCount() {
			return COLUMNS.length;
		}

		@Override
		public String getColumnName(int column) {
			return COLUMNS[column];
		}

		@Override
		public Object getColumnValueForRow(Review.Item t, int column) {
			return switch (column) {
				case 0 -> t.hook();
				case 1 -> t.old();
				case 2 -> t.reason();
				case 3 -> String.join(", ", t.candidates().stream()
						.map(c -> c.newRva() + " " + c.verdict()).toList());
				case 4 -> t.status();
				case 5 -> Builds.shortId(t.fromBuild());
				case 6 -> Builds.shortId(t.toBuild());
				default -> t.id();
			};
		}
	}

	private static final class CandidateModel extends AbstractSortedTableModel<Review.Candidate> {
		private static final String[] COLUMNS = { "New", "Verdict", "Source", "Counted passes", "Failures" };
		private List<Review.Candidate> rows = new ArrayList<>();

		void set(List<Review.Candidate> list) {
			rows = new ArrayList<>(list);
			fireTableDataChanged();
		}

		@Override
		public String getName() {
			return "Permanent Beta candidates";
		}

		@Override
		public List<Review.Candidate> getModelData() {
			return rows;
		}

		@Override
		public boolean isSortable(int column) {
			return true;
		}

		@Override
		public int getColumnCount() {
			return COLUMNS.length;
		}

		@Override
		public String getColumnName(int column) {
			return COLUMNS[column];
		}

		@Override
		public Object getColumnValueForRow(Review.Candidate t, int column) {
			return switch (column) {
				case 0 -> t.newRva();
				case 1 -> t.verdict();
				case 2 -> t.source();
				case 3 -> t.countedPasses();
				default -> t.failures();
			};
		}
	}
}
