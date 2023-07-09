package GhidraJupyterKotlin;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import docking.widgets.OptionDialog;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.script.GhidraState;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.task.RunManager;
import ghidra.util.task.TaskMonitor;
import org.apache.commons.lang3.ArrayUtils;
import org.json.JSONObject;
import resources.ResourceManager;

import javax.swing.*;
import java.awt.*;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URISyntaxException;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = "GhidraJupyterKotlin",
	category = PluginCategoryNames.INTERPRETERS,
	shortDescription = "Kotlin Jupyter kernel for Ghidra.",
	description = "Kotlin Jupyter kernel for Ghidra."
)
//@formatter:on
public class JupyterKotlinPlugin extends ProgramPlugin {
	private static final String OPTION_LAST_URI = "LAST_URI";
	private static final String DEFAULT_URI = "http://localhost:8888/tree";
	private static final String OPTION_CONSOLE_CMD = "CONSOLE_CMD";
	private static final String DEFAULT_CONSOLE_CMD = "jupyter-qtconsole --existing";
	private static final String PLUGIN_NAME = "JupyterKotlinPlugin";
	private final RunManager runManager = new RunManager();
	private final CellContext cellContext = new CellContext();
	private Options programOptions;
	private Options toolOptions;

	public File getConnectionFile() {
		return (currentKernel != null) ? currentKernel.getConnectionFile() : null;
	}

	private KernelThread currentKernel = null;
	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public JupyterKotlinPlugin(PluginTool tool) {
		super(tool);
		toolOptions = tool.getOptions(PLUGIN_NAME);
		toolOptions.registerOption(OPTION_CONSOLE_CMD, OptionType.STRING_TYPE, DEFAULT_CONSOLE_CMD, null,
				"Default Console command to execute (connection file will be appended)");
		toolOptions.registerOption(OPTION_LAST_URI, OptionType.STRING_TYPE, DEFAULT_URI, null,
				"Default URI to open when using the GUI shortcut. " +
						"This can be set to the full path to a specific notebook " +
						"that should open directly after the kernel starts waiting");
		registerActions();
	}

	public void clearKernel() {
		currentKernel = null;
	}


	private void registerActions(){
		DockingAction action = new DockingAction("Kotlin QtConsole", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (getConnectionFile() == null) {
					currentKernel = new KotlinQtConsoleThread(cellContext, ConnectionFile.create());
					runManager.runNow(currentKernel, "Kotlin kernel");
				}
				launchQtConsole();
			}
		};
		ImageIcon qtconsoleIcon = ResourceManager.loadImage("images/qtconsole.png");
		action.setToolBarData(new ToolBarData(qtconsoleIcon, null));
		action.setMenuBarData(
				new MenuData(new String[] { "Jupyter", "Open QTConsole" }, qtconsoleIcon, null));
		action.setEnabled(true);
		action.markHelpUnnecessary();
		tool.addAction(action);

		DockingAction notebookAction = new DockingAction("Kotlin Notebook", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				currentKernel = new NotebookThread(cellContext, tool);
				runManager.runNow(currentKernel, "Notebook");
			}
		};
		ImageIcon kernelIcon = ResourceManager.loadImage("images/notebook.png");
		notebookAction.setToolBarData(new ToolBarData(kernelIcon, null));
		notebookAction.setMenuBarData(
				new MenuData(new String[] { "Jupyter", "Start Kotlin Kernel for Notebook/Lab" }, kernelIcon, null));
		notebookAction.setEnabled(true);
		notebookAction.markHelpUnnecessary();
		tool.addAction(notebookAction);


		DockingAction serverAction = new DockingAction("Jupyter Server", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				openNotebookServer();
			}
		};

		serverAction.setMenuBarData(
				new MenuData(new String[] { "Jupyter", "Open Jupyter Notebook Server" }, null, null));
		serverAction.setDescription("Tries to open existing server or offers to start a new one");
		tool.addAction(serverAction);

		DockingAction defaultNotebookAction = new DockingAction("Default Notebook", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				openDefaultNotebook();
			}
		};

		defaultNotebookAction.setMenuBarData(
				new MenuData(new String[] { "Jupyter", "Open Default Notebook" }, null, null));
		defaultNotebookAction.setDescription("Open Default Notebook");
		tool.addAction(defaultNotebookAction);

		DockingAction interruptAction = new InterruptKernelAction(this);
		interruptAction.setMenuBarData(
				new MenuData(new String[] { "Jupyter", "Interrupt Execution" }, null, null));
		interruptAction.setDescription("Interrupts the currently running kernel if it is executing something");
		tool.addAction(interruptAction);

		// TODO: Make kernel shutdown reliable again
//		DockingAction shutdownAction = new ShutDownKernelAction(this);
//		shutdownAction.setMenuBarData(
//			new MenuData(new String[] { "Jupyter", "Shutdown Kernel" }, null, null));
//		shutdownAction.setDescription("Terminates the currently running kernel if it isn't busy");
//		tool.addAction(shutdownAction);

	}

	private void launchQtConsole() {
		String[] console = toolOptions.getString(OPTION_CONSOLE_CMD,
				DEFAULT_CONSOLE_CMD).split(" ");
		String[] command = ArrayUtils.add(console, currentKernel.getConnectionFile().toString());
		try {
			Runtime.getRuntime().exec(command);
		} catch (IOException e) {
			Msg.showError(this, null, "QT Console process failed",
					"The console command failed to start because of an IOException.\n" +
							"Most likely jupyter-qtconsole is not available in your PATH because it wasn't installed\n" +
							"or your custom command has some issues\n" +
							"You can manually run the following command to debug this: \n" +
							String.join(" ", command) +
							"\nThe kernel*.json path is optional. Leaving it out will reconnect to your most recent running kernel, which is most likely the correct one.\n" +
							"You can also run 'jupyter-console --existing' for a terminal based console which is typically already included with a Jupyter install",
					e);
		}
	}

	private URI checkForRunningNotebookServer(){
		Runtime rt = Runtime.getRuntime();
		String[] commands = {"jupyter", "notebook", "list", "--json"};

		Process proc = null;
		try {
			proc = rt.exec(commands);

			BufferedReader stdInput = new BufferedReader(new
					InputStreamReader(proc.getInputStream()));

			String s = stdInput.readLine();

			if (s != null) {
				JSONObject obj = new JSONObject(s);
				return new URI((String) obj.get("url"));
				}
		} catch (IOException | URISyntaxException e) {
			e.printStackTrace();
		}
		return null;
	}

	private void openURI(URI uri){
		if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
			try {
				Desktop.getDesktop().browse(uri);
			} catch (IOException e) {
				e.printStackTrace();
			}
		} else {
			Msg.error(this,
					"Notebook couldn't be opened because environment doesn't support opening URLs");
		}
	}
	private void openNotebookServer() {
		URI uri = checkForRunningNotebookServer();

		if (uri !=null){
			openURI(uri);
		} else {
			if (OptionDialog.showYesNoDialog(null,
					"Start new Jupyter server?",
					"No running Jupyter Notebook server could be detected, would you like to start a new one?\n" +
							"This server will use the default options by simply invoking 'jupyter-notebook'" +
							"and persist after closing Ghidra")
					== OptionDialog.OPTION_ONE){
				Runtime rt = Runtime.getRuntime();
				String[] commands = {"jupyter-notebook" };
				try {
					rt.exec(commands);
				} catch (IOException e) {
					Msg.showError(this, null,
							"Failed to start Jupyter Server",
							"The Jupyter Server could not be started", e);
				}
			}

		}
	}

	private void openDefaultNotebook(){
		var programValue = programOptions.getString(OPTION_LAST_URI, "");
		var toolValue = toolOptions.getString(OPTION_LAST_URI, "");
		var value = "";
		if (programValue.equals("") && toolValue.equals("")){
			var msg = String.format("The URI option was not set, please go to\n" +
							"'Edit'-> 'Options for %s' -> %s\n" +
							"and set the option to the full URL your default browser should navigate to", currentProgram.getName(), PLUGIN_NAME);
			Msg.showError(this, null,"No URI set in options", msg);
			return;
		}
		else if (programValue.equals("")){
			Msg.info(this, "No program specific notebook configured, but default option is available");
			value = toolValue;
		}
		else {
			value = programValue;
		}
		try {
			var uri = new URI(value);
			if (uri.getScheme().equals("http")) {
				currentKernel = new NotebookThread(cellContext, tool);
				runManager.runNow(currentKernel, "Notebook");
				openURI(uri);
			}
			else {
				Msg.showError(this, null, "Invalid URI", "Scheme of the URI option isn't http, this seems wrong");
			}
		} catch (URISyntaxException e) {
			Msg.showError(this, null, "Last URI Option is invalid",
					"Last URI in options was not a valid URI and parsing it threw an exception", e);
		}


	}
	@Override
	protected void programActivated(Program activatedProgram) {
		Msg.info(this, "Program activated");
		var state = new GhidraState(tool, tool.getProject(),
				currentProgram, currentLocation, currentSelection, currentHighlight);
		cellContext.set(state, TaskMonitor.DUMMY, null);

		programOptions = activatedProgram.getOptions(PLUGIN_NAME);
		programOptions.registerOption(OPTION_LAST_URI, OptionType.STRING_TYPE, "", null,
				"Saved URI");
	}

	protected void programClosed(Program program) {
		Msg.info(this, "Program closed");
		if (cellContext.getCurrentProgram() == program) {
			var state = new GhidraState(tool, tool.getProject(),
					null, null, null, null);
			cellContext.set(state, TaskMonitor.DUMMY, null);
		}
	}

	/**
	 * Subclass should override this method if it is interested in
	 * program location events.
	 * @param loc location could be null
	 */
	protected void locationChanged(ProgramLocation loc) {
		if (currentLocation != null) {
			cellContext.setCurrentLocation(currentLocation.getAddress());
			cellContext.currentContextLocation = loc;
		}
	}

	/**
	 * Subclass should override this method if it is interested in
	 * program selection events.
	 * @param sel selection could be null
	 */
	protected void selectionChanged(ProgramSelection sel) {
		cellContext.setCurrentSelection(currentSelection);
	}

	/**
	 * Subclass should override this method if it is interested in
	 * program highlight events.
	 * @param hl highlight could be null
	 */
	protected void highlightChanged(ProgramSelection hl) {
		try {
			cellContext.setCurrentHighlight(currentHighlight);
		} catch (NullPointerException e) {
			Msg.error(this, "Null Pointer exception during set highlight, probably harmless", e);
		}
	}
}
