package GhidraJupyterKotlin;

import java.awt.*;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URISyntaxException;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import docking.widgets.OptionDialog;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.script.GhidraState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.task.RunManager;
import ghidra.util.task.TaskMonitor;
import org.json.JSONObject;
import resources.ResourceManager;

import javax.swing.*;

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
	private final RunManager runManager = new RunManager();
	private final CellContext cellContext = new CellContext();
	private File connectionFile = null;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public JupyterKotlinPlugin(PluginTool tool) {
		super(tool, true, true);


		DockingAction action = new DockingAction("Kotlin QtConsole", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (connectionFile == null) {
					connectionFile = ConnectionFile.create();
					var runable = new KotlinQtConsoleThread(cellContext, connectionFile);
					runManager.runNow(runable, "Kotlin kernel");
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
				var runnable = new NotebookThread(cellContext, tool);
				runManager.runNow(runnable, "Notebook");
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

	}

	private void launchQtConsole() {
		String[] command = {"jupyter-qtconsole", "--existing", connectionFile.toString()};
		try {
			Runtime.getRuntime().exec(command);
		} catch (IOException e) {
			Msg.showError(this, null, "QT Console process failed",
					"The QT Console failed to start because of an IOException.\n" +
							"Most likely jupyter-qtconsole is not available in your PATH because it wasn't installed\n" +
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

	private void openNotebookServer() {
		URI uri = checkForRunningNotebookServer();

		if (uri !=null){
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

	@Override
	protected void programActivated(Program activatedProgram) {
		Msg.info(this, "Program activated");
		var state = new GhidraState(tool, tool.getProject(),
				currentProgram, currentLocation, currentSelection, currentHighlight);
		cellContext.set(state, TaskMonitor.DUMMY, null);
	}

	protected void programClosed(Program program) {
		Msg.info(this, "Program closed");
		var state = new GhidraState(tool, tool.getProject(),
				null, null, null, null);
		cellContext.set(state, TaskMonitor.DUMMY, null);
	}

	/**
	 * Subclass should override this method if it is interested in
	 * program location events.
	 * @param loc location could be null
	 */
	protected void locationChanged(ProgramLocation loc) {
		if (currentLocation != null) {
			//if the state has null variables but we still get a location changed likely a check in occured so reset state
			if(cellContext.getState() != null && cellContext.getState().getCurrentAddress() == null)
			{
				var state = new GhidraState(tool, tool.getProject(),
					currentProgram, currentLocation, currentSelection, currentHighlight);
				cellContext.set(state, TaskMonitor.DUMMY, null);
			}
			
			Msg.info(this, String.format("Location changed to %s", currentLocation));
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
		Msg.info(this, String.format("Selection changed to %s", currentSelection));
		cellContext.setCurrentSelection(currentSelection);
	}

	/**
	 * Subclass should override this method if it is interested in
	 * program highlight events.
	 * @param hl highlight could be null
	 */
	protected void highlightChanged(ProgramSelection hl) {
		Msg.info(this, "Highlight changed");
		cellContext.setCurrentHighlight(currentHighlight);
	}
}
