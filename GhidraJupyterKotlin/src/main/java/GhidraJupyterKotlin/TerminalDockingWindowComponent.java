package GhidraJupyterKotlin;

import com.jediterm.core.Color;
import com.jediterm.core.util.TermSize;
import com.jediterm.terminal.ProcessTtyConnector;
import com.jediterm.terminal.TerminalColor;
import com.jediterm.terminal.TtyConnector;
import com.jediterm.terminal.emulator.ColorPalette;
import com.jediterm.terminal.ui.JediTermWidget;
import com.jediterm.terminal.ui.settings.DefaultSettingsProvider;
import com.pty4j.PtyProcess;
import com.pty4j.PtyProcessBuilder;
import com.pty4j.WinSize;
import docking.ComponentProvider;
import docking.Tool;

import generic.theme.Gui;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitorComponent;
import kotlin.Unit;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.kotlinx.jupyter.api.libraries.JupyterIntegration;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static GhidraJupyterKotlin.JupyterKotlinPlugin.OPTION_CONSOLE_PATH;

public class TerminalDockingWindowComponent extends ComponentProvider {
    private final JPanel panel;
    private final JediTermWidget widget;
    private final JupyterKotlinPlugin plugin;
    private final ThemeAwareSettingsProvider settings;
    TaskMonitorComponent taskMonitorComponent;

    public TerminalDockingWindowComponent(Tool tool, JupyterKotlinPlugin plugin) {
        super(tool, "Jupyter Console Terminal Window", plugin.getName());
        this.plugin = plugin;
        settings = new ThemeAwareSettingsProvider();
        widget = constructWidget();
        panel = new JPanel();
        // Construct the overall component which consists of the terminal widget and TaskMonitorComponent
        taskMonitorComponent = new TaskMonitorComponent();
        panel.setLayout(new BorderLayout());
        panel.add(widget, BorderLayout.CENTER);
        panel.add(taskMonitorComponent, BorderLayout.SOUTH);
        taskMonitorComponent.setVisible(false);
        taskMonitorComponent.setIndeterminate(true);
    }

//    public void connectToJupyter()  {
//        this.setVisible(true);
//        if (!widget.isSessionRunning()) {
//            Msg.info(this, "Starting Jupyter terminal...");
//            TtyConnector ttyConnector = createTtyConnector();
//            widget.setTtyConnector(ttyConnector);
//            widget.start();
//        }
//    }

    private JediTermWidget constructWidget() {
        var widget = new JediTermWidget(80, 24, settings);
        widget.getTerminalPanel().addKeyListener(new CustomKeyAdapter());
        return widget;
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }

    private @NotNull TtyConnector createTtyConnector(File connectionFile) {
        try {
            String[] command;
            var consoleExecFile = getJupyterConsolePath();
            String consolePathAsString;
            if (consoleExecFile == null) {
                consolePathAsString = "jupyter-console"; // Assume it's in PATH
            } else {
                consolePathAsString = consoleExecFile.getAbsolutePath();
            }
            command = new String[]{
                    consolePathAsString,
                    "--existing=" + connectionFile.getAbsolutePath(),
                    "--ZMQTerminalInteractiveShell.kernel_is_complete_timeout=10.0" // See https://github.com/Kotlin/kotlin-jupyter/issues/170
            };
            Map<String, String> envs = new HashMap<>(System.getenv());
            envs.put("TERM", "xterm-256color");

            PtyProcess process = new PtyProcessBuilder().setCommand(command).setEnvironment(envs).start();
            return new PtyProcessTtyConnector(process, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /// Triggers when the component is activated in Ghidra (i.e. focused)
    /// Here we need can check if there:
    /// 1. Exists a process running the terminal session already
    /// 2. If not, check if there is an existing kernel already, and connect to it
    /// 3. If not, start a new kernel and terminal session
    ///
    @Override
    public void componentActivated() {
        if (widget.isSessionRunning()) {
            return;
        }
        // No process is running yet
        TaskLauncher.launchModal("Initializing Jupyter Kernel...", () -> {
            File connectionFile = plugin.getOrStartNewConsoleKernel();
            startTerminalSession(connectionFile);
        });

    }

    public void resetTerminalSession() {
        if (widget.isSessionRunning()) {
            TaskLauncher.launchModal("Initializing Jupyter Kernel...", () -> {
                widget.getTtyConnector().close();
                File connectionFile = plugin.getOrStartNewConsoleKernel();
                TtyConnector ttyConnector = createTtyConnector(connectionFile);
                widget.setTtyConnector(ttyConnector);
            });
        }

    }

    private File getJupyterConsolePath() {
        return dockingTool.getOptions(JupyterKotlinPlugin.PLUGIN_NAME).getFile(OPTION_CONSOLE_PATH, null);
    }

    private void startTerminalSession(File connectionFile) {
        TtyConnector ttyConnector = createTtyConnector(connectionFile);
        widget.setTtyConnector(ttyConnector);
        widget.start();
    }

    public void updateTerminalColors() {
        settings.refreshColors();
        widget.getTerminalPanel().repaint();
    }


    public static class PtyProcessTtyConnector extends ProcessTtyConnector {
        private final PtyProcess myProcess;

        public PtyProcessTtyConnector(@NotNull PtyProcess process, @NotNull Charset charset) {
            this(process, charset, null);
        }

        public PtyProcessTtyConnector(@NotNull PtyProcess process, @NotNull Charset charset, @Nullable List<String> commandLine) {
            super(process, charset, commandLine);
            myProcess = process;
        }

        public void resize(@NotNull TermSize termSize) {
            if (isConnected()) {
                myProcess.setWinSize(new WinSize(termSize.getColumns(), termSize.getRows()));
            }
        }

        @Override
        public boolean isConnected() {
            return myProcess.isAlive();
        }

        @Override
        public String getName() {
            return "Local";
        }
    }

    /**
     * This KeyAdapter is called by Ghidra's {@link docking.KeyBindingOverrideKeyEventDispatcher#dispatchKeyEvent(KeyEvent)}
     * while deciding if a keypress is handled by a component and should thus not trigger an Action inside the Ghidra Action system.
     * Usually the Terminal Panel would receive the KeyEvent from the Java AWT event handling system
     * which calls {@link com.jediterm.terminal.ui.TerminalPanel#processKeyEvent(KeyEvent)}, which is overriden from
     * {@link java.awt.Component#processKeyEvent(KeyEvent)}.
     * But Ghidra never forwards the event to AWT if there is a keybinding matching an action, and would instead trigger
     * the action.
     * So we handle the key event here and send it directly to the terminal,
     * and consuming it, which tells Ghidra to not process it further.
     */
    private class CustomKeyAdapter extends KeyAdapter {
        @Override
        public void keyPressed(KeyEvent e) {
            // Send the event directly to the terminal
            widget.getTerminalPanel().processKeyEvent(e);
            // Prevent Ghidra from processing the event further and triggering a keybinding
            e.consume();
        }

        @Override
        public void keyTyped(KeyEvent e) {
            widget.getTerminalPanel().processKeyEvent(e);
            // Prevent Ghidra from processing the event further, though usually not needed for keyTyped
            e.consume();
        }

        @Override
        public void keyReleased(KeyEvent e) {
            e.consume();
        }

    }

    /// Settings provider that provides a {@ColorPalette} based on the Ghidra theme
    static class ThemeAwareSettingsProvider extends DefaultSettingsProvider {
        ColorPalette cachedPalette = loadPaletteFromTheme();
        @Override
        public Font getTerminalFont() {
            return Gui.getFont("font.plugin.terminal");
        }

        public void refreshColors() {
            cachedPalette = loadPaletteFromTheme();
        }

        private ColorPalette loadPaletteFromTheme() {
            return new ColorPalette() {
                final java.awt.Color[] ansiColors = setColorArrayFromTheme();

                private java.awt.Color[] setColorArrayFromTheme() {
                    return new java.awt.Color[]{
                            Gui.getColor("color.fg.plugin.terminal.normal.black"),   // 0
                            Gui.getColor("color.fg.plugin.terminal.normal.red"),     // 1
                            Gui.getColor("color.fg.plugin.terminal.normal.green"),   // 2
                            Gui.getColor("color.fg.plugin.terminal.normal.yellow"),  // 3
                            Gui.getColor("color.fg.plugin.terminal.normal.blue"),    // 4
                            Gui.getColor("color.fg.plugin.terminal.normal.magenta"), // 5
                            Gui.getColor("color.fg.plugin.terminal.normal.cyan"),    // 6
                            Gui.getColor("color.fg.plugin.terminal.normal.white"),    // 7
                            Gui.getColor("color.fg.plugin.terminal.bright.black"),   // 8
                            Gui.getColor("color.fg.plugin.terminal.bright.red"),     // 9
                            Gui.getColor("color.fg.plugin.terminal.bright.green"),   // 10
                            Gui.getColor("color.fg.plugin.terminal.bright.yellow"),  // 11
                            Gui.getColor("color.fg.plugin.terminal.bright.blue"),    // 12
                            Gui.getColor("color.fg.plugin.terminal.bright.magenta"), // 13
                            Gui.getColor("color.fg.plugin.terminal.bright.cyan"),    // 14
                            Gui.getColor("color.fg.plugin.terminal.bright.white")     // 15
                    };
                }


                @Override
                protected @NotNull Color getForegroundByColorIndex(int i) {
                    var awtColor = ansiColors[i];
                    return new Color(awtColor.getRed(), awtColor.getGreen(), awtColor.getBlue());
                }

                @Override
                protected @NotNull Color getBackgroundByColorIndex(int i) {
                    var awtColor = ansiColors[i];
                    return new Color(awtColor.getRed(), awtColor.getGreen(), awtColor.getBlue());
                }

                @Override
                public @NotNull Color getForeground(@NotNull TerminalColor color) {
                    // We use "color.fg" and not "color.fg.plugin.terminal" here to get the general foreground color
                    // The "color.*.plugin.terminal" colors are "grey on black" even for a light theme
                    java.awt.Color foreGroundColor = Gui.getColor("color.fg");
                    return new Color(foreGroundColor.getRed(), foreGroundColor.getGreen(), foreGroundColor.getBlue());
                }

                @Override
                public @NotNull Color getBackground(@NotNull TerminalColor color) {
                    java.awt.Color backgroundColor = Gui.getColor("color.bg");
                    return new Color(backgroundColor.getRed(), backgroundColor.getGreen(), backgroundColor.getBlue());
                }
            };
        }

        @Override
        public ColorPalette getTerminalColorPalette() {
            return cachedPalette;
        }
    }

    public static class JupyterConsoleIntegration extends JupyterIntegration {
        TaskMonitorComponent taskMonitorComponent;
        public JupyterConsoleIntegration(TaskMonitorComponent  monitorComponent) {
            this.taskMonitorComponent = monitorComponent;
        }
        @Override
        public void onLoaded(@NotNull JupyterIntegration.Builder builder) {
            builder.beforeCellExecution((it) -> {
                taskMonitorComponent.setVisible(true);
                return Unit.INSTANCE;
            });
            builder.afterCellExecution((p1, p2, p3) -> {
                taskMonitorComponent.setVisible(false);
                return Unit.INSTANCE;
            });
            builder.onInterrupt((it) -> {
//                taskMonitorComponent.cancel();
                return Unit.INSTANCE;
            });
        }
    }


}

