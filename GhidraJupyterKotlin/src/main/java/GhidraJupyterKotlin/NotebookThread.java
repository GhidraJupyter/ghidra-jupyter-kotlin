package GhidraJupyterKotlin;


import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.MonitoredRunnable;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import org.jetbrains.kotlinx.jupyter.IkotlinKt;
import org.jetbrains.kotlinx.jupyter.libraries.EmptyResolutionInfoProvider;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Collections;
import java.util.Optional;

public class NotebookThread implements MonitoredRunnable {
    /**
     * Steps:
     * 1. Create proxy file
     * 2. Wait on proxy file
     * 3. Read connection file path
     * 4. Embed kernel
     */

    private final CellContext context;
    private final PluginTool tool;
    private File connectionFile = null;

    public NotebookThread(CellContext ctx, PluginTool tool) {
        this.context = ctx;
        this.tool = tool;
    }

    private class WaitTask extends Task {
        public WaitTask() {
            super("Waiting for Jupyter Notebook connection",
                    true,
                    false,
                    true,
                    true);
        }

        @Override
        public void run(TaskMonitor taskMonitor) throws CancelledException {
            var proxyPath = Path.of(Optional.ofNullable(System.getenv("GHIDRA_JUPYTER_PROXY"))
                    .orElse(
                            Path.of(System.getProperty("user.home"))
                                    .resolve(".ghidra")
                                    .resolve("notebook_proxy")
                                    .toString()
                    ));
            try {
                connectionFile = new NotebookProxy(proxyPath).waitForConnection(taskMonitor);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    @Override
    public void monitoredRun(TaskMonitor monitor) {
        if (connectionFile == null) {
            tool.execute(new WaitTask());
        }

        Msg.info(this, connectionFile.toString());
        IkotlinKt.embedKernel(
                connectionFile,
                EmptyResolutionInfoProvider.INSTANCE,
                Collections.singletonList(context));
    }

}
