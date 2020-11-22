package GhidraJupyterKotlin;

import ghidra.util.Msg;
import ghidra.util.task.MonitoredRunnable;
import ghidra.util.task.TaskMonitor;
import org.jetbrains.kotlin.jupyter.IkotlinKt;

import java.io.*;
import java.util.*;

public class KotlinQtConsoleThread implements MonitoredRunnable {

    private final CellContext context;
    private final File connectionFile;

    public KotlinQtConsoleThread(CellContext ctx, File connectionFile) {
        this.context = ctx;
        this.connectionFile = connectionFile;
    }

    @Override
    public void monitoredRun(TaskMonitor monitor) {
        Msg.info(this, connectionFile.toString());
        IkotlinKt.embedKernel(
                connectionFile,
                null,
                Collections.singletonList(context));
    }

}
