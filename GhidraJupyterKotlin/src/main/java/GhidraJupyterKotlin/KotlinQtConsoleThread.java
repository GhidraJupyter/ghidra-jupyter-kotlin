package GhidraJupyterKotlin;

import ghidra.util.Msg;
import ghidra.util.task.MonitoredRunnable;
import ghidra.util.task.TaskMonitor;
import org.jetbrains.kotlinx.jupyter.IkotlinKt;
import org.jetbrains.kotlinx.jupyter.libraries.EmptyResolutionInfoProvider;
import org.zeromq.ZMQException;

import java.io.*;
import java.util.*;

public class KotlinQtConsoleThread implements KernelThread {

    private final CellContext context;
    private final File connectionFile;

    public KotlinQtConsoleThread(CellContext ctx, File connectionFile) {
        this.context = ctx;
        this.connectionFile = connectionFile;
    }

    @Override
    public void monitoredRun(TaskMonitor monitor) {
        Msg.info(this, connectionFile.toString());
        try {
            IkotlinKt.embedKernel(
                    connectionFile,
                    null,
                    Collections.singletonList(context));
        } catch( ZMQException e){
           Msg.warn(this,"Kernel terminated, probably because of shutdown request?", e);
        }
    }

    @Override
    public File getConnectionFile() {
        return connectionFile;
    }
}
