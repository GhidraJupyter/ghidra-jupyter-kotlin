package GhidraJupyterKotlin;

import ghidra.util.task.MonitoredRunnable;

import java.io.File;

public interface KernelThread extends MonitoredRunnable {
    File getConnectionFile();
}
