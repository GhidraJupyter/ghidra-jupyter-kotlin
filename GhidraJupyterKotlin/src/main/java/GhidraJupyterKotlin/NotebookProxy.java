package GhidraJupyterKotlin;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

class NotebookProxy {
    File proxyFile;
    File pidFile;

    public NotebookProxy(Path proxyBase) {
        this.proxyFile = new File(proxyBase.toString() + ".path");
        this.pidFile = new File(proxyBase.toString() + ".pid");
    }

    public File waitForConnection(TaskMonitor monitor) throws IOException, CancelledException {
        // Write the PID to file so that the
        pidFile.delete();
        pidFile.createNewFile();
        pidFile.deleteOnExit();

        long pid = ProcessHandle.current().pid();
        Files.write(Path.of(pidFile.getPath()), Long.toString(pid).getBytes(), StandardOpenOption.APPEND);

        // Create a proxy file and wait for a line on it
        proxyFile.delete();
        proxyFile.createNewFile();
        proxyFile.deleteOnExit();

        var lineReader = new LineReader(proxyFile);

        return new File(lineReader.readLine(monitor));
    }
}
