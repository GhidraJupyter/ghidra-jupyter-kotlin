package GhidraJupyterKotlin;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

class LineReader {
    BufferedReader reader;

    public LineReader(File file) throws FileNotFoundException {
        reader = new BufferedReader(new FileReader(file));
    }

    public String readLine(TaskMonitor monitor) throws IOException, CancelledException {
        while (!reader.ready()) {
            try {
                if (monitor.isCancelled()){
                    throw new CancelledException();
                }
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        return reader.readLine();
    }
}
