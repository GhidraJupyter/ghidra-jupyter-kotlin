package GhidraJupyterKotlin;


import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class ConnectionFile {

    public static File create() {
        return writeConfigFile();

    }

    private static List<Integer> getPorts(Integer n) {
        ArrayList<Socket> sockets = new ArrayList<>();
        try {
            for (int i = 0; i < n; i++) {
                Socket s = new Socket();
                s.setSoLinger(false, 0);
                s.bind(new InetSocketAddress("", 0));
                sockets.add(s);
            }
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
        ArrayList<Integer> ports = new ArrayList<>();
        for (Socket s : sockets) {
            ports.add(s.getLocalPort());
            try {
                s.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        return ports;
    }


    private static String getJupyterRuntime() {
        ProcessBuilder builder = new ProcessBuilder("jupyter", "--runtime-dir");
        try {

            Process process = builder.start();
            process.waitFor();

            BufferedReader processOutputReader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));

            return processOutputReader.readLine().strip();
        } catch (InterruptedException | IOException e) {
            e.printStackTrace();
            return null;
        }
    }


    private static String formatConnectionFile(String key, List<Integer> ports) {
        return String.format("{\n" +
                "  \"control_port\": %d,\n" +
                "  \"shell_port\": %d,\n" +
                "  \"transport\": \"tcp\",\n" +
                "  \"signature_scheme\": \"hmac-sha256\",\n" +
                "  \"stdin_port\": %d,\n" +
                "  \"hb_port\": %d,\n" +
                "  \"ip\": \"127.0.0.1\",\n" +
                "  \"iopub_port\": %d,\n" +
                "  \"key\": \"%s\"\n" +
                "}", ports.get(0), ports.get(1), ports.get(2), ports.get(3), ports.get(4), key);
    }

    private static File writeConfigFile() {
        String key = UUID.randomUUID().toString();
        List<Integer> ports = getPorts(5);
        if (ports == null) {
            return null;
        }
        String runtimeDir = getJupyterRuntime();
        File kernelFile = new File(runtimeDir, String.format("kernel-%s.json", key));
        // Make sure that the directory actually exists
        // this is not guaranteed by only invoking `jupyter --runtime-dir`
        // on new machines that never did anything with jupyter the directory won't exist
        // and writing the file will fail
        try {
            Files.createDirectories(kernelFile.getParentFile().toPath());
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }

        String connectionFile = formatConnectionFile(key, ports);

        try {
            BufferedWriter writer = new BufferedWriter(new FileWriter(kernelFile));
            writer.write(connectionFile);
            writer.flush();
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }

        return kernelFile;
    }
}
