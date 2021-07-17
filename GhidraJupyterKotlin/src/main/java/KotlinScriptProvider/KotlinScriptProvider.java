/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.script;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.lang.*;

import javax.tools.JavaFileObject.Kind;

import generic.io.NullPrintWriter;
import generic.jar.*;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.util.Msg;


public class KotlinScriptProvider extends GhidraScriptProvider {

    @Override
    public String getDescription() {
        return "Kotlin";
    }

    @Override
    public String getExtension() {
        return ".kt";
    }

    @Override
    public boolean deleteScript(ResourceFile scriptSource) {
        // Assuming script is in default java package, so using script's base name as class name.
        File clazzFile = getClassFile(scriptSource, GhidraScriptUtil.getBaseName(scriptSource));
        clazzFile.delete();
        return super.deleteScript(scriptSource);
    }

    @Override
    public GhidraScript getScriptInstance(ResourceFile sourceFile, PrintWriter writer)
            throws ClassNotFoundException, InstantiationException, IllegalAccessException {

        if (writer == null) {
            writer = new NullPrintWriter();
        }

        // Assuming script is in default java package, so using script's base name as class name.
        File clazzFile = getClassFile(sourceFile, GhidraScriptUtil.getBaseName(sourceFile));
        compile(sourceFile, writer); // may throw an exception


        Class<?> clazz = null;
        try {
            clazz = getScriptClass(sourceFile);
        }
        catch (GhidraScriptUnsupportedClassVersionError e) {
            // Unusual Code Alert!: This implies the script was compiled in a newer
            // version of Java.  So, just delete the class file and try again.
            ResourceFile classFile = e.getClassFile();
            classFile.delete();
            return getScriptInstance(sourceFile, writer);
        }

        Object object = clazz.newInstance();
        if (object instanceof GhidraScript) {
            GhidraScript script = (GhidraScript) object;
            script.setSourceFile(sourceFile);
            return script;
        }

        String message = "Not a valid Ghidra script: " + sourceFile.getName();
        writer.println(message);
        Msg.error(this, message); // the writer may not be the same as Msg, so log it too
        return null; // class is not a script
    }


    /**
     * Gets the class file corresponding to the given source file and class name.
     * If the class is in a package, the class name should include the full
     * package name.
     *
     * @param sourceFile The class's source file.
     * @param className  The class's name (including package if applicable).
     * @return The class file corresponding to the given source file and class name.
     */
    protected File getClassFile(ResourceFile sourceFile, String className) {
        ResourceFile resourceFile =
                getClassFileByResourceFile(sourceFile, className);

        File file = resourceFile.getFile(false);
        return file;
    }

    static ResourceFile getClassFileByResourceFile(ResourceFile sourceFile, String rawName) {
        String javaAbsolutePath = sourceFile.getAbsolutePath();
        String classAbsolutePath = javaAbsolutePath.replace(".java", ".class");

        return new ResourceFile(classAbsolutePath);
    }

    protected boolean needsCompile(ResourceFile sourceFile, File classFile) {

        // Need to compile if there is no class file.
        if (!classFile.exists()) {
            return true;
        }

        // Need to compile if the script's source file is newer than its corresponding class file.
        if (sourceFile.lastModified() > classFile.lastModified()) {
            return true;
        }

        // Need to compile if parent classes are not up to date.
        return !areAllParentClassesUpToDate(sourceFile);
    }


    private boolean areAllParentClassesUpToDate(ResourceFile sourceFile) {

        List<Class<?>> parentClasses = getParentClasses(sourceFile);
        if (parentClasses == null) {
            // some class is missing!
            return false;
        }

        if (parentClasses.isEmpty()) {
            // nothing to do--no parent class to re-compile
            return true;
        }

        // check each parent for modification
        for (Class<?> clazz : parentClasses) {
            ResourceFile parentFile = getSourceFile(clazz);
            if (parentFile == null) {
                continue; // not sure if this can happen (inner-class, maybe?)
            }

            // Parent class might have a non-default java package, so use class's full name.
            File clazzFile = getClassFile(parentFile, clazz.getName());

            if (parentFile.lastModified() > clazzFile.lastModified()) {
                return false;
            }
        }

        return true;
    }

    protected boolean compile(ResourceFile sourceFile, final PrintWriter writer)
            throws ClassNotFoundException {
        if (!doCompile(sourceFile, writer)) {
            writer.flush(); // force any error messages out
            throw new ClassNotFoundException("Unable to compile class: " + sourceFile.getName());
        }
        writer.println("Successfully compiled: " + sourceFile.getName());
        return true;
    }

    String preparePath(String path) {
        // `kotlinc` doesn't seem to handle Winodws-style paths (with `\` in them) so
        // we're ensuring that all path-separators are `/`.
        return String.format("\"%s\"", path.replace(File.separator, "/"));
    }

    private void writeCompilerArgfile(ResourceFile sourceFile, String outputDirectory, Path compilerArgsPath) throws FileNotFoundException {
        List<String> args = new ArrayList<String>();
        args.add("-api-version");
        args.add("1.3");
        args.add("-d");
        args.add(preparePath(outputDirectory));
        args.add("-classpath");
        args.add(preparePath(getClassPath()));
        args.add(preparePath(sourceFile.getAbsolutePath()));

        PrintStream printStream = new PrintStream(new FileOutputStream(compilerArgsPath.toFile()));


        printStream.print(String.join(" ", args));
    }

    private boolean doCompile(ResourceFile sourceFile, final PrintWriter writer) {

        List<ResourceFileJavaFileObject> list = new ArrayList<>();
        list.add(
                new ResourceFileJavaFileObject(sourceFile.getParentFile(), sourceFile, Kind.SOURCE));

        String outputDirectory = outputDir(sourceFile).getAbsolutePath();
        Msg.trace(this, "Compiling script " + sourceFile + " to dir " + outputDirectory);

        Path compilerArgsPath = Paths.get(outputDirectory, "kotlinc.argfile");

        try {
            writeCompilerArgfile(sourceFile, outputDirectory, compilerArgsPath);
        } catch (FileNotFoundException e) {
            String message = String.format("Unable to create compiler arguments file: %s", compilerArgsPath.toAbsolutePath().toString());
            Msg.error(this, message);
            writer.println(message);
            return false;
        }

        try {

            Process process = launchCompiler(compilerArgsPath);

            StringBuilder processOutput = new StringBuilder();

            try (BufferedReader processOutputReader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));) {
                String readLine;

                while ((readLine = processOutputReader.readLine()) != null) {
                    processOutput.append(readLine);
                    processOutput.append(System.lineSeparator());
                }

                process.waitFor();
            }

            if (process.exitValue() != 0) {
                String message = processOutput.toString();
                Msg.error(this, message);
                writer.write(message);
                return false;
            }

            return true;
        } catch (InterruptedException | IOException e) {
            String message = "kotlinc invocation failed";
            Msg.error(this, message);
            writer.println(message);
            return false;
        }

    }

    private ResourceFile outputDir(ResourceFile sourceFile) {
        return sourceFile.getParentFile();
    }

    private Process launchCompiler(Path compilerArgsPath) throws IOException {
        try {
            ProcessBuilder builder = new ProcessBuilder("kotlinc", "@" + compilerArgsPath.toAbsolutePath().toString());
            builder.redirectErrorStream(true);
            return builder.start();

        } catch (IOException exception) {
            if (System.getProperty("os.name").toLowerCase().contains("win")) {
                ProcessBuilder builder = new ProcessBuilder("cmd.exe", "/c", "kotlinc", "@" + compilerArgsPath.toAbsolutePath().toString());
                builder.redirectErrorStream(true);
                return builder.start();
            }

            throw exception;
        }
    }

    private List<Class<?>> getParentClasses(ResourceFile scriptSourceFile) {

        Class<?> scriptClass = getScriptClass(scriptSourceFile);
        if (scriptClass == null) {
            return null; // special signal that there was a problem
        }

        List<Class<?>> parentClasses = new ArrayList<>();
        Class<?> superClass = scriptClass.getSuperclass();
        while (superClass != null) {
            if (superClass.equals(GhidraScript.class)) {
                break; // not interested in the built-in classes
            } else if (superClass.equals(HeadlessScript.class)) {
                break; // not interested in the built-in classes
            }
            parentClasses.add(superClass);
            superClass = superClass.getSuperclass();
        }
        return parentClasses;
    }

    private Class<?> getScriptClass(ResourceFile scriptSourceFile) {
        String clazzName = GhidraScriptUtil.getBaseName(scriptSourceFile);
        try {
            URL classURL = outputDir(scriptSourceFile).getFile(false).toURI().toURL();
            ClassLoader cl = new URLClassLoader(new URL[] {classURL});
            Class<?> clazz = cl.loadClass(clazzName);
            return clazz;
        }
        catch (NoClassDefFoundError | ClassNotFoundException e) {
            Msg.error(this, "Unable to find class file for script file: " + scriptSourceFile, e);
        }
        catch (MalformedURLException e) {
            Msg.error(this, "Malformed URL exception:", e);
        }
        return null;
    }

    private void compileParentClasses(ResourceFile sourceFile, PrintWriter writer) {

        List<Class<?>> parentClasses = getParentClasses(sourceFile);
        if (parentClasses == null) {
            // this shouldn't happen, as this method is called after the child class is
            // re-compiled and thus, all parent classes should still be there.
            return;
        }

        if (parentClasses.isEmpty()) {
            // nothing to do--no parent class to re-compile
            return;
        }

        //
        // re-compile each class's source file
        //

        // first, reverse the order, so that we compile the highest-level classes first,
        // and then on down, all the way to the script class
        Collections.reverse(parentClasses);

        // next, add back to the list the script that was just compiled, as it may need
        // to be re-compiled after the parent classes are re-compiled
        Class<?> scriptClass = getScriptClass(sourceFile);
        if (scriptClass == null) {
            // shouldn't happen
            return;
        }
        parentClasses.add(scriptClass);

        for (Class<?> parentClass : parentClasses) {
            ResourceFile parentFile = getSourceFile(parentClass);
            if (parentFile == null) {
                continue; // not sure if this can happen (inner-class, maybe?)
            }

            if (!doCompile(parentFile, writer)) {
                Msg.error(this, "Failed to re-compile parent class: " + parentClass);
                return;
            }
        }
    }

    private ResourceFile getSourceFile(Class<?> c) {
        // check all script paths for a dir named
        String classname = c.getName();
        String filename = classname.replace('.', '/') + ".kt";

        List<ResourceFile> scriptDirs = GhidraScriptUtil.getScriptSourceDirectories();
        for (ResourceFile dir : scriptDirs) {
            ResourceFile possibleFile = new ResourceFile(dir, filename);
            if (possibleFile.exists()) {
                return possibleFile;
            }
        }

        return null;
    }

    private String getSourcePath() {
        String classpath = System.getProperty("java.class.path");
        List<ResourceFile> dirs = GhidraScriptUtil.getScriptSourceDirectories();
        for (ResourceFile dir : dirs) {
            classpath += (System.getProperty("path.separator") + dir.getAbsolutePath());
        }
        return classpath;
    }

    private String getClassPath() {
        String classpath = System.getProperty("java.class.path");
        return classpath;
    }

    @Override
    public void createNewScript(ResourceFile newScript, String category) throws IOException {
        String scriptName = newScript.getName();
        String className = scriptName;
        int dotpos = scriptName.lastIndexOf('.');
        if (dotpos >= 0) {
            className = scriptName.substring(0, dotpos);
        }
        PrintWriter writer = new PrintWriter(new FileWriter(newScript.getFile(false)));

        writeHeader(writer, category);

        writer.println("import ghidra.app.script.GhidraScript");

        for (Package pkg : Package.getPackages()) {
            if (pkg.getName().startsWith("ghidra.program.model.")) {
                writer.println("import " + pkg.getName() + ".*");
            }
        }

        writer.println("");

        writer.println("class " + className + " : GhidraScript() {");

        writer.println("    @Throws(Exception::class)");
        writer.println("    override fun run() {");

        writeBody(writer);

        writer.println("    }");
        writer.println("");
        writer.println("}");
        writer.println("");
        writer.close();
    }

    @Override
    public String getCommentCharacter() {
        return "//";
    }
}
