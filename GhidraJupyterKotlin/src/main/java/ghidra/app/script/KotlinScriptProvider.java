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

import generic.io.NullPrintWriter;
import generic.jar.ResourceFile;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.util.Msg;
import org.jetbrains.kotlin.cli.common.CLIConfigurationKeys;
import org.jetbrains.kotlin.cli.common.arguments.K2JVMCompilerArguments;
import org.jetbrains.kotlin.cli.common.config.ContentRootsKt;
import org.jetbrains.kotlin.cli.common.messages.CompilerMessageSeverity;
import org.jetbrains.kotlin.cli.jvm.K2JVMCompiler;
import org.jetbrains.kotlin.cli.jvm.compiler.EnvironmentConfigFiles;
import org.jetbrains.kotlin.cli.jvm.compiler.KotlinCoreEnvironment;
import org.jetbrains.kotlin.cli.jvm.compiler.KotlinToJVMBytecodeCompiler;
import org.jetbrains.kotlin.cli.jvm.config.JvmContentRootsKt;
import org.jetbrains.kotlin.com.intellij.openapi.util.Disposer;
import org.jetbrains.kotlin.config.CommonConfigurationKeys;
import org.jetbrains.kotlin.config.CompilerConfiguration;
import org.jetbrains.kotlin.config.JVMConfigurationKeys;
import org.jetbrains.kotlin.utils.PathUtil;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;


@SuppressWarnings("unused")
// This is an ExtensionPoint, so the class loader automatically searches for classes ending in "ScriptProvider"
// and sets them up
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
        //noinspection ResultOfMethodCallIgnored
        clazzFile.delete();
        return super.deleteScript(scriptSource);
    }

    @Override
    public GhidraScript getScriptInstance(ResourceFile sourceFile, PrintWriter writer)
            throws GhidraScriptLoadException {

        if (writer == null) {
            writer = new NullPrintWriter();
        }

        // Assuming script is in default java package, so using script's base name as class name.
        File clazzFile = getClassFile(sourceFile, GhidraScriptUtil.getBaseName(sourceFile));
        try {
            compile(sourceFile, writer); // may throw an exception
        } catch (ClassNotFoundException e) {
            throw new GhidraScriptLoadException("The class could not be found. " +
                    "It must be the public class of the .java file: " + e.getMessage(), e);
        }


        Class<?> clazz;
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

        Object object = null;
        try {
            // If clazz is null for some reason crashing with it might make it more obvious where the issue lies
            //noinspection ConstantConditions
            object = clazz.getDeclaredConstructor().newInstance();
        } catch (InvocationTargetException | NoSuchMethodException e) {
            throw new GhidraScriptLoadException(e);
        } catch (InstantiationException | IllegalAccessException e) {
            throw new GhidraScriptLoadException(e);
        }
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

        return resourceFile.getFile(false);
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

    protected void compile(ResourceFile sourceFile, final PrintWriter writer)
            throws ClassNotFoundException {
        if (!doEmbeddedCompile(sourceFile, writer)) {
            writer.flush(); // force any error messages out
            throw new ClassNotFoundException("Unable to compile class: " + sourceFile.getName());
        }
        writer.println("Successfully compiled: " + sourceFile.getName());
    }

    private K2JVMCompilerArguments getCompilerArgs(K2JVMCompiler compiler){
        var arguments = compiler.createArguments();
        var cp = getClassPath();

        arguments.setClasspath(cp);

        return arguments;
    }
    private boolean doEmbeddedCompile(ResourceFile sourceFile, final PrintWriter writer) {
        Msg.info(this, "Compiling sourceFile: " + sourceFile.getAbsolutePath());

        if (System.getProperty("os.name").startsWith("Windows")) {
            System.getProperties().setProperty("idea.io.use.nio2", java.lang.Boolean.TRUE.toString());
        }

        var rootDisposable = Disposer.newDisposable();
        var compiler = new K2JVMCompiler();
        var args = getCompilerArgs(compiler);
        var compilerConfiguration = new CompilerConfiguration();
        // TODO: What is a good module name here?
        compilerConfiguration.put(CommonConfigurationKeys.MODULE_NAME, "SOME_MODULE_NAME");
        var collector = new KotlinCompilerMessageCollector(sourceFile);
        compilerConfiguration.put(CLIConfigurationKeys.MESSAGE_COLLECTOR_KEY, collector);
        JvmContentRootsKt.addJvmClasspathRoots(compilerConfiguration, PathUtil.getJdkClassesRootsFromCurrentJre());
        JvmContentRootsKt.addJvmClasspathRoots(compilerConfiguration, getClassPathAsFiles());
        ContentRootsKt.addKotlinSourceRoot(compilerConfiguration, sourceFile.toString());
        compilerConfiguration.put(JVMConfigurationKeys.OUTPUT_DIRECTORY, outputDir(sourceFile).getFile(false));

        // This shouldn't be needed and is a workaround for a bug in the Kotlin compiler
        // https://youtrack.jetbrains.com/issue/KT-20167/JDK-9-unresolved-supertypes-Object-when-working-with-Kotlin-Scripting-API
        compilerConfiguration.put(JVMConfigurationKeys.JDK_HOME, new File(System.getProperty("java.home")));

        var disposable = Disposer.newDisposable();

        KotlinCoreEnvironment env = KotlinCoreEnvironment.createForProduction(
                disposable, compilerConfiguration, EnvironmentConfigFiles.JVM_CONFIG_FILES);

        return KotlinToJVMBytecodeCompiler.INSTANCE.compileBunchOfSources(env);
    }

    private List<File> getClassPathAsFiles(){
        return Arrays.stream(System.getProperty("java.class.path").split(File.pathSeparator))
                .map(File::new)
                // There might be files like "ExtensionPoint.manifest" as a classpath entry
                // the Kotlin compiler tries to open them as .jars (ZIP) and fails, so filter them out
                .filter(it -> it.getName().endsWith(".jar") || it.isDirectory())
                .collect(Collectors.toList());
    }

    private ResourceFile outputDir(ResourceFile sourceFile) {
        return sourceFile.getParentFile();
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
            return cl.loadClass(clazzName);
        }
        catch (NoClassDefFoundError | ClassNotFoundException e) {
            Msg.error(this, "Unable to find class file for script file: " + scriptSourceFile, e);

        }
        catch (MalformedURLException e) {
            Msg.error(this, "Malformed URL exception:", e);
        }
        return null;
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

    private String getClassPath() {
        return System.getProperty("java.class.path");
    }

    @Override
    public void createNewScript(ResourceFile newScript, String category) throws IOException {
        String scriptName = newScript.getName();
        String className = scriptName;
        int dotPos = scriptName.lastIndexOf('.');
        if (dotPos >= 0) {
            className = scriptName.substring(0, dotPos);
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
