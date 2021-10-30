# Ghidra-Jupyter

## Automatic Installation

1. Use pip to install the kernel and the management utility
    
    ```bash
   pip install ghidra-jupyter
    ```
   
2. Use the management utility to install the extension.
   Make sure `$GHIDRA_INSTALL_DIR` is defined,
   as it points the utility to the right path.

    ```bash
    ghidra-jupyter install-extension
   ```
   
3. If you have multiple installs of Ghidra,
   you can point the installer to the right one.
   
   ```bash
   ghidra-jupyter install-extension --ghidra <my-ghidra-install-dir>
   ```
   
## Manual Installation

1. Use pip to install the kernel and the management utility
    
    ```bash
   pip install ghidra-jupyter
    ```
   
2. Download `GhidraJupyterKotlin-1.0.0.zip` from our releases page
3. Place the zip under `$GHIDRA_INSTALL_DIR/Ghidra/Extensions/`
   
## Usage

After installation, you should be prompted about a new plugin when opening the CodeBrowser. Confirm the installation and activate it via "File -> Configure..." and ticking the checkbox for the "Miscellaneous" Group.

Directly after you'll see 2 new buttons and a new menu inside Ghidra.

![Ghidra Buttons](resources/readme/buttons.png)

![Ghidra Menu](resources/readme/menu.png)


The third action is only available in the menu and provides a shortcut
to open an already running `juptyter-notebook` server or to start a new one.


### Kotlin QtConsole

This feature requires the Jupyter QT Console to be installed and `jupyter-qtconsole` to be available in your `PATH`. This is a separate package on PyPI and in most distros, so you typically need to explicitly install it.

Click the ![QtConsole] button to open a QtConsole.

Once you click, a Jupyter Kernel will be initialized in the current Ghidra program
and the Jupyter QtConsole will launch.

![QtConsole Window](resources/readme/qtconsole_window.png)

#### Caveats

If you want to interrupt the code you executed, the menu action "Interrupt Current Kernel" or "Ctrl+C" will NOT work. It will simply print `Cannot interrupt a kernel I did not start.`

This is a limitation of the Jupyter QT console. To work around this issue, the plugin provides an action `Interrupt Execution` in the `Jupyter` submenu. This will interrupt the curently executed cell:

![Interrupt Demo](resources/readme/interrupt_demo.png)


### Jupyter Notebook

1. Start Jupyter Notebook or Jupyter Lab
   
   ```bash
   jupyter notebook
   ```
   
   or by using the menu action.

2. Click the ![Notebook] button in Ghidra to accept a notebook connection

   The following popup will show, indicating that Ghidra is actively waiting

   ![Awaiting Connection](resources/readme/waiting.png)

3. In the Jupyter Notebook home page, create a Ghidra(Kotlin) notebook

   ![Create Notebook](resources/readme/create_notebook.png)

   Once you do, the notebook will connect to your waiting Ghidra instance.
   
   ![Jupyter Notebook](resources/readme/notebook_view.png)

[QtConsole]:resources/readme/qtconsole.png
[Notebook]:resources/readme/notebook.png

## Demo Snippets

These snippets can be pasted directly in the QT console or a notebook cell.

### Kotlin Extensions

[Extensions](https://kotlinlang.org/docs/extensions.html#extensions-are-resolved-statically) are a Kotlin feature which allows extending existing classes with new methods, properties or operators. This allows various convience features, especially combined with other Kotlin Features like operator overloading and easily providing lambdas. They need to be explicitly imported in your script/kernel before using them:

```kotlin
// Import all extensions in the GhidraJupyterKotlin.extensions.address package
import GhidraJupyterKotlin.extensions.address.*
```

If you end up writing any kind of extension method/property/operator we would be happy to recieve a PR.
Not all extension provided are documented in the README.md, check the [extensions folder](./GhidraJupyterKotlin/src/main/java/GhidraJupyterKotlin/extensions) for all of them. Nearly all of them are fairly simple (a few lines at most) so they can also serve as good examples how to write your own.

#### Explicit Database Transactions

Unlike the Jython REPL, the Kotlin Kernel does NOT wrap each cell in an implicit Database transaction. Any attempt to modify the Database will result in `NoTransactionException: Transaction has not been started`.

Instead there is an extension method on the `UndoableDomainObject` interface, that makes Database transactions explicit with minimal syntactic overhead.

```kotlin
// Regular usage without extension via the official Ghidra API
val transactionID = currentProgram.startTransaction("Transaction Description")
/* your code modifying the DB */
currentProgram.name = "NewName"
currentProgram.endTransaction(transactionID, true) // true means the changes should be commited to the DB

// Using the extension
import GhidraJupyterKotlin.extensions.misc.*

currentProgram.runTransaction("Transaction Description") {
	/* your code modifying the DB */
	currentProgram.name = "NewName"
}


// There is another extension that only takes a function and uses a default transaction description
currentProgram.runTransaction {
	currentProgram.name = "NewName
}

```

If the code throws any kind of Exception the transaction will be aborted, i.e. `.endTransaction` will be called with `commit=false`.


#### Address Arithmetic with Operators

Unlike Java, Kotlin supports [operator overloading](https://kotlinlang.org/docs/operator-overloading.html). This can be used to make calculations involving addresses more comfortable:

```kotlin
import GhidraJupyterKotlin.extensions.address.*
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressRange

val x: Address = currentAddress + 0x10  // Address + Offset (Int or Long)
val y: Address = currentAddress - 0x10  // Address - Offset (Int or Long)
val z: Address = x - y 			// Difference between Addresses

val range: AddressRange = y..x // The range of addresses between currentAddress-0x10 and currentAddress+0x10

```

### Export x64dbg labels into clipboard

Generate a `x64dbg` script based on the `currentProgram` that labels all the functions in `x64dbg` and stores it in the clipboard

```kotlin
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;

currentProgram.functionManager.getFunctions(false)
.map { f -> "lblset 0x${f.entryPoint.offset}, ${f.name}"}.joinToString("\n")
.let { 
    val sel = StringSelection(it)
    Toolkit.getDefaultToolkit().systemClipboard.setContents(sel, sel)
}
```


## Building the Ghidra Plugin

1. Get the [kotlin-jupyter-kernel] jars
   1. Install the Kotlin Jupyter kernel
      ```bash
      pip install kotlin-jupyter-kernel
      ```
   2. Copy the JARs over to `GhidraJupyterKotlin/lib`
      1. First, we use `pip show kotlin-jupyter-kernel` to see where it was installed
         ```bash
         pip show kotlin-jupyter-kernel
         ```
      
      2. From the Location line (usually site-packages) we go to the run-kotlin-kernel package and copy the jars.
         So `site-packages/run-kotlin-kernel/jars/*`. The contents should be:
         ```text
         annotations-13.0.jar
         jupyter-lib-0.8.3.1.jar
         kotlin-jupyter-kernel-0.8.3.1.jar
         kotlin-reflect-1.4.30-dev-2223.jar
         kotlin-script-runtime-1.4.30-dev-2223.jar
         kotlin-stdlib-1.4.30-dev-2223.jar
         kotlin-stdlib-common-1.4.30-dev-2223.jar
         ```
   3. Build the Ghidra plugin
      ```bash
      cd GhidraJupyterKotlin
      gradle
      ```
   4. Install the plugin using the ghidra-jupyter installer
      ```bash
      ghidra-jupyter install-extension --extension-path GhidraJupyterKotlin/dist/<today's-zip-file>
      ```
      
## Licenses

This project is released under the MIT license.

The project uses components that are released under different licenses:

- [kotlin-jupyter](https://github.com/Kotlin/kotlin-jupyter) is released under the Apache-2.0 License
- The Kotlin runtime and libraries are released under the Apache-2.0 License
