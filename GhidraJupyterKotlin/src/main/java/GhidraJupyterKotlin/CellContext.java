package GhidraJupyterKotlin;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

public class CellContext extends GhidraScript {

    ProgramLocation currentContextLocation;

    public CellContext(GhidraScript script) {
        super();
        this.set(script.getState(),
                script.getMonitor(),
                null
        );
    }

    public CellContext() {
        super();
    }



    @Override
    protected void run() throws Exception {
        throw new Exception("This is not supposed to be run as a script!");
    }

    @Override
    public void print(String message) {
        super.print(message);
        System.out.print(message);
    }

    @Override
    public void println(String message) {
        super.println(message);
        System.out.println(message);
    }

    // Expose protected variables with a getter
    // Kotlin will allow accessing them without the get prefix
    // e.g. currentAddress in the Jupyter console will call this function and not return currentAddress directly
    // This also allows adding some extra useful helpers like currentFunction

    public Address getCurrentAddress() {
        return currentAddress;
    }

    // This is not the same as the currentLocation in the Jython Shell or Ghidra Scripts
    // This uses the object provided to GhidraJupyterKotlin.JupyterKotlinPlugin.locationChanged directly
    // This contains more information like the exact token referenced in the decompiler or disassembly listing
    // The normal currentLocation in the Jython shell seems to be always simply the current address which is less useful
    public ProgramLocation getCurrentLocation() {
        return currentContextLocation;
    }

    public ProgramSelection getCurrentSelection() {
        return currentSelection;
    }

    public ProgramSelection getCurrentHighlight() {
        return currentHighlight;
    }

    public Function getCurrentFunction() {
        return currentProgram.getFunctionManager().getFunctionContaining(currentAddress);
    }

}
