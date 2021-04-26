package GhidraJupyterKotlin;

import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.util.Msg;
import org.jetbrains.kotlinx.jupyter.IkotlinKt;
import org.jetbrains.kotlinx.jupyter.libraries.EmptyResolutionInfoProvider;

import java.io.File;
import java.util.Collections;

public class GhidraKotlinKernelLaunchable implements GhidraLaunchable {
    @Override
    public void launch(GhidraApplicationLayout ghidraApplicationLayout, String[] args) throws Exception {
        var connectionFile = new File(args[0]);
        Msg.info(this, connectionFile.toString());
        IkotlinKt.embedKernel(
                connectionFile,
                EmptyResolutionInfoProvider.INSTANCE,
                null);
    }
}
