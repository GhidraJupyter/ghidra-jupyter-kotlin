// Generate a x64dbg script based on the currentProgram that labels all the functions in x64dbg and stores it in the clipboard
//@category    Debugger

import ghidra.app.script.GhidraScript
import GhidraJupyterKotlin.extensions.misc.*
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection


@Suppress("unused")
class Dumpx64dbgLabels : GhidraScript() {
    @Throws(Exception::class)
    override fun run() {
        currentProgram.functions
            .map { f -> "lblset 0x${f.entryPoint.offset}, ${f.name}"}
            .joinToString("\n")
            .let {
                val sel = StringSelection(it)
                Toolkit.getDefaultToolkit().systemClipboard.setContents(sel, sel)
            }
    }
}