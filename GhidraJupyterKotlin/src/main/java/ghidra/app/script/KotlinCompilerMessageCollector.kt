package ghidra.app.script

import generic.jar.ResourceFile
import ghidra.util.Msg
import org.jetbrains.kotlin.cli.common.messages.CompilerMessageSeverity
import org.jetbrains.kotlin.cli.common.messages.CompilerMessageSourceLocation
import org.jetbrains.kotlin.cli.common.messages.MessageCollector

class KotlinCompilerMessageCollector(private val sourceFile: ResourceFile) : MessageCollector {
    override fun clear() {
        return
    }

    override fun hasErrors(): Boolean {
        return false
    }

    override fun toString(): String {
        return "MessageCollector for compilation of $sourceFile"
    }
    override fun report(severity: CompilerMessageSeverity, message: String, location: CompilerMessageSourceLocation?) {
        when (severity){
            CompilerMessageSeverity.EXCEPTION -> Msg.error(this, message)
            CompilerMessageSeverity.ERROR -> Msg.error(this, message)
            CompilerMessageSeverity.STRONG_WARNING -> Msg.warn(this, message)
            CompilerMessageSeverity.WARNING -> Msg.warn(this, message)
            CompilerMessageSeverity.INFO -> Msg.info(this, message)
            CompilerMessageSeverity.LOGGING -> Msg.debug(this, message)
            CompilerMessageSeverity.OUTPUT -> Msg.out(message)
        }
    }
}