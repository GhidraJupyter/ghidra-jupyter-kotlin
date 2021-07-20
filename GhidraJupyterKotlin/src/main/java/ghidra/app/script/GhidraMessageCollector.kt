package ghidra.app.script

import org.jetbrains.kotlin.cli.common.messages.CompilerMessageSeverity
import org.jetbrains.kotlin.cli.common.messages.CompilerMessageSourceLocation
import org.jetbrains.kotlin.cli.common.messages.MessageCollector

object GhidraMessageCollector: MessageCollector {
    override fun clear() {
        return
    }

    override fun hasErrors(): Boolean {
        return false
    }

    override fun report(severity: CompilerMessageSeverity, message: String, location: CompilerMessageSourceLocation?) {
        return
    }
}