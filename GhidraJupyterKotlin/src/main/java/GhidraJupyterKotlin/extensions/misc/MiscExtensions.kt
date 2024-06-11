package GhidraJupyterKotlin.extensions.misc

import ghidra.framework.model.DomainObject
import ghidra.program.model.listing.FunctionIterator
import ghidra.program.model.listing.FunctionManager
import ghidra.program.model.listing.Program

val FunctionManager.functions: FunctionIterator
    get() = this.getFunctions(true)


val Program.functions: FunctionIterator
    get() = this.functionManager.getFunctions(true)


fun DomainObject.runTransaction(description: String, transaction: () -> Unit) {
    val transactionID: Int = this.startTransaction(description)
    try {
        transaction()
        this.endTransaction(transactionID, true)
    }
    catch (e: Throwable) {
        this.endTransaction(transactionID, false)
        throw e
    }
}

fun DomainObject.runTransaction(transaction: () -> Unit){
    val transactionID: Int = this.startTransaction("Kotlin Lambda Transaction")
    try {
        transaction()
        this.endTransaction(transactionID, true)
    }
    catch (e: Throwable) {
        this.endTransaction(transactionID, false)
        throw e
    }
}