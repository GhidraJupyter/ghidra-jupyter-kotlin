package GhidraJupyterKotlin

import docking.ActionContext
import docking.action.DockingAction
import org.jetbrains.kotlinx.jupyter.*
import org.jetbrains.kotlinx.jupyter.messaging.*
import org.jetbrains.kotlinx.jupyter.KernelJupyterParams.Companion.fromFile
import org.zeromq.ZMQ
import java.util.*


class ShutDownKernelAction(var parentPlugin: JupyterKotlinPlugin): DockingAction("Interrupt Kernel", parentPlugin.name) {
    override fun actionPerformed(context: ActionContext?) {
        // This creates a ZMQ socket, to send a shutdown request to the running kernel
        // This is basically a duplicate of InterruptKernelAction and could be merged in the future
        val config: KernelJupyterParams = fromFile(parentPlugin.connectionFile)

        val ctx = ZMQ.context(1)
        val control = ctx.socket(JupyterSockets.CONTROL.zmqClientType)
        control.connect("${config.transport}://*:${config.ports[JupyterSockets.CONTROL.ordinal]}")
        if (config.sigScheme == "hmac-sha256"){
            val hmac = HMAC("HmacSHA256", config.key!!)
            control.sendMessage(
                Message(id = listOf(byteArrayOf(1)),
                    MessageData(
                        header = makeHeader(
                            MessageType.SHUTDOWN_REQUEST,
                            sessionId = UUID.randomUUID().toString()),
                        content = ShutdownRequest(false))),
                hmac)
            parentPlugin.clearKernel()
        }


    }
}