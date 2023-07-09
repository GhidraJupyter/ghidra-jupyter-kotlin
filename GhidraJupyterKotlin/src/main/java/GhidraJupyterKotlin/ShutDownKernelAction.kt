package GhidraJupyterKotlin

import docking.ActionContext
import docking.action.DockingAction
import org.jetbrains.kotlinx.jupyter.api.libraries.JupyterSocketType
import org.jetbrains.kotlinx.jupyter.messaging.*
import org.jetbrains.kotlinx.jupyter.protocol.HMAC
import org.jetbrains.kotlinx.jupyter.protocol.JupyterSocketInfo
import org.jetbrains.kotlinx.jupyter.sendMessage
import org.jetbrains.kotlinx.jupyter.startup.KernelJupyterParams
import org.zeromq.ZMQ
import java.util.*


class ShutDownKernelAction(var parentPlugin: JupyterKotlinPlugin): DockingAction("Interrupt Kernel", parentPlugin.name) {
    override fun actionPerformed(context: ActionContext?) {
        // This creates a ZMQ socket, to send a shutdown request to the running kernel
        // This is basically a duplicate of InterruptKernelAction and could be merged in the future

        // It's unreliable/broken after updating to the latest version of the Kotlin Kernel,
        // so it's currently not exposed as an action anymore
        val config: KernelJupyterParams = KernelJupyterParams.fromFile(parentPlugin.connectionFile)

        val ctx = ZMQ.context(1)
        val control = ctx.socket(JupyterSocketInfo.CONTROL.zmqClientType)
        control.connect("${config.transport}://*:${config.ports[JupyterSocketType.CONTROL]}")
        if (config.signatureScheme == "hmac-sha256"){
            val hmac = HMAC("HmacSHA256", config.key!!)
            control.sendMessage(
                Message(id = listOf(byteArrayOf(1)),
                    MessageData(
                        header = makeHeader(
                            MessageType.SHUTDOWN_REQUEST,
                            sessionId = UUID.randomUUID().toString()),
                        content = ShutdownRequest(false))),
                hmac)
//            parentPlugin.clearKernel()
        }


    }
}