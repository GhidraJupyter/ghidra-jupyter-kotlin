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


class InterruptKernelAction(var parentPlugin: JupyterKotlinPlugin): DockingAction("Interrupt Kernel", parentPlugin.name) {
    override fun actionPerformed(context: ActionContext?) {
        // This creates a ZMQ socket, to send an interrupt request to the running kernel
        // This is needed because Jupyter QT Console doesn't seem to provide this feature and just prints
        // "Cannot interrupt a kernel I did not start"
        // when using the "Interrupt Kernel" menu entry
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
                                            MessageType.INTERRUPT_REQUEST,
                                            sessionId = UUID.randomUUID().toString()),
                                    content = InterruptRequest())),
                    hmac)
        }


    }
}