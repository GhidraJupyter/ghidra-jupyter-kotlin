@file:Suppress("unused")
//They are imported in some script or the kernel itself by the user
// use them by adding the following import to script
// import GhidraJupyterKotlin.extensions.address.*
package GhidraJupyterKotlin.extensions.address

import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressRange
import ghidra.program.model.address.AddressRangeImpl



/**
 * `currentAddress+10` returns a new Address
 */
operator fun Address.plus(rhs: Long): Address {
    return this.addNoWrap(rhs)
}
operator fun Address.plus(rhs: Int): Address {
    return this.addNoWrap(rhs.toLong())
}

/**
 * `currentAddress-10` returns a new Address
 */
operator fun Address.minus(rhs: Long): Address {
    return this.subtractNoWrap(rhs)
}
operator fun Address.minus(rhs: Int): Address {
    return this.subtractNoWrap(rhs.toLong())
}

/**
 * `currentAddress..otherAddress` gives an AddressRange with currentAddress as start, and otherAddress as end
 */
operator fun Address.rangeTo(rhs: Address): AddressRange {
    return AddressRangeImpl(this, rhs)
}
