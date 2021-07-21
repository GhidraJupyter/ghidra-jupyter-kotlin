package GhidraJupyterKotlin.extensions.data

import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Data



// For a Data object that supports component (like arrays or structs) you can use
// `data[i]` instead of `data.getComponent(i)`
operator fun Data.get(i: Int): Data? {
    return this.getComponent(i)
}

// For a Data object that represents a struct you can use
// `data[fieldName]`

operator fun Data.get(name: String): Data? {
    if (this.dataType is Structure){
        val s = (this.dataType as Structure)
        val idx = s.components.firstOrNull { it.fieldName == name }?.ordinal
        return idx?.let(this::getComponent)
    }
    return null
}