import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class DisassembleAll extends GhidraScript {
    @Override
    public void run() throws Exception {
        Memory memory = currentProgram.getMemory();
        for (MemoryBlock memBlk: memory.getBlocks()) {
            Address startAddr = memBlk.getStart();
            Address endAddr = memBlk.getEnd();

            AddressSet unprocessedAddr = new AddressSet(currentProgram, startAddr, endAddr);
            while (!unprocessedAddr.isEmpty()) {
                Address nxt = unprocessedAddr.getMinAddress();

                if (disassemble(nxt)) {
                    Instruction inst = getInstructionAt(nxt);
                    if (inst != null)
                        unprocessedAddr.deleteRange(inst.getMinAddress(), inst.getMaxAddress());
                    else 
                        unprocessedAddr.delete(nxt, nxt);
                }
            }
        }
    }
}
