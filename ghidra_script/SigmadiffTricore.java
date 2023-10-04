import java.io.BufferedWriter;
import java.io.FileWriter;
import java.util.Iterator;
import java.util.TreeMap;
import java.util.TreeSet;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.scalar.Scalar;

public class SigmadiffTricore extends GhidraScript {

    final int imageBase = 0x80000000;
    final int smallDataSectionBase = 0x0;

    // This writer & debugger is just convenient for debugging
    private BufferedWriter writer;
    private BufferedWriter debugger;

    /**
     * Created graph
     * Vertices: Functions & Global variables
     * Edges: 
     *      Function & Function: Call relationship
     *      Function to Variable: the function writes to the variable
     *      Variable to Function: 
     *          The function reads from the variable
     *          A variable stores the location of another function entry (TODO)
     *      Variable to Variable:
     *          A variable connect to next adjacent variable in memory
     *          A variable stores the location of another variable (TODO)
     */
    private SigmaGraph graph;

    /**
     * Ordered set for all global variables
     */
    private TreeSet<GlobalVariable> varSet;

    /**
     * Judge whether a instruction has a0 as an operator
     * @param inst The instruction
     * @return {@code true} if inst contains a0 as an operator
     */
    private boolean containsA0(Instruction inst) {
        int opNum = inst.getNumOperands();

        for (int i = 0; i < opNum; ++i) {
            Object[] operands = inst.getOpObjects(i);
            for (Object op: operands)
                if (op instanceof Register && 
                    ((Register)op).getName().equals("a0"))
                    return true;
        }
        
        return false;
    }

    /**
     * Set image base according to the {@code imageBase} variable
     * 
     * @throws Exception
     * @see SigmadiffTricore#imageBase
     */
    private void setImageBase() throws Exception {
        Address addr = currentProgram.getAddressFactory().getAddress(String.format("%x", imageBase));
        currentProgram.setImageBase(addr, true);
        return ;
    }

    /**
     * Get the offset of a store instruction
     * @param inst The instruction
     * @return The offset
     * @see Instruction
     */
    private int getStoreOffset(Instruction inst) {
        if (inst.getOpObjects(0).length == 1) return 0;
        return (int)((Scalar)inst.getOpObjects(0)[1]).getValue();
    }

    /**
     * Get the offset of a load instruction
     * @param inst The instruction
     * @return The offset
     * @see Instruction
     */
    private int getLoadOffset(Instruction inst) {
        if (inst.getOpObjects(1).length == 1) return 0;
        return (int)((Scalar)inst.getOpObjects(1)[1]).getValue();
    }

    /**
     * Get a {@code GlobalVariable} according to an offset
     * @param offset The offset
     * @return The {@code GlobalVariable} object requested
     * @see GlobalVariable
     */
    private GlobalVariable getGlobalVariable(int offset) {
        GlobalVariable var = new GlobalVariable(offset);
        if (varSet.contains(var)) return var;
        varSet.add(var);
        return var;
    }

    /**
     * Read data from a {@code GlobalVariable}. This function is NOT TESTED!!!
     * @param var
     * @return
     * @throws MemoryAccessException
     */
    private int readData(GlobalVariable var) throws MemoryAccessException {
        var addr = currentProgram.getAddressFactory().getAddress(String.format("%x", imageBase + var.getOffset()));
        var data = getDataAt(addr);
        return data.getInt(0);
    }

    @SuppressWarnings("unused")
    private int checkSmallDataSectionBase() throws Exception {
        FunctionIterator functionIterator = currentProgram.getFunctionManager().getFunctions(true);
        for (Function f: functionIterator) {
            InstructionIterator instIter = currentProgram.getListing().getInstructions(f.getBody(), true);
            for (Instruction inst: instIter) {
                if (containsA0(inst)) {
                    debugger.write(inst.toString());
                    debugger.newLine();
                }
            }
        }

        return 0x0;
    }

    /**
     * Create the inter-procedural call graph for current program
     * @see SigmadiffTricore#graph
     */
    private void createInterProceduralCallGraph() {

        println("Constructing inter-procedural call graph...");

        FunctionManager functionManager = currentProgram.getFunctionManager();
        for (Function f: functionManager.getFunctions(true)) {
            for (Function calledF: f.getCalledFunctions(monitor)) {
                if (graph.newF2FEdge(f, calledF)) { }
            }
        }

        println("Done.");
        println(String.format("[Summary] nodes: %d, edges: %d\n", graph.getNodeNum(), graph.getEdgeNum()));

    }

    /**
     * Run DFS (Depth-First-Search) on current graph
     * @throws Exception
     * @see SigmadiffTricore#graph
     */
    @SuppressWarnings("unused")
    private void dfsGraph() throws Exception {

        println("DFS graph...");

        graph.dfsGraph(writer);

        println("Done.");
    }

    /**
     * Create edges between functions and its corresponding global variables
     * @throws Exception
     * @see SigmadiffTricore#graph
     */
    private void createFunctionAndVariableEdges() throws Exception {

        FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);
        for (Function f: funcIter) {
            InstructionIterator instIter = currentProgram.getListing().getInstructions(f.getBody(), true);
            while (instIter.hasNext()) {

                Instruction inst = instIter.next();
                int opcode = PcodeOp.UNIMPLEMENTED;

                for (PcodeOp op: inst.getPcode()) {

                    if (op.getOpcode() == PcodeOp.STORE) {
                        opcode = PcodeOp.STORE;
                        break;
                    } else if (op.getOpcode() == PcodeOp.LOAD) {
                        opcode = PcodeOp.LOAD;
                        break;
                    }

                }

                switch (opcode) {
                    case PcodeOp.STORE:
                        if (containsA0(inst))
                            graph.newF2VEdge(f, getGlobalVariable(getStoreOffset(inst)));
                        break;

                    case PcodeOp.LOAD:
                        if (containsA0(inst))
                            graph.newV2FEdge(getGlobalVariable(getLoadOffset(inst)), f);
                        break;
                
                    default:
                        break;
                }
            }
        }

    }

    /**
     * Create edges between global variables according to their order
     * @see SigmadiffTricore#varSet
     */
    public void createVariableOrderEdges() {

        Iterator<GlobalVariable> varIt = varSet.iterator();
        
        if (!varIt.hasNext()) {
            return ;
        }

        GlobalVariable current = varIt.next();
        while (varIt.hasNext()) {
            GlobalVariable next = varIt.next();
            graph.newV2VEdge(current, next);
            current = next;
        }

    }

    /**
     * Create edges between global variables and functions if the variable stores the entry of a function.
     * This function is NOT TESTED!!!
     * @throws MemoryAccessException
     */
    @Deprecated
    public void createVariablePoint2FunctionEdge() throws MemoryAccessException {
        TreeMap<Integer, Function> entry2FunctionMap = new TreeMap<>();
        for (var f: currentProgram.getFunctionManager().getFunctions(true)) {
            entry2FunctionMap.put((int)f.getEntryPoint().getOffset(), f);
        }
        for (var v: varSet) {
            int data = readData(v);
            if (entry2FunctionMap.containsKey(data)) {
                graph.newV2FEdge(v, entry2FunctionMap.get(data));
            }
        }
    }

    /**
     * Create edges between global variables if the variable stores the pointer to another variable.
     * This function is NOT TESTED!!!
     * @throws MemoryAccessException
     */
    @Deprecated
    public void createVariablePoint2VarlaibleEdge() throws MemoryAccessException {
        TreeMap<Integer, GlobalVariable> offset2VariableMap = new TreeMap<>();
        for (var v: varSet) {
            offset2VariableMap.put(v.getOffset(), v);
        }
        for (var v: varSet) {
            int data = readData(v);
            if (offset2VariableMap.containsKey(data)) {
                graph.newV2VEdge(v, offset2VariableMap.get(data));
            }
        }
    }

    @Override
    protected void run() throws Exception {

        String[] args = getScriptArgs();
        if (args.length == 1) {
            printf("Graph Write to File: %s\n", args[0]);
        }

        writer = new BufferedWriter(new FileWriter(args[0]));
        debugger = new BufferedWriter(new FileWriter("./debug.txt"));

        graph = new SigmaGraph();
        varSet = new TreeSet<>();

        setImageBase();
        createInterProceduralCallGraph();
        createFunctionAndVariableEdges();
        createVariableOrderEdges();

        graph.export(writer, true);
        writer.close();
        debugger.close();

    }
}
