import java.io.BufferedWriter;
import java.io.FileWriter;
import java.util.Arrays;
import java.util.TreeSet;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.scalar.Scalar;

public class SigmadiffTricore extends GhidraScript {

    final int imageBase = 0x80000000;
    private BufferedWriter writer;
    private SigmaGraph graph;
    private TreeSet<GlobalVariable> varSet;

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

    private void setImageBase() throws Exception {
        Address addr = currentProgram.getAddressFactory().getAddress(String.format("%x", imageBase));
        currentProgram.setImageBase(addr, true);
        return ;
    }

    private int getStoreOffset(Instruction inst) {
        if (inst.getOpObjects(0).length == 1) return 0;
        return (int)((Scalar)inst.getOpObjects(0)[1]).getValue();
    }

    private int getLoadOffset(Instruction inst) {
        if (inst.getOpObjects(1).length == 1) return 0;
        return (int)((Scalar)inst.getOpObjects(1)[1]).getValue();
    }

    private GlobalVariable getGlobalVariable(int offset) {
        GlobalVariable var = new GlobalVariable(offset);
        if (varSet.contains(var)) return var;
        varSet.add(var);
        return var;
    }

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

    private void dfsGraph() throws Exception {

        println("DFS graph...");

        graph.dfsGraph(writer);

        println("Done.");
    }

    private void createFunctionAndVariableEdges() throws Exception {

        // LinkedList<Node> queue = new LinkedList<>();
        // queue.push(graph.getFunctionNode(currentProgram.get));
        // test
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
                        graph.newF2VEdge(f, getGlobalVariable(getStoreOffset(inst)));
                        break;

                    case PcodeOp.LOAD:
                        graph.newV2FEdge(getGlobalVariable(getLoadOffset(inst)), f);
                        break;
                
                    default:
                        break;
                }

                // if (opcode == PcodeOp.STORE) {

                //     boolean a0Flg = containsA0(inst);

                //     if (a0Flg) {

                //         writer.write(inst.toString());
                //         writer.newLine();

                //         int opNum = inst.getNumOperands();
                //         for (int i = 0; i < opNum; ++i) {
                //             Object[] ops = inst.getOpObjects(i);
                //             writer.write(Arrays.toString(ops));
                //         }

                //         writer.newLine();
                //         writer.newLine();

                //     }

                // } else if (opcode == PcodeOp.LOAD) {

                //     boolean a0Flg = containsA0(inst);

                //     if (a0Flg) {

                //         writer.write(inst.toString());
                //         writer.newLine();

                //         int opNum = inst.getNumOperands();
                //         for (int i = 0; i < opNum; ++i) {
                //             Object[] ops = inst.getOpObjects(i);
                //             writer.write(Arrays.toString(ops));
                //         }

                //         writer.newLine();
                //         writer.newLine();

                //     }

                // } else {
                //     boolean a0Flg = containsA0(inst);

                //     if (a0Flg) {
                //         writer.write(inst.toString());
                //         writer.newLine();

                //         int opNum = inst.getNumOperands();
                //         for (int i = 0; i < opNum; ++i) {
                //             Object[] ops = inst.getOpObjects(i);
                //             writer.write(Arrays.toString(ops));
                //         }

                //         writer.newLine();
                //         writer.newLine();
                //     }
                // }
            }
        }

    }

    @Override
    protected void run() throws Exception {

        writer = new BufferedWriter(new FileWriter("/Users/gdjs2/Desktop/sigmadiff/script/SigmaDiffTricore/graph_image2_exp.txt"));
        graph = new SigmaGraph();
        varSet = new TreeSet<>();

        setImageBase();
        createInterProceduralCallGraph();
        // dfsGraph();
        createFunctionAndVariableEdges();

        graph.export(writer, true);
        writer.close();

    }
}
