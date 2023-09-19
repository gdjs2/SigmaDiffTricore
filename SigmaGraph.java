import java.io.BufferedWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import ghidra.program.model.listing.Function;

class GlobalVarNode extends Node { }
class FunctionNode extends Node { }

/**
 * Graph node class for SigmaGraph
 */
class Node {

    /**
     * Edges for each node
     */
    private ArrayList<Node> edges;

    /**
     * Constructor
     */
    public Node() {
        edges = new ArrayList<Node>();
    }

    /**
     * Get edges of a node
     * @return the edges in {@code ArrayList}
     * @see ArrayList
     */
    public ArrayList<Node> getEdges() {
        return edges;
    }
}

/**
 * Graph Class
 */
public class SigmaGraph {

    private HashMap<Function, FunctionNode> func2Node;
    private HashMap<FunctionNode, Function> node2Func;
    private HashMap<GlobalVariable, GlobalVarNode> var2Node;
    private HashMap<GlobalVarNode, GlobalVariable> node2Var;

    private ArrayList<Node> nodes;
    private int f2fEdgeCnt, f2vEdgeCnt, v2fEdgeCnt, v2vEdgeCnt;
    private int edgeCnt = 0;
    
    /**
     * Constructor
     */
    public SigmaGraph() {
        nodes = new ArrayList<Node>();

        func2Node = new HashMap<>();
        node2Func = new HashMap<>();
        var2Node = new HashMap<>();
        node2Var = new HashMap<>();

        edgeCnt = f2fEdgeCnt = f2vEdgeCnt = v2fEdgeCnt = v2vEdgeCnt = 0;
    }

    /**
     * Get a {@code FunctionNode} object according to the function {@code f}
     * @param f The function
     * @return The requested {@code FunctionNode} object
     * @see FunctionNode
     * @see Function
     */
    public FunctionNode getFunctionNode(Function f) {

        if (func2Node.containsKey(f)) return func2Node.get(f);

        FunctionNode newNode = new FunctionNode();
        func2Node.put(f, newNode);
        node2Func.put(newNode, f);
        nodes.add(newNode);
        return newNode;
    }

    /**
     * Get a {@code GlobalVarNode} object according to the global variable {@code var}
     * @param var The global variable
     * @return The requested {@code GlobalVarNode} object
     * @see GlobalVarNode
     * @see GlobalVariable
     */
    public GlobalVarNode getGlobalVarNode(GlobalVariable var) {
        
        if (var2Node.containsKey(var)) return var2Node.get(var);

        GlobalVarNode newNode = new GlobalVarNode();
        var2Node.put(var, newNode);
        node2Var.put(newNode, var);
        nodes.add(newNode);
        return newNode;
    }

    public int getNodeNum() {
        return nodes.size();
    }

    public int getFunctionNodeNum() {
        return func2Node.size();
    }

    public int getVariableNodeNum() {
        return var2Node.size();
    }

    public int getEdgeNum() {
        return edgeCnt;
    }

    public int getF2FEdgeNum() {
        return f2fEdgeCnt;
    }

    public int getF2VEdgeNum() {
        return f2vEdgeCnt;
    }

    public int getV2FEdgeNum() {
        return v2fEdgeCnt;
    }

    public int getV2VEdgeNum() {
        return v2vEdgeCnt;
    }

    /**
     * Inner method for creating a new edge
     * @param from Source {@code Node}
     * @param to Destination {@code Node}
     * @return {@code true} if this edge is added successfully
     */
    private boolean newEdge(Node from, Node to) {
        if (!from.getEdges().contains(to)) {
            from.getEdges().add(to);
            ++edgeCnt;
            return true;
        }
        return false;
    }

    /**
     * Wrapper method for creating a new edge from a function to function
     * @param from Source {@code Function}
     * @param to Destination {@code Function}
     * @return {@code true} if this edge is added successfully
     * @see Function
     */
    public boolean newF2FEdge(Function from, Function to) {
        boolean ret = newEdge(getFunctionNode(from), getFunctionNode(to));
        f2fEdgeCnt += ret ? 1 : 0;
        return ret;
    }

    /**
     * Wrapper method for creating a new edge from a function to global variable
     * @param from Source {@code Function}
     * @param to Destination {@code GlobalVariable}
     * @return {@code true} if this edge is added successfully
     * @see Function
     * @see GlobalVariable
     */
    public boolean newF2VEdge(Function from, GlobalVariable to)  {
        boolean ret = newEdge(getFunctionNode(from), getGlobalVarNode(to));
        f2vEdgeCnt += ret ? 1 : 0;
        return ret;
    }

    /**
     * Wrapper method for creating a new edge from a global variable to function
     * @param from Source {@code GlobalVariable}
     * @param to Destination {@code Function}
     * @return {@code true} if this edge is added successfully
     * @see Function
     * @see GlobalVariable
     */
    public boolean newV2FEdge(GlobalVariable from, Function to) {
        boolean ret = newEdge(getGlobalVarNode(from), getFunctionNode(to));
        v2fEdgeCnt += ret ? 1 : 0;;
        return ret;
    }

    /**
     * Wrapper method for creating a new edge from a global variable to global variable
     * @param from Source {@code GlobalVariable}
     * @param to Destination {@code GlobalVariable}
     * @return {@code true} if this edge is added successfully
     * @see GlobalVariable
     */
    public boolean newV2VEdge(GlobalVariable from, GlobalVariable to) {
        boolean ret = newEdge(getGlobalVarNode(from), getGlobalVarNode(to));
        v2vEdgeCnt += ret ? 1 : 0;
        return ret;
    }

    /**
     * Inner method for DFS (Depth-First-Search) the graph
     * @param cur current {@code node}
     * @param vis {@code Set} for visited {@code Node}
     * @param writer {@code BufferedWriter} for writing logs
     * @throws Exception
     */
    private void _dfs(Node cur, Set<Node> vis, BufferedWriter writer) throws Exception {
        vis.add(cur);
        if (writer != null) writer.write(String.format("%s->", ((Function)node2Func.get(cur)).getName()));
        for (Node to: cur.getEdges()) {
            if (!vis.contains(to)) _dfs(to, vis, writer);
        }
    }

    /**
     * Exported method for DFS (Depth-First-Search) the graph
     * @param writer {@code BufferedWriter} for writing logs
     * @throws Exception
     */
    public void dfsGraph(BufferedWriter writer) throws Exception {
        HashSet<Node> vis = new HashSet<>();
        for (Node node: nodes) {
            if (vis.contains(node)) continue;
            _dfs(node, vis, writer);
            writer.newLine();
        }
    }

    /**
     * Export the graph to a writer
     * @param writer {@code Writer} for exporting the graph
     * @param expFlg {@true} if want to export some explaination
     * @throws Exception
     */
    public void export(Writer writer, boolean expFlg) throws Exception {

        if (expFlg) writer.write(String.format("Function Node Count: "));
        writer.write(String.format("%d\n", getFunctionNodeNum()));

        if (expFlg) writer.write(String.format("Variable Node Count: "));
        writer.write(String.format("%d\n", getVariableNodeNum()));

        if (expFlg) writer.write(String.format("Function2Function Edge Count: "));
        writer.write(String.format("%d\n", getF2FEdgeNum()));
        for (Node from: nodes)
            if (from instanceof FunctionNode)
                for (Node to: from.getEdges())
                    if (to instanceof FunctionNode)
                        writer.write(String.format("%s %s\n", node2Func.get(from), node2Func.get(to)));
        writer.write("\n");

        if (expFlg) writer.write(String.format("Function2Variable Edge Count: "));
        writer.write(String.format("%d\n", getF2VEdgeNum()));
        for (Node from: nodes)
            if (from instanceof FunctionNode)
                for (Node to: from.getEdges())
                    if (to instanceof GlobalVarNode)
                        writer.write(String.format("%s %s\n", node2Func.get(from), node2Var.get(to)));
        writer.write("\n");

        if (expFlg) writer.write(String.format("Variable2Function Edge Count: "));
        writer.write(String.format("%d\n", getV2FEdgeNum()));
        for (Node from: nodes)
            if (from instanceof GlobalVarNode)
                for (Node to: from.getEdges())
                    if (to instanceof FunctionNode)
                        writer.write(String.format("%s %s\n", node2Var.get(from), node2Func.get(to)));
        writer.write("\n");

        if (expFlg) writer.write(String.format("Variable2Variable Edge Count: "));
        writer.write(String.format("%d\n", getV2VEdgeNum()));
        for (Node from: nodes)
            if (from instanceof GlobalVarNode)
                for (Node to: from.getEdges())
                    if (to instanceof GlobalVarNode)
                        writer.write(String.format("%s %s\n", node2Var.get(from), node2Var.get(to)));
        writer.write("\n");
    }
}