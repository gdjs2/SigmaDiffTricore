import java.io.BufferedWriter;
import java.io.PrintWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import ghidra.program.model.listing.Function;

class GlobalVarNode extends Node { }
class FunctionNode extends Node { }

class Node {
    private ArrayList<Node> edges;

    Node() {
        edges = new ArrayList<Node>();
    }

    public ArrayList<Node> getEdges() {
        return edges;
    }
}

public class SigmaGraph {

    private HashMap<Function, FunctionNode> func2Node;
    private HashMap<FunctionNode, Function> node2Func;
    private HashMap<GlobalVariable, GlobalVarNode> var2Node;
    private HashMap<GlobalVarNode, GlobalVariable> node2Var;

    private ArrayList<Node> nodes;
    private int f2fEdgeCnt, f2vEdgeCnt, v2fEdgeCnt;
    private int v2vEdgeCnt;
    private int edgeCnt = 0;
    
    public SigmaGraph() {
        nodes = new ArrayList<Node>();

        func2Node = new HashMap<>();
        node2Func = new HashMap<>();
        var2Node = new HashMap<>();
        node2Var = new HashMap<>();

        edgeCnt = f2fEdgeCnt = f2vEdgeCnt = v2fEdgeCnt = v2vEdgeCnt = 0;
    }

    public FunctionNode getFunctionNode(Function f) {

        if (func2Node.containsKey(f)) return func2Node.get(f);

        FunctionNode newNode = new FunctionNode();
        func2Node.put(f, newNode);
        node2Func.put(newNode, f);
        nodes.add(newNode);
        return newNode;
    }

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

    private boolean newEdge(Node from, Node to) {
        if (!from.getEdges().contains(to)) {
            from.getEdges().add(to);
            ++edgeCnt;
            return true;
        }
        return false;
    }

    public boolean newF2FEdge(Function from, Function to) {
        ++f2fEdgeCnt;
        return newEdge(getFunctionNode(from), getFunctionNode(to));
    }

    public boolean newF2VEdge(Function from, GlobalVariable to)  {
        ++f2vEdgeCnt;
        return newEdge(getFunctionNode(from), getGlobalVarNode(to));
    }

    public boolean newV2FEdge(GlobalVariable from, Function to) {
        ++v2fEdgeCnt;
        return newEdge(getGlobalVarNode(from), getFunctionNode(to));
    }

    public boolean newV2VEdge(GlobalVariable from, GlobalVariable to) {
        ++v2vEdgeCnt;
        return newEdge(getGlobalVarNode(from), getGlobalVarNode(to));
    }

    private void _dfs(Node cur, Set<Node> vis, BufferedWriter writer) throws Exception {
        vis.add(cur);
        if (writer != null) writer.write(String.format("%s->", ((Function)node2Func.get(cur)).getName()));
        for (Node to: cur.getEdges()) {
            if (!vis.contains(to)) _dfs(to, vis, writer);
        }
    }

    public void dfsGraph(BufferedWriter writer) throws Exception {
        HashSet<Node> vis = new HashSet<>();
        for (Node node: nodes) {
            if (vis.contains(node)) continue;
            _dfs(node, vis, writer);
            writer.newLine();
        }
    }

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
                        writer.write(String.format("%s %s\n", from, to));

        if (expFlg) writer.write(String.format("Function2Variable Edge Count: "));
        writer.write(String.format("%d\n", getF2VEdgeNum()));
        for (Node from: nodes)
            if (from instanceof FunctionNode)
                for (Node to: from.getEdges())
                    if (to instanceof GlobalVarNode)
                        writer.write(String.format("%s %s\n", from, to));

        if (expFlg) writer.write(String.format("Variable2Function Edge Count: "));
        writer.write(String.format("%d\n", getV2FEdgeNum()));
        for (Node from: nodes)
            if (from instanceof GlobalVarNode)
                for (Node to: from.getEdges())
                    if (to instanceof FunctionNode)
                        writer.write(String.format("%s %s\n", from, to));

        if (expFlg) writer.write(String.format("Variable2Variable Edge Count: "));
        writer.write(String.format("%d\n", getV2VEdgeNum()));
        for (Node from: nodes)
            if (from instanceof GlobalVarNode)
                for (Node to: from.getEdges())
                    if (to instanceof GlobalVarNode)
                        writer.write(String.format("%s %s\n", from, to));
    }
}