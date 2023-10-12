import java.io.BufferedWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.listing.Function;

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
     * @throws Exception
     */
    public void export(Writer writer) throws Exception {
    
        JsonObject jsonObject = new JsonObject();

        JsonArray functionNodes = new JsonArray();
        JsonArray variableNodes = new JsonArray();

        JsonArray f2fEdges = new JsonArray();
        JsonArray f2vEdges = new JsonArray();
        JsonArray v2fEdges = new JsonArray();
        JsonArray v2vEdges = new JsonArray();

        for (Node node: nodes) {
            if (node instanceof FunctionNode) {
                functionNodes.add(node2Func.get(node).getName());
                for (Node to: node.getEdges()) {
                    if (to instanceof FunctionNode) {
                        JsonObject edge = new JsonObject();
                        edge.addProperty("from", node2Func.get(node).getName());
                        edge.addProperty("to", node2Func.get(to).getName());
                        f2fEdges.add(edge);
                    }
                    else if (to instanceof GlobalVarNode) {
                        JsonObject edge = new JsonObject();
                        edge.addProperty("from", node2Func.get(node).getName());
                        edge.addProperty("to", node2Var.get(to).toString());
                        f2vEdges.add(edge);
                    }
                }
            }
                
            else if (node instanceof GlobalVarNode) {
                variableNodes.add(node2Var.get(node).toString());
                for (Node to: node.getEdges()) {
                    if (to instanceof FunctionNode) {
                        JsonObject edge = new JsonObject();
                        edge.addProperty("from", node2Var.get(node).toString());
                        edge.addProperty("to", node2Func.get(to).getName());
                        v2fEdges.add(edge);
                    }
                    else if (to instanceof GlobalVarNode) {
                        JsonObject edge = new JsonObject();
                        edge.addProperty("from", node2Var.get(node).toString());
                        edge.addProperty("to", node2Var.get(to).toString());
                        v2vEdges.add(edge);
                    }
                }
            }
                
        }

        jsonObject.add("functionNodes", functionNodes);
        jsonObject.add("variableNodes", variableNodes);
        jsonObject.add("f2fEdges", f2fEdges);
        jsonObject.add("f2vEdges", f2vEdges);
        jsonObject.add("v2fEdges", v2fEdges);
        jsonObject.add("v2vEdges", v2vEdges);

        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        gson.toJson(jsonObject, writer);
    }
}