import java.util.ArrayList;

/**
 * Graph node class for SigmaGraph
 */
public class Node {

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