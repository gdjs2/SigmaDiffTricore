import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.TreeSet;

public class MachineStatePartial implements Serializable {
	String name;
	HashMap<Node, TreeSet<String>> sELeaf;
	HashMap<Node, TreeSet<String>> calleeSELeaf;
	HashSet<String> callingFunction;
	ArrayList<Struct> dataStructs;
	TreeSet<String> returns;
	HashSet<Node> loads;
	HashSet<Node> calleeLoads;
	int cuNode;

	public MachineStatePartial() {

	}
}