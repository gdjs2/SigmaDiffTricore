import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.TreeSet;

public class PhiNode extends Node {
	HashSet<Node> valueSet;

	public PhiNode(int byteLength) {
		this.setOperation("Phi");
		this.setSize(byteLength);
		this.valueSet = new HashSet<Node>();
		this.leafSet = new TreeSet<String>();

	}

	public PhiNode(String oper, int byteLength) {
		this.setOperation(oper);
		this.setSize(byteLength);
		this.valueSet = new HashSet<Node>();
		this.leafSet = new TreeSet<String>();
	}

	public HashSet<Node> getValueSet() {
		return valueSet;
	}

	public void setValueSet(HashSet<Node> valueSet) {
		this.valueSet = valueSet;
	}

	public String getOperation() {
		this.setOperation(this.toString());
		return operation;
	}

	public TreeSet<String> getLeafSet() {
		return this.leafSet;
	}

	public void merge(Node v) {
		if (!(v instanceof PhiNode)) {
			if (!v.toString().equals("VZERO"))
				this.valueSet.add(v);
		} else {
			for (Node n : ((PhiNode) v).getValueSet()) {
				if (n.toString().equals("VZERO"))
					continue;
				if (n instanceof PhiNode) {
					this.merge(n);
				} else {
					this.valueSet.add(n);
				}
			}
		}
		this.collectLeaf(v);
	}

	public void collectLeaf(Node n) {
		if (n == null)
			return;
		if (n.isConstant())
			return;
		else if (n.isLeaf() && n.getOperation().equals("RFC"))
			this.leafSet.addAll(n.leafSet);
		else if (n.isLeaf())
			this.leafSet.add(n.toString());
		else if (n instanceof PhiNode) {
			this.leafSet.addAll(n.getLeafSet());
		} else {
			n.recollectLeaf();
			this.leafSet.addAll(n.getLeafSet());
		}
	}

	/**
	 * merge a node with the phi node, keep the simplest value
	 * 
	 * @param v
	 */
	public void mergeLong(Node v) {
		merge(v);
		if (this.valueSet.size() > 1) {
			MyComparator comparator = new MyComparator("");
			List<Node> list = new ArrayList<Node>(this.valueSet);
			java.util.Collections.sort(list, comparator);
			this.valueSet = new HashSet<Node>();
			this.valueSet.add(list.get(list.size() - 1));
		}
	}

	/**
	 * merge a node with the phi node, keep the simplest value
	 * 
	 * @param v
	 */
	public void merge1(Node v) {
		merge(v);
		if (this.valueSet.size() > 1) {
			MyComparator comparator = new MyComparator("");
			List<Node> list = new ArrayList<Node>(this.valueSet);
			java.util.Collections.sort(list, comparator);
			this.valueSet = new HashSet<Node>();
			this.valueSet.add(list.get(0));
		}
	}

	/**
	 * merge a node with the phi node, keep the two simplest values
	 * 
	 * @param v
	 */
	public void merge2(Node v) {
		merge(v);
		if (this.valueSet.size() > 2) {
			MyComparator comparator = new MyComparator("");
			List<Node> list = new ArrayList<Node>(this.valueSet);
			java.util.Collections.sort(list, comparator);
			this.valueSet = new HashSet<Node>();
			this.valueSet.add(list.get(0));
			this.valueSet.add(list.get(1));
		}

	}

	public String toStringLeaf() {
		String s;
		s = "f(";
		int i = 0;
		int size = this.leafSet.size();
		for (String n : this.leafSet) {
			if (n.equals("RFC") || n.contains("A_Stack")) {
				size -= 1;
			}
		}
		for (String n : this.leafSet) {
			if (n.equals("RFC") || n.contains("A_Stack")) {
				continue;
			}
			s += n;
			if (i < size - 1)
				s += " , ";
			i++;
		}
		s += ")";
		return s;
	}

	public String toString() {
		return this.toStringLeaf();
	}

	public Node deepCopy() {
		PhiNode copy = new PhiNode(this.getOperation(), this.getSize());
		copy.valueSet = new HashSet<Node>();
		copy.leafSet = new TreeSet<String>();
//		for (Node v : this.valueSet) {
//			Node c = v.deepCopy();
//			copy.valueSet.add(c);
//		}
		// we don't need the value set when replace args for phi node, so don't copy it
		copy.valueSet.addAll(this.valueSet);
		copy.leafSet.addAll(this.leafSet);
		return copy;
	}

	public Node shallowCopy() {
		PhiNode copy = new PhiNode(this.getOperation(), this.getSize());
		copy.valueSet = new HashSet<Node>();
		copy.leafSet = new TreeSet<String>();
		copy.valueSet.addAll(this.valueSet);
		copy.leafSet.addAll(this.leafSet);
//		System.out.println("shallow copy: " + this.toString());
		return copy;
	}

	public int createStruct(ArrayList<Struct> args, int parentByteLength, ArrayList<Struct> currentStruct, int level)
			throws Exception {
		for (Node n : this.valueSet) {
			if (n.isConstant())
				continue;
			int offset = n.createStruct(args, parentByteLength, currentStruct, level + 1);
			currentStruct.get(0).isArray(true);
			return offset;
		}
		throw new Exception("failed to parse address");
	}

	public int mergeStruct(ArrayList<Struct> args, int parentByteLength, ArrayList<Struct> currentStruct,
			Struct mergedStruct, int level) throws Exception {
		for (Node n : this.valueSet) {
			int offset = n.mergeStruct(args, parentByteLength, currentStruct, mergedStruct, level);
			currentStruct.get(0).isArray(true);
			return offset;
		}
		throw new Exception("failed to parse address");
	}

	public boolean replaceArgs(String side, HashMap<String, Node> argReplaceMap) {
		TreeSet<String> leafsets = (TreeSet<String>) this.getLeafSet().clone();
		for (String s : leafsets) {
			if (argReplaceMap.containsKey(s)) {
				this.leafSet.remove(s);
				this.collectLeaf(argReplaceMap.get(s));
				continue;
			}
			if (!s.contains("ARG"))
				continue;
			return false;
		}
		this.reset = true;
		return true;
	}

	public void setSymbol() {
		for (Node n : this.valueSet)
			n.setSymbol();
	}

	public boolean isLeaf() {
		return false;
	}
}