import java.io.Serializable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.TreeSet;

public class Node implements Serializable {
	private Node left;
	private Node right;
	protected String operation;
	protected int byteLength;
	private String accessMode;
	protected boolean isStructField = false; // if this node is a field of a data structure, use this symbol to
												// represent it
	protected boolean reset = false;
	protected boolean longString = false;
	protected TreeSet<String> leafSet = new TreeSet<String>(); // TreeSet is sorted

	public Node() {

	}

	public Node(Node left, Node right, String operator, int byteLength) {
		this.left = left;
		this.right = right;
		this.operation = operator;
		this.byteLength = byteLength;
	}

	public int getSize() {
		return byteLength;
	}

	public void setSize(int byteLength) {
		this.byteLength = byteLength;
	}

	public String getOperation() {
		return operation;
	}

	public void setOperation(String oper) {
		this.operation = oper;
	}

	public void setAccessMode(String mode) {
		this.accessMode = mode;
	}

	public String getAccessMode() {
		return accessMode;
	}

	public Node getLeft() {
		return left;
	}

	public Node getRight() {
		return right;
	}

	public void setRight(Node value) {
		this.right = value;
	}

	public void setLeft(Node value) {
		this.left = value;
	}

	public void setSymbol() {
		this.isStructField = true;
	}

	public void recollectLeaf() {
		if (this == null)
			return;
		if (this.isConstant())
			return;
		if (this.reset)
			return;
		if (this.isLeaf() && this.getOperation().equals("RFC"))
			return;
		this.getLeafSet().clear();
		if (this.isLeaf())
			this.leafSet.add(this.toString());
		else if (this instanceof PhiNode) {
			// for phi node that hasn't been reset leaves
			HashSet<String> ret = new HashSet<String>();
			for (Node v : ((PhiNode) this).getValueSet()) {
				v.recollectLeaf();
				ret.addAll(v.getLeafSet());
			}
			this.leafSet.addAll(ret);
		} else {
			HashSet<String> ret = new HashSet<String>();
			this.getLeft().recollectLeaf();
			ret.addAll(this.getLeft().getLeafSet());
			if (this.getRight() != null) {
				this.getRight().recollectLeaf();
				ret.addAll(this.getRight().getLeafSet());
			}
//			if (this.isStructField && !this.toString().contains("f("))
//				this.leafSet.add(this.toString());
//			else
			this.leafSet.addAll(ret);
		}
		this.reset = true;
	}

	public TreeSet<String> getLeafSet() {
		return this.leafSet;
	}

	public String toString() {
		if (this.isLeaf() && this.operation.equals("RFC"))
			return this.toStringLeaf();
		if (this.isLeaf())
			return this.operation;

		String left = this.left.toString();
		// we don't want the complete expression if the expression is too long
		if (left.length() > 100 || this.left.longString) {
			this.longString = true;
			return this.toStringLeaf();
		} else if (this.operation.equals("*()"))
			return "[" + left + "]";
		else if (this.operation.equals("RESIZE"))
			return "(uint" + String.valueOf(this.byteLength * 8) + "_t)(" + left + ")";
		else if (this.operation.equals("~"))
			return "~(" + left + ")";
		else {
			String newStr = "(" + left + " " + this.operation + " " + this.right.toString() + ")";
			if (newStr.length() > 100 || this.left.longString || this.right.longString) {
				this.longString = true;
				return this.toStringLeaf();
			}
			return newStr;
		}
	}

	public String toStringLeaf() {
		this.recollectLeaf();
		String s;
		s = "f(";
		int i = 0;
		int size = this.leafSet.size();
		for (String n : this.leafSet) {
			if (!n.equals("RFC") && !n.contains("A_Stack"))
				continue;
			--size;
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

	public boolean isLeaf() {
		return (this.left == null) && (this.right == null);
	}

	public boolean isConstant() {
		if (this.isLeaf() && isPureDigital(this.operation)) {
			return true;
		}
		return false;
	}

	/**
	 * Test if the symbol is zero or not
	 *
	 * @param symbol
	 * @return
	 */
	public static boolean isZero(String symbol) {
		if (isPureDigital(symbol)) {
			long n = parseLong(symbol);
			return (n == 0);
		} else if (symbol == "VZERO")
			return true;
		return false;
	}

	/**
	 * Return digital value from symbolic value
	 *
	 * @param symbol
	 * @return
	 */
	public static long parseLong(String symbol) {
		long ret;
		if (symbol == "VZERO") {
			ret = 0;
		} else if (symbol.startsWith("0x")) {
			ret = new BigInteger(symbol.substring(2), 16).longValue();
		} else {
			ret = new BigInteger(symbol, 10).longValue();
		}

		return ret;
	}

	/**
	 * Test if a symbolic value is pure digitvalue
	 *
	 * @param symbol
	 * @return
	 */
	public static boolean isPureDigital(String symbol) {
		boolean yes = false;
		try {
			if (symbol == "VZERO")
				return true;
			if (symbol.startsWith("0x")) {
				new BigInteger(symbol.substring(2), 16);
			} else {
				new BigInteger(symbol, 10);
			}
			yes = true;
		} catch (Exception e) {

		}
		return yes;
	}

	public Node deepCopy() {
		Node left2 = null;
		Node right2 = null;
		if (this.left != null)
			left2 = this.left.deepCopy();
		if (this.right != null)
			right2 = this.right.deepCopy();
		Node n = new Node(left2, right2, this.operation, this.byteLength);
		return n;
	}

	public Node shallowCopy() {
		Node n = new Node(this.left, this.right, this.operation, this.byteLength);
		n.accessMode = this.accessMode;
		n.leafSet.addAll(this.leafSet);
//		System.out.println("shallow copy " + n.toString());
		return n;
	}

	// if there's a constant value, it's always put in right node
	public Node add(Node other) {
		if (this.isConstant() && parseLong(this.operation) == 0)
			return other;
		if (other.isConstant() && parseLong(other.getOperation()) == 0)
			return this;
		if (this.isConstant() && other.isConstant()) {
			Long v1 = parseLong(this.operation);
			Long v2 = parseLong(other.getOperation());
			return new Node(null, null, String.valueOf(v1 + v2), this.byteLength);
		} else if (this.isConstant() && other.getRight() != null && other.getRight().isConstant()
				&& other.getOperation().equals("+") && !other.isLeaf()) {
			Node ret = other.shallowCopy();
			Long v1 = parseLong(this.operation);
			Long v2 = parseLong(other.getRight().getOperation());
			ret.setRight(new Node(null, null, String.valueOf(v1 + v2), other.getSize()));
			return ret;
		} else if (other.isConstant() && this.getRight() != null && this.getRight().isConstant()
				&& this.getOperation().equals("+")) {
			Node ret = this.shallowCopy();
			Long v1 = parseLong(other.getOperation());
			Long v2 = parseLong(this.getRight().getOperation());
			ret.setRight(new Node(null, null, String.valueOf(v1 + v2), this.byteLength));
			return ret;
		} else if (this.isConstant()) {
			return new Node(other, this, "+", this.byteLength);
		} else if (other.isConstant()) {
			return new Node(this, other, "+", this.byteLength);
		} else if (this.toString().equals("f()")) {
			return new Node(other, this, "+", this.byteLength);
		} else if (other.toString().equals("f()")) {
			return new Node(this, other, "+", this.byteLength);
		} else if (this.toString().contains("ARG") || this.toString().compareTo(other.toString()) > 0) {
			// if both of them are not constants, sort according to their complexity,
			// simpler one put on right child
			return new Node(this, other, "+", this.byteLength);
		} else {
			return new Node(other, this, "+", this.byteLength);
		}
	}

	// if there's a constant value, it's always put in right node
	public Node mul(Node other) {
		if (this.isConstant() && parseLong(this.operation) == 1)
			return other;
		if (other.isConstant() && parseLong(other.getOperation()) == 1)
			return this;
		if (this.isConstant() && parseLong(this.operation) == 0)
			return new Node(null, null, "0", this.byteLength);
		if (other.isConstant() && parseLong(other.getOperation()) == 0)
			return new Node(null, null, "0", other.getSize());

		if (this.isConstant() && other.isConstant()) {
			Long v1 = parseLong(this.operation);
			Long v2 = parseLong(other.getOperation());
			return new Node(null, null, String.valueOf(v1 * v2), this.byteLength);
		} else if (this.isConstant() && other.getRight() != null && other.getRight().isConstant()
				&& other.getOperation().equals("*")) {
			Node ret = other.shallowCopy();
			Long v1 = parseLong(this.operation);
			Long v2 = parseLong(other.getRight().getOperation());
			ret.setRight(new Node(null, null, String.valueOf(v1 * v2), other.getSize()));
			return ret;
		} else if (other.isConstant() && this.getRight() != null && this.getRight().isConstant()
				&& this.getOperation().equals("*")) {
			Node ret = this.shallowCopy();
			Long v1 = parseLong(other.getOperation());
			Long v2 = parseLong(this.getRight().getOperation());
			ret.setRight(new Node(null, null, String.valueOf(v1 * v2), this.byteLength));
			return ret;
		} else if (this.isConstant()) {
			return new Node(other, this, "*", this.byteLength);
		} else if (other.isConstant()) {
			return new Node(this, other, "*", this.byteLength);
		} else if (this.toString().compareTo(other.toString()) > 0) {
			// if both of them are not constants, sort according to their complexity,
			// simpler one put on right child
			return new Node(this, other, "*", this.byteLength);
		} else {
			return new Node(other, this, "*", this.byteLength);
		}
	}

	public Node sub(Node other) {
		if (other.isConstant() && parseLong(other.getOperation()) == 0)
			return this;
		if (this.isConstant() && other.isConstant()) {
			Long v1 = parseLong(this.operation);
			Long v2 = parseLong(other.getOperation());
			return new Node(null, null, String.valueOf(v1 - v2), this.byteLength);
		} else if (other.isConstant() && this.getRight() != null && this.getRight().isConstant()
				&& this.getOperation().equals("+")) {
			Node ret = this.shallowCopy();
			Long v1 = parseLong(other.getOperation());
			Long v2 = parseLong(this.getRight().getOperation());
			ret.setRight(new Node(null, null, String.valueOf(v2 - v1), this.byteLength));
			return ret;
		} else if (other.isConstant() && this.getRight() != null && this.getRight().isConstant()
				&& this.getOperation().equals("-")) {
			Node ret = this.shallowCopy();
			Long v1 = parseLong(other.getOperation());
			Long v2 = parseLong(this.getRight().getOperation());
			ret.setRight(new Node(null, null, String.valueOf(-(v2 + v1)), this.byteLength));
			ret.setOperation("+");
			return ret;
		} else if (other.isConstant()) {
			Long v1 = parseLong(other.getOperation());
			other.setOperation(String.valueOf(-v1));
			return new Node(this, other, "+", this.byteLength);
		} else {
			return new Node(this, other, "-", this.byteLength);
		}
	}

	public Node div(Node other) {
		if (other.isConstant() && parseLong(other.getOperation()) == 1)
			return this;
		if (this.isConstant() && other.isConstant()) {
			Long v1 = parseLong(this.operation);
			Long v2 = parseLong(other.getOperation());
			if (v2 == 0)
				return new Node(null, null, "NAT", this.byteLength);
			return new Node(null, null, String.valueOf(v1 / v2), this.byteLength);
		} else if (other.isConstant() && this.getRight() != null && this.getRight().isConstant()
				&& this.getOperation().equals("/")) {
			Node ret = this.shallowCopy();
			Long v1 = parseLong(other.getOperation());
			Long v2 = parseLong(this.getRight().getOperation());
			ret.setRight(new Node(null, null, String.valueOf(v2 * v1), this.byteLength));
			return ret;
		} else {
			return new Node(this, other, "/", this.byteLength);
		}
	}

	/**
	 * bitwise and
	 * 
	 * @param other
	 * @return
	 */
	public Node and(Node other) {
		Node output;
		if (this.toString().equals(other.toString()))
			output = this;
		else if (other.isConstant() && parseLong(other.getOperation()) == -1) {
			output = this;
		} else if (this.isConstant() && parseLong(this.getOperation()) == -1) {
			output = other;
		} else if (this.isConstant() && parseLong(this.getOperation()) == 0) {
			output = this;
		} else if (other.isConstant() && parseLong(other.getOperation()) == 0) {
			output = other;
		} else if (this.isConstant() && other.isConstant()) {
			long inputLong1 = parseLong(this.getOperation());
			long inputLong2 = parseLong(other.getOperation());
			output = new Node(null, null, String.valueOf(inputLong1 & inputLong2), this.getSize());
		} else if (this.toString().compareTo(other.toString()) > 0) {
			// if both of them are not constants, sort according to their complexity,
			// simpler one put on right child
			output = new Node(this, other, "&", this.byteLength);
		} else {
			output = new Node(other, this, "&", this.byteLength);
		}
		return output;
	}

	public Node or(Node other) {
		Node output;
		if (this.isConstant() && parseLong(this.getOperation()) == 0) {
			output = other;
		} else if (other.isConstant() && parseLong(other.getOperation()) == 0) {
			output = this;
		} else if (this.isConstant() && other.isConstant()) {
			long inputLong1 = parseLong(this.getOperation());
			long inputLong2 = parseLong(other.getOperation());
			output = new Node(null, null, String.valueOf(inputLong1 | inputLong2), this.getSize());
		} else if (this.toString().compareTo(other.toString()) > 0) {
			// if both of them are not constants, sort according to their complexity,
			// simpler one put on right child
			output = new Node(this, other, "|", this.byteLength);
		} else {
			output = new Node(other, this, "|", this.byteLength);
		}
		return output;
	}

	public Node piece(Node other) {
		if (other.isConstant()) {
			Node output = this.mul(
					new Node(null, null, String.valueOf((int) Math.pow(2, (8 * other.getSize()))), this.getSize()));
			output = output.add(other);
			return output;
		}
		return new Node(this, other, "#", this.getSize() + other.getSize());
	}

	public Node subpiece(Node other) {
		Node output = this
				.div(new Node(null, null, String.valueOf((int) Math.pow(2, (8 * other.getSize()))), this.getSize()));
		return output;
	}

	public Node xor(Node other) {
		if (this.isConstant() && other.isConstant()) {
			long inputLong1 = parseLong(this.getOperation());
			long inputLong2 = parseLong(other.getOperation());
			return new Node(null, null, String.valueOf(inputLong1 ^ inputLong2), this.getSize());
		} else if (this.toString().equals(other.toString()))
			return new Node(null, null, "0", this.getSize());
		else
			return new Node(this, other, "^", this.getSize());
	}

	public Node ls(Node other) {
		if (this.isConstant() && other.isConstant()) {
			long inputLong1 = parseLong(this.getOperation());
			long inputLong2 = parseLong(other.getOperation());
			return new Node(null, null, String.valueOf(inputLong1 << inputLong2), this.getSize());
		} else if (other.isConstant()) {
			long inputLong2 = parseLong(other.getOperation());
			return this.mul(new Node(null, null, String.valueOf((int) Math.pow(2, inputLong2)), this.getSize()));
		} else
			return new Node(this, other, "<<", this.getSize());
	}

	public Node rs(Node other) {
		if (this.isConstant() && other.isConstant()) {
			long inputLong1 = parseLong(this.getOperation());
			long inputLong2 = parseLong(other.getOperation());
			return new Node(null, null, String.valueOf(inputLong1 >> inputLong2), this.getSize());
		} else if (other.isConstant()) {
			long inputLong2 = parseLong(other.getOperation());
			return this.div(new Node(null, null, String.valueOf((int) Math.pow(2, inputLong2)), this.getSize()));
		} else
			return new Node(this, other, ">>", this.getSize());
	}

	public Node resize(int newLength) {
		this.byteLength = newLength;
		return this;
	}

	public Node neg() {
		if (this.isConstant())
			return new Node(null, null, String.valueOf(~parseLong(this.operation)), this.getSize());
		return new Node(this, null, "~", this.getSize());
	}

	/**
	 * if this node is more complex than the other node, return >=0
	 * 
	 * @param other
	 * @return
	 */
	public int compareTo(Node other) {
		int ret = this.toString().compareTo(other.toString());
		int typeThis;
		int typeOther;
		if (this.isConstant()) {
			typeThis = 1;
		} else if (this.toString().contains("f()") && !this.toString().contains("ARG")) {
			typeThis = 2;
		} else
			typeThis = 3;

		if (other.isConstant()) {
			typeOther = 1;
		} else if (other.toString().contains("f()") && !other.toString().contains("ARG")) {
			typeOther = 2;
		} else
			typeOther = 3;

		if (typeThis == typeOther)
			return ret;
		return typeThis - typeOther;
	}

	public int createStruct(ArrayList<Struct> args, int parentByteLength, ArrayList<Struct> currentStruct, int level)
			throws Exception {
		if (level > 1000) {
			throw new Exception("failed to parse address");
		}
		if (this.isLeaf() && this.getOperation().contains("ARG")) {
			int argIdx = Integer.parseInt(this.getOperation().substring(3)) - 1;
			// currentStruct.remove(0);
			currentStruct.add(args.get(argIdx));
			return 0;
		} else if (this.getOperation().equals("+")) {
			int offset = this.getLeft().createStruct(args, this.byteLength, currentStruct, level + 1);
			if (this.getRight().isConstant()) {
				offset += Integer.parseInt(this.getRight().getOperation());
				return offset;
			}
			// this could be an array
			if (currentStruct.size() > 0 && this.getRight().toString().contains("f(")) {
				currentStruct.get(0).isArray(true);
				return offset;
			}
			throw new Exception("failed to parse address");
		} else if (this.getOperation().equals("*()")) {
			int offset = this.getLeft().createStruct(args, this.byteLength, currentStruct, level + 1);

			if (currentStruct.size() > 0) {
				Struct cur = currentStruct.get(0);
				Struct childStruct;
				if (cur.get(offset) != null) {
					childStruct = cur.get(offset);
				} else {
					cur.extend(offset + parentByteLength);
					childStruct = new Struct(0);
					childStruct.setParentStruct(cur);
					cur.insert(childStruct, parentByteLength, offset);
				}
				if (this.getLeft().getAccessMode() != null)
					childStruct.setAccessMode(this.getLeft().getAccessMode());
				childStruct.addN(this.getLeft());
				currentStruct.remove(0);
				currentStruct.add(childStruct);
				return 0;
			} else
				throw new Exception("failed to parse address");
		} else {
			throw new Exception("failed to parse address");
		}
	}

	public int mergeStruct(ArrayList<Struct> args, int parentByteLength, ArrayList<Struct> currentStruct,
			Struct mergedStruct, int level) throws Exception {
		if (level > 1000) {
			throw new Exception("failed to parse address");
		}
		int returnOffset;
		if (this.isLeaf() && this.getOperation().contains("ARG")) {
			int argIdx = Integer.parseInt(this.getOperation().substring(3)) - 1;
			// currentStruct.remove(0);
			currentStruct.add(args.get(argIdx));
			returnOffset = 0;
		} else if (this.getOperation().equals("+")) {
			int offset = this.getLeft().mergeStruct(args, this.byteLength, currentStruct, mergedStruct, level + 1);
			if (this.getRight().isConstant()) {
				offset += Integer.parseInt(this.getRight().getOperation());
				returnOffset = offset;
			}
			// this could be an array
			else if (currentStruct.size() > 0 && this.getRight().toString().contains("f(")) {
				currentStruct.get(0).isArray(true);
				returnOffset = offset;
			} else {
				throw new Exception("failed to parse address");
			}
		} else if (this.getOperation().equals("*()")) {
			int offset = this.getLeft().mergeStruct(args, this.byteLength, currentStruct, mergedStruct, level + 1);

			if (currentStruct.size() > 0) {
				Struct cur = currentStruct.get(0);
				Struct childStruct;
				if (cur.get(offset) != null) {
					childStruct = cur.get(offset);
				} else {
					cur.extend(offset + parentByteLength);
					childStruct = new Struct(0);
					childStruct.setParentStruct(cur);
					cur.insert(childStruct, parentByteLength, offset);
				}
				if (this.getLeft().getAccessMode() != null)
					childStruct.setAccessMode(this.getLeft().getAccessMode());
				childStruct.addN(this.getLeft());
				currentStruct.remove(0);
				currentStruct.add(childStruct);

				returnOffset = 0;
			} else
				throw new Exception("failed to parse address");
		} else {
			throw new Exception("failed to parse address");
		}

		if (level == 0) {
			Struct cur = currentStruct.get(0);
			cur.merge(mergedStruct);
		}

		return returnOffset;
	}

	public boolean replaceArgs(String side, HashMap<String, Node> argReplaceMap) {
		Node n = side.equals("left") ? this.getLeft() : this.getRight();
		if (n == null) {
			return true;
		}
		boolean argChanged = true;
		if (n instanceof PhiNode) {
			argChanged &= n.replaceArgs("", argReplaceMap);
			this.reset = false;
			return argChanged;
		}
		if (n.isLeaf()) {
			String key = n.toString();
			if (argReplaceMap.containsKey(key)) {
				if (side.equals("left")) {
					this.setLeft(argReplaceMap.get(key));
				} else {
					this.setRight(argReplaceMap.get(key));
				}
			} else if (key.contains("ARG")) {
				return false;
			}
		}
		if (n.getLeft() != null) {
			argChanged &= n.replaceArgs("left", argReplaceMap);
		}
		if (n.getRight() != null) {
			argChanged &= n.replaceArgs("right", argReplaceMap);
		}
		this.reset = false;
		return argChanged;
	}
}