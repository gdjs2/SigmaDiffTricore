import java.io.Serializable;
import java.util.HashMap;
import java.util.HashSet;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

public class Struct implements Serializable {
	private int size;
	private HashMap<Integer, Struct> members;
	private HashMap<Integer, Integer> memberSize;
	private int byteLength;
	private Struct parent;
	private boolean isArray;
	private HashSet<String> accessMode = new HashSet<String>();
	private HashSet<Node> n = new HashSet<Node>();

	public HashSet<Node> getN() {
		return n;
	}

	public void addN(Node n) {
		this.n.add(n);
	}

	public Struct() {

	}

	public Struct(int size) {
		this.size = size;
		this.members = new HashMap<Integer, Struct>();
		this.memberSize = new HashMap<Integer, Integer>();
		this.isArray = false;
	}

	public void setAccessMode(String mode) {
		this.accessMode.add(mode);
	}

	public String getAccessMode() {
		if (accessMode.size() == 1)
			return (String) accessMode.toArray()[0];
		else if (accessMode.size() > 1)
			return "load/store";
		else
			return null;
	}

	public void extend(int size) {
		if (this.size > size)
			return;
		this.size = size;
	}

	public Struct get(int offset) {
		if (offset >= size) {
			return null;
		} else {
			return this.members.get(offset);
		}
	}

	public void isArray(boolean isarray) {
		this.isArray = isarray;
	}

	public void insert(Struct subStruct, int size, int offset) {
		this.members.put(offset, subStruct);
		this.memberSize.put(offset, size);
	}

	public void setParentStruct(Struct parent) {
		this.parent = parent;
	}

	public void setSymbol() {
		for (int key : this.members.keySet()) {
			if (this.members == null)
				continue;
			if (this.members.get(key).getSize() > 0) {
				this.members.get(key).setSymbol();
			} else {
				for (Node n : this.members.get(key).getN())
					n.setSymbol();
			}
		}
	}

	public int getSize() {
		return size;
	}

	public void setSize(int size) {
		this.size = size;
	}

	public void deepcopy(Struct s) {
		this.extend(s.size);
		for (int i : s.members.keySet()) {
			if (s.members.get(i) == null)
				continue;
			if (this.members.get(i) == null)
				this.members.put(i, new Struct(0));
			this.members.get(i).deepcopy(s.members.get(i));
			this.memberSize.put(i, s.memberSize.get(i));
		}
		this.byteLength = s.byteLength;
		this.isArray = s.isArray;
		this.accessMode.addAll(s.accessMode);
		this.n = s.n;
		return;
	}

	public void merge(Struct s) {
		if (this.getSize() == 0) {
			this.deepcopy(s);
		}
		int maxSize = Math.max(this.size, s.size);
		this.extend(maxSize);
		for (int i : s.members.keySet()) {
			if (s.get(i) == null)
				continue;
			if (this.get(i) == null)
				this.members.put(i, new Struct(0));
			this.get(i).merge(s.get(i));
		}
	}

	public JSONObject toJSON() {
		if (this.size == 0) {
			return null;
		}

		JSONObject structObject = new JSONObject();

		JSONArray offsets = new JSONArray();
		for (int i : this.members.keySet()) {
			JSONObject subJSON = this.members.get(i).toJSON();
			if (subJSON == null) {
				offsets.add(String.valueOf(i) + " " + this.members.get(i).getAccessMode());
			} else {
				structObject.put(String.valueOf(i), subJSON);
			}
		}
		structObject.put("offsets", offsets);
		structObject.put("isArray", this.isArray);
		return structObject;
	}
}