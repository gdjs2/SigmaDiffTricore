import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeSet;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import ghidra.app.decompiler.ClangToken;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;

public class MachineStatePCode {
	private Map<Varnode, Node> m_vnode;
	private Map<Varnode, Node> m_mems;
	private Map<String, Node> m_stack;
	private HashMap<Long, HashSet<String>> indirect_stack_off; // the stack offsets that will be influenced by the next
																// store pcode
	Language language;
	private int paramLength;
	private String name;
	private String outputPath;
	private HashMap<Address, Long> m_refSymbolLocationMap;
	private HashMap<SequenceNumber, Node> loads;
	private HashMap<SequenceNumber, ArrayList<Node>> callargs;
	private HashMap<SequenceNumber, Node> returns;
	private HashMap<Node, Node> sideeffect;
	private HashMap<Node, TreeSet<String>> sELeaf;
	private HashMap<String, HashMap<Node, TreeSet<String>>> calleeSELeaf;
	private HashMap<String, HashSet<Node>> calleeLoads;
	private HashSet<Node> loadAndStores;
	private ArrayList<Struct> dataStructs;
	private HashSet<String> callingFunction;
	private HashMap<String, TreeSet<String>> calleeReturns;
	private HashSet<String> usedStringsAndFunctions;
	private HashMap<PcodeOp, ArrayList<ClangToken>> mapping;

	public MachineStatePCode(Map<Varnode, Node> varnode_status) {
		m_vnode = varnode_status;
	}

	/* Used for forking */
	private MachineStatePCode() {

	}

	public static MachineStatePCode createInitState(HighFunction hfunction, String output,
			HashMap<Address, Long> refSymbolLocationMap, HashMap<PcodeOp, ArrayList<ClangToken>> mapping) {
		MachineStatePCode s = new MachineStatePCode();
		s.language = hfunction.getLanguage();
		s.m_refSymbolLocationMap = refSymbolLocationMap;
		/* Set register values to symbolic initial values */
		s.m_vnode = new HashMap<>(); // CPU State : Varnode
		s.m_mems = new HashMap<Varnode, Node>();
		s.m_stack = new HashMap<String, Node>();
		s.indirect_stack_off = new HashMap<Long, HashSet<String>>();
		s.loads = new HashMap<SequenceNumber, Node>();
		s.callargs = new HashMap<SequenceNumber, ArrayList<Node>>();
		s.returns = new HashMap<SequenceNumber, Node>();
		s.sideeffect = new HashMap<Node, Node>();
		s.loadAndStores = new HashSet<Node>();
		s.calleeSELeaf = new HashMap<String, HashMap<Node, TreeSet<String>>>();
		s.sELeaf = new HashMap<Node, TreeSet<String>>();
		s.calleeLoads = new HashMap<String, HashSet<Node>>();
		s.calleeReturns = new HashMap<String, TreeSet<String>>();
		s.usedStringsAndFunctions = new HashSet<String>();
		s.outputPath = output;
		s.mapping = mapping;
		String name = hfunction.getFunction().getName();
		if (hfunction.getFunction().isThunk())
			name += "_thunk";
		s.name = name + "@" + hfunction.getFunction().getEntryPoint().getOffset();
		s.paramLength = hfunction.getFunctionPrototype().getNumParams();
		for (int i = 0; i < hfunction.getFunctionPrototype().getNumParams(); i++) {
			if (hfunction.getFunctionPrototype().getParam(i).getHighVariable() == null)
				continue;
			Varnode key = hfunction.getFunctionPrototype().getParam(i).getHighVariable().getRepresentative();
			Node a = new Node(null, null, "ARG" + String.valueOf(i + 1), key.getSize());
			s.m_vnode.put(key, a);
		}

		/* Doesn't need to initialize memory state */
		return s;
	}

	public void createStruct(HashMap<String, MachineStatePartial> mstateAll) {
		ArrayList<Struct> args = new ArrayList<Struct>();
		for (int i = 0; i < paramLength; i++) {
			Struct a = new Struct(0);
			args.add(a);
		}

		for (Entry<SequenceNumber, ArrayList<Node>> entry : this.callargs.entrySet()) {
			ArrayList<Node> callarg = entry.getValue();
			String callee = callarg.get(callarg.size() - 1).getOperation();// the name of callee is put on the last
																			// element of callarg array
			if (callee.contains("memset_thunk@") || callee.contains("memset@")) {
				this.addCalleeSideEffect(callarg.get(0), callarg.get(1).leafSet, callee);
				continue;
			}
			if (!mstateAll.containsKey(callee))
				continue;
			if (this.name.equals(callee))
				continue;
			if (mstateAll.get(callee).dataStructs == null)
				continue;

			mstateAll.get(callee).callingFunction.remove(this.name);
			HashMap<String, Node> argReplaceMap = new HashMap<String, Node>(); // we need to replace key to value when
																				// call replaceArgs
			for (int i = 0; i < callarg.size() - 1; i++) {
//				if (callarg.get(i).toString().contains("ARG"))
				callarg.get(i).recollectLeaf();
				argReplaceMap.put("ARG" + String.valueOf(i + 1), callarg.get(i));
			}
			for (int i = 0; i < mstateAll.get(callee).dataStructs.size(); i++) {
				String key = "ARG" + String.valueOf(i + 1);
				Node argNode = argReplaceMap.get(key);
				Struct mergedNode = mstateAll.get(callee).dataStructs.get(i);
				try {
					ArrayList<Struct> currentStruct = new ArrayList<Struct>();
					argNode.mergeStruct(args, argNode.getSize(), currentStruct, mergedNode, 0);
				} catch (Exception e) {
//					System.err.println("Faild to create struct for : " + n.toString());
//					 e.printStackTrace();
				}

			}

			// update side effect
			this.addCalleeSideEffect(mstateAll.get(callee).sELeaf, argReplaceMap, callee);
			this.addCalleeSideEffect(mstateAll.get(callee).calleeSELeaf, argReplaceMap, callee);

			// update loads
			this.addCalleeLoads(mstateAll.get(callee).loads, argReplaceMap, callee);
			this.addCalleeLoads(mstateAll.get(callee).calleeLoads, argReplaceMap, callee);

		}

		for (Node n : loadAndStores) {
			// System.out.println("Phi: " + n.toString());
//			for (Node rn : n.expandPhiNodes()) {
//				try {
//					System.out.println(rn.toString());
//					ArrayList<Struct> currentStruct = new ArrayList<Struct>();
//					rn.createStruct(args, rn.getSize(), currentStruct);
//					// System.out.println(args.get(0).toJSON().toString());
//				} catch (Exception e) {
//					System.err.println("Faild to create struct for : " + rn.toString());
//					// e.printStackTrace();
//				}
//			}
			try {
				ArrayList<Struct> currentStruct = new ArrayList<Struct>();
				n.createStruct(args, n.getSize(), currentStruct, 0);
				// System.out.println(args.get(0).toJSON().toString());
			} catch (Exception e) {
//				System.err.println("Faild to create struct for : " + n.toString());
				// e.printStackTrace();
			}

		}

		this.dataStructs = args;

		for (Struct a : args) {
			a.setSymbol();
		}

		// remove some function from mstate in order to save space
		HashSet<String> removedName = new HashSet<String>();
		for (MachineStatePartial ms : mstateAll.values()) {
			if (ms.callingFunction.size() == 0)
				removedName.add(ms.name);
		}
		for (String rm : removedName) {
			mstateAll.remove(rm);
		}
//		System.out.println("mstateAll: " + mstateAll.size());
	}

	public void addStackOffset(Long seq, String offset) {
		if (!indirect_stack_off.containsKey(seq))
			indirect_stack_off.put(seq, new HashSet<String>());
		indirect_stack_off.get(seq).add(offset);
	}

	public void addCallArgs(SequenceNumber addr, ArrayList<Node> s) {
		callargs.put(addr, s);
	}

	public ArrayList<Node> getCallArgs(SequenceNumber addr) {
		return callargs.get(addr);
	}

	public void addLoads(SequenceNumber addr, Node s) {
		loads.put(addr, s);
	}

	public void addReturns(SequenceNumber addr, Node s) {
		returns.put(addr, s);
	}

	public HashSet<Node> getReturnValues() {
		return new HashSet<Node>(returns.values());
	}

	public void addSideEffect(Node varnode, Node s) {
		sideeffect.put(varnode, s);
	}

	public void addStringsAndFunctions(String s) {
		this.usedStringsAndFunctions.add(s);
	}

	public HashMap<PcodeOp, ArrayList<ClangToken>> getMapping() {
		return mapping;
	}

	public void addCalleeSideEffect(Node varnode, TreeSet<String> s, String callee) {
		if (varnode.toString().contains("ARG") && !varnode.toString().contains("RSP")) {
			HashMap<Node, TreeSet<String>> se4callee = new HashMap<Node, TreeSet<String>>();
			se4callee.put(varnode, s);
			calleeSELeaf.put(callee, se4callee);
		}
	}

	public void addCalleeSideEffect(HashMap<Node, TreeSet<String>> sideeffect, HashMap<String, Node> argReplaceMap,
			String callee) {
		HashMap<Node, TreeSet<String>> se4callee;
		if (calleeSELeaf.containsKey(callee))
			se4callee = calleeSELeaf.get(callee);
		else
			se4callee = new HashMap<Node, TreeSet<String>>();
		HashSet<String> tempStringSet = new HashSet<String>();
		for (Node v : sideeffect.keySet()) {
			TreeSet<String> se = sideeffect.get(v);
			TreeSet<String> newSe = new TreeSet<String>();
//			System.out.println("value " + se.toString());
			boolean argChanged = true;
			for (String key : se) {
				if (argReplaceMap.containsKey(key)) {
					newSe.addAll(argReplaceMap.get(key).leafSet);
				} else if (key.contains("ARG")) {
					// if the leaf node is an arg but it's not in the argReplaceMap, meaning that we
					// don't know how to replace it
					argChanged = false;
					break;
				} else {
					newSe.add(key);
				}
			}
			if (!argChanged) {
				continue;
			}

//			System.out.println("address " + v.toString());
			Node newAddr = v.deepCopy();
			if (newAddr instanceof PhiNode)
				argChanged &= newAddr.replaceArgs("", argReplaceMap);
			else if (newAddr.isLeaf()) {
				String key = newAddr.toString();
				if (argReplaceMap.containsKey(key)) {
					newAddr = argReplaceMap.get(key);
				} else if (key.contains("ARG")) {
					break;
				}
			} else {
				argChanged &= newAddr.replaceArgs("left", argReplaceMap);
				argChanged &= newAddr.replaceArgs("right", argReplaceMap);
			}
			if (argChanged) {
				String newAddrString = newAddr.toString();
				String newSideEffect = newAddrString + newSe.toString();
				if (!tempStringSet.contains(newSideEffect) && newAddrString.contains("ARG")
						&& !newAddrString.contains("RSP"))
					se4callee.put(newAddr, newSe);
				tempStringSet.add(newSideEffect);
			}

		}
		calleeSELeaf.put(callee, se4callee);
	}

	public void addCalleeLoads(HashSet<Node> loads, HashMap<String, Node> argReplaceMap, String callee) {
		HashSet<Node> loads4callee;
		if (calleeLoads.containsKey(callee))
			loads4callee = calleeLoads.get(callee);
		else
			loads4callee = new HashSet<Node>();
		HashSet<String> tempStringSet = new HashSet<String>();
		for (Node v : loads) {
//			System.out.println("address " + v.toString());
			boolean argChanged = true;
			Node newAddr = v.deepCopy();
			if (newAddr instanceof PhiNode)
				argChanged &= newAddr.replaceArgs("", argReplaceMap);
			else if (newAddr.isLeaf()) {
				String key = newAddr.toString();
				if (argReplaceMap.containsKey(key)) {
					newAddr = argReplaceMap.get(key);
				} else if (key.contains("ARG")) {
					break;
				}
			} else {
				argChanged &= newAddr.replaceArgs("left", argReplaceMap);
				argChanged &= newAddr.replaceArgs("right", argReplaceMap);
			}
			if (argChanged) {
				String newAddrString = newAddr.toString();
				if (!tempStringSet.contains(newAddrString) && newAddrString.contains("ARG")
						&& !newAddrString.contains("RSP")) {
					loads4callee.add(newAddr);
					tempStringSet.add(newAddrString);
				}
			}

		}
		calleeLoads.put(callee, loads4callee);
	}

	public void printConstraints(String filepath) {
		try {
			FileWriter fw = new FileWriter(filepath);
			fw.write("loads\n");
			for (Node con : loads.values()) {
				fw.write(con + "\n");
			}

			fw.write("returns\n");
			for (Node con : returns.values()) {
				fw.write(con + "\n");
			}
			fw.write("call arguments\n");
			for (ArrayList<Node> con : callargs.values()) {
				fw.write(con.toString() + "\n");
			}
			fw.write("side effect\n");
			for (Node con : sideeffect.values()) {
				fw.write(con + "\n");
			}
			fw.close();
		} catch (IOException e) {

		}

	}

	public void toJSON(String filepath, HighFunction hfunction) {
		try {
			JSONObject constraintObject = new JSONObject();
			JSONArray cond = new JSONArray();
			for (Node con : this.loads.values()) {
				cond.add((String.valueOf(con.toStringLeaf()) + ": " + con.toString()));
			}
			constraintObject.put("loads", cond);
			JSONObject calleeloads = new JSONObject();
			for (Map.Entry<String, HashSet<Node>> con : this.calleeLoads.entrySet()) {
				String callee = con.getKey();
				JSONArray cloads = new JSONArray();
				HashSet<String> hashSet = new HashSet<String>();
				for (Node node : con.getValue()) {
					hashSet.add(String.valueOf(node.toStringLeaf()) + ": " + node.toString());
				}
				cloads.addAll(hashSet);
				calleeloads.put(callee, cloads);
			}
			constraintObject.put("calleeloads", calleeloads);
			TreeSet<String> retSet = new TreeSet<String>();
			for (Node con : this.returns.values()) {
				for (String str : con.leafSet) {
					if (str.equals("RFC") || str.contains("A_Stack"))
						continue;
					retSet.add(str);
				}
			}
			JSONArray retArray = new JSONArray();
			retArray.addAll(retSet);
			constraintObject.put("return", retArray);
			JSONArray stringsAndLibcalls = new JSONArray();
			stringsAndLibcalls.addAll(this.usedStringsAndFunctions);
			constraintObject.put("stringsAndLibcalls", stringsAndLibcalls);
			JSONArray calls = new JSONArray();
			for (ArrayList<Node> arrayList : this.callargs.values()) {
				JSONArray jSONArray = new JSONArray();
				for (Node c : arrayList) {
					jSONArray.add(c.toStringLeaf());
				}
				calls.add(jSONArray);
			}
			constraintObject.put("calls", calls);
			JSONArray jSONArray = new JSONArray();
			for (Map.Entry<Node, Node> entry : this.sideeffect.entrySet()) {
				Node key = entry.getKey();
				jSONArray.add((String.valueOf(key.toStringLeaf()) + ": " + key.toString() + ": "
						+ entry.getValue().toStringLeaf()));
			}
			constraintObject.put("sideeffect", jSONArray);
			JSONObject jSONObject = new JSONObject();
			for (Entry<String, HashMap<Node, TreeSet<String>>> entry : this.calleeSELeaf.entrySet()) {
				String callee = entry.getKey();
				JSONArray cse = new JSONArray();
				HashSet<String> csestring = new HashSet<String>();
				for (Entry<Node, TreeSet<String>> seset : entry.getValue().entrySet()) {
					Node key = seset.getKey();
					String s = "f(";
					int i = 0;
					int size = seset.getValue().size();
					for (String n : seset.getValue()) {
						if (!n.equals("RFC") && !n.contains("A_Stack"))
							continue;
						--size;
					}
					for (String n : seset.getValue()) {
						if (n.equals("RFC") || n.contains("A_Stack"))
							continue;
						s = String.valueOf(s) + n;
						if (i < size - 1) {
							s = String.valueOf(s) + " , ";
						}
						++i;
					}
					s = String.valueOf(s) + ")";
					csestring.add(String.valueOf(key.toStringLeaf()) + ": " + key.toString() + ": " + s);
				}
				cse.addAll(csestring);
				jSONObject.put(callee, cse);
			}
			constraintObject.put("calleesideeffect", jSONObject);

			for (int i = 0; i < this.paramLength; i++) {
				JSONObject dsJSON = this.dataStructs.get(i).toJSON();
				if (this.dataStructs != null && dsJSON != null) {
					constraintObject.put("arg" + String.valueOf(i + 1), dsJSON);
				} else {
					constraintObject.put("arg" + String.valueOf(i + 1),
							hfunction.getFunctionPrototype().getParam(i).getDataType().toString());
				}
			}

			constraintObject.put("numargs", paramLength);
			Files.write(Paths.get(filepath), constraintObject.toJSONString().getBytes());
		} catch (IOException e) {
			System.out.println("An error occurred.");
			e.printStackTrace();
		}

	}

	public static String identifyStrings(Varnode vnode) {
		if (VSAPCode.stringRefLocationSet.containsKey(vnode.getPCAddress())
				&& VSAPCode.stringRefLocationSet.get(vnode.getPCAddress()).containsKey(vnode.getOffset())) {
			return VSAPCode.stringRefLocationSet.get(vnode.getPCAddress()).get(vnode.getOffset());
		}
		for (Address addr : VSAPCode.stringLocationMap.keySet()) {
			if (!addr.getAddressSpace().toString().equals("ram:"))
				continue;
			Long startIndex = addr.getOffset();
			Address addrString = vnode.getAddress();
			Long offset = addrString.getOffset();
			Long endIndex = startIndex + (long) VSAPCode.stringLocationMap.get(addr).length();
			if (offset >= endIndex || offset < startIndex)
				continue;
			int subIndex = (int) (offset - startIndex);
			String stringdata = VSAPCode.stringLocationMap.get(addr);
			stringdata = stringdata.substring(subIndex);
			stringdata = stringdata.replaceAll("\n", " ");
			stringdata = stringdata.strip();
			stringdata = stringdata.replaceAll("[^\\x20-\\x7e]", "");
			if (VSAPCode.stringRefLocationSet.containsKey(vnode.getPCAddress())) {
				VSAPCode.stringRefLocationSet.get(vnode.getPCAddress()).put(vnode.getOffset(), stringdata);
			} else {
				HashMap<Long, String> value = new HashMap<Long, String>();
				value.put(vnode.getOffset(), stringdata);
				VSAPCode.stringRefLocationSet.put(vnode.getPCAddress(), value);
			}
			return stringdata;
		}
		return null;
	}

	public Node getVnodeValue(Varnode vnode, boolean isCondition) {
		Node ret;
		if (this.m_vnode.containsKey(vnode)) {
			if (isCondition) {
				return this.m_vnode.get(vnode);
			}
			Node returnNode = this.m_vnode.get(vnode);
			if (returnNode.getOperation().contains("_") && !returnNode.getOperation().contains("A_")
					|| returnNode.getOperation().equals("^")) {
				return new Node(null, null, "0", vnode.getSize());
			}
			return returnNode;
		}
		if (vnode.isConstant()) {
			String isString = identifyStrings(vnode);
			if (isString != null) {
				ret = new Node(null, null, isString, vnode.getSize());
				this.usedStringsAndFunctions.add(isString);
			} else {
				ret = this.m_refSymbolLocationMap.containsKey(vnode.getPCAddress())
						&& this.m_refSymbolLocationMap.get(vnode.getPCAddress()).longValue() == vnode.getOffset()
								? new Node(null, null, "Symbol", vnode.getSize())
								: new Node(null, null,
										String.valueOf(Node.parseLong((String) vnode.toString(this.language))),
										vnode.getSize());
			}
		} else if (vnode.toString(language).equals("FS_OFFSET")) {
			ret = new Node(null, null, "FS_OFFSET", vnode.getSize());
		} else if (vnode.toString(language).equals("RSP")) {
			ret = new Node(null, null, "RSP", vnode.getSize());
		} else if (vnode.getSpace() == 53) { // stack
			if (m_stack.containsKey(Long.toHexString(vnode.getOffset()))) {
				ret = m_stack.get(Long.toHexString(vnode.getOffset()));
			} else {
				ret = new Node(null, null, vnode.toString(language), vnode.getSize());
				return ret;
			}
		} else {
			// System.out.println(vnode.toString(language));
			ret = new Node(null, null, "VZERO", vnode.getSize());
		}
		m_vnode.put(vnode, ret);
		return ret;
		// System.out.println(vnode.toString(language));
		// return new Node("V" + vnode.toString(language));
	}

	public boolean setVnodeValue(Varnode register, Node value) {
		assert value != null;
		if (register.getSize() != value.getSize())
			value.setSize(register.getSize());
		Node n = m_vnode.get(register);
		if (n == null || !n.toString().equals(value.toString())) {
			m_vnode.put(register, value);
//		System.out.println("set vnode " + register.toString() + " as " + value.toString());
			return true;
		}
		return false;
	}

	public void setMemAccess(Node address, String mode) {
		Node mem = new Node(address, null, "*()", address.getSize());
		address.setAccessMode(mode);
		loadAndStores.add(mem);
	}

	public boolean setMemValue(Varnode address, Node value, PcodeOp pcode) {
		assert value != null;

		Node addrNode = m_vnode.get(address);
		if (addrNode == null)
			addrNode = this.getVnodeValue(address, false);
		if (addrNode.toString().contains("RSP")) {
			if (addrNode instanceof PhiNode) {
				boolean ret = false;
				for (Node addr : ((PhiNode) addrNode).getValueSet()) {
					Node n = m_stack.get(addr.toString());
					if (n == null) {
						m_stack.put(addr.toString(), value);
						ret = true;
					} else if (n != null && !n.toString().equals(value.toString())) {
						// for memory locations, if already exists a value in this location, we need to
						// merge the new value with old value
						PhiNode newOutput = new PhiNode(value.getSize());
						newOutput.merge(value);
						newOutput.merge(n);
						ret = true;
						if (n.toString().equals(newOutput.toString()))
							ret = false;
						m_stack.put(addr.toString(), newOutput);
					}
				}
				return ret;
			} else {
				Long seq = (long) pcode.getSeqnum().getTime();
				if (!indirect_stack_off.containsKey(seq)) {
					Node n = m_stack.get(addrNode.toString());
					if (n == null) {
						m_stack.put(addrNode.toString(), value);
						return true;
					} else if (n != null && !n.toString().equals(value.toString())) {
						// for memory locations, if already exists a value in this location, we need to
						// merge the new value with old value
						PhiNode newOutput = new PhiNode(value.getSize());
						newOutput.merge(value);
						newOutput.merge(n);
						if (n.toString().equals(newOutput.toString()))
							return false;
						else {
							m_stack.put(addrNode.toString(), newOutput);

							return true;
						}
					}
					return false;
				} else {
					boolean ret = false;
					for (String offset : indirect_stack_off.get(seq)) {
						Node n = m_stack.get(offset);
						if (n == null) {
							m_stack.put(offset, value);
							ret |= true;
						} else if (!n.toString().equals(value.toString())) {
							// for memory locations, if already exists a value in this location, we need to
							// merge the new value with old value
							PhiNode newOutput = new PhiNode(value.getSize());
							newOutput.merge(value);
							newOutput.merge(n);
							if (n.toString().equals(newOutput.toString()))
								ret |= false;
							else {
								m_stack.put(addrNode.toString(), newOutput);
								ret |= true;
							}
						}
					}
					indirect_stack_off.clear();
					return ret;
				}
			}
		} else {

			Node n = m_mems.get(address);
			if (n == null) {
				m_mems.put(address, value);
				// System.out.println("MEM: add " + address.toString(language) + ": " +
				// value.toString());
				return true;
			} else if (n != null && !n.toString().equals(value.toString())) {
				// for memory locations, if already exists a value in this location, we need to
				// merge the new value with old value
				PhiNode newOutput = new PhiNode(value.getSize());
				newOutput.merge(value);
				newOutput.merge(n);
				if (n.toString().equals(newOutput.toString()))
					return false;
				else {
					m_mems.put(address, newOutput);
//				System.out.println("MEM: change " + address.toString(language) + " from " + n.toString() + " to "
//						+ newOutput.toString());

					return true;
				}
			}
			return false;
		}
	}

	public Node getMemValue(Varnode address) {
		return touchMemAddr(address);
	}

	/**
	 * Make the memory address if never touched
	 *
	 * @param address
	 * @return
	 */
	public Node touchMemAddr(Varnode vaddress) {
		Node value = m_mems.get(vaddress);
		if (value == null) {
			Node address = m_vnode.get(vaddress);
			if (address == null) {
//				System.out.println(vaddress.toString(language));
				if (vaddress.toString(language).equals("RSI")) {
					address = new Node(null, null, "ARG2", vaddress.getSize());
					m_vnode.put(vaddress, address);
				} else if (vaddress.toString(language).equals("RDX")) {
					address = new Node(null, null, "ARG3", vaddress.getSize());
					m_vnode.put(vaddress, address);
				} else if (vaddress.toString(language).equals("RCX")) {
					address = new Node(null, null, "ARG4", vaddress.getSize());
					m_vnode.put(vaddress, address);
				} else if (vaddress.toString(language).equals("R8")) {
					address = new Node(null, null, "ARG5", vaddress.getSize());
					m_vnode.put(vaddress, address);
				} else if (vaddress.toString(language).equals("R9")) {
					address = new Node(null, null, "ARG6", vaddress.getSize());
					m_vnode.put(vaddress, address);
				} else {
					address = new Node(null, null, "0", vaddress.getSize());
					m_vnode.put(vaddress, address);
				}
			} else if (address.toString().contains("RSP")) {
				value = m_stack.get(Long.toHexString(vaddress.getOffset()));
				if (value != null)
					return value;
				Node symbolNode = new Node(address, null, "*()", address.getSize());
				m_stack.put(address.toString(), symbolNode);
				return symbolNode;
			}
			Node symbolNode = new Node(address, null, "*()", address.getSize());
			m_mems.put(vaddress, symbolNode);
			return symbolNode;
		}
		return value;
	}

	/**
	 * Make a deep copy of a Map, for internal use only
	 *
	 * @param proto
	 * @return
	 */
	private Map<String, String> _deepCopy(Map<String, String> proto) {
		Map<String, String> to = new HashMap<>();

		for (Map.Entry<String, String> ent : proto.entrySet()) {
			String k = new String(ent.getKey());
			String v = new String(ent.getValue());
			to.put(k, v);
		}
		return to;
	}

	public MachineStatePartial copyUseful(Set<Function> fset) {
		MachineStatePartial newMS = new MachineStatePartial();
		newMS.dataStructs = this.dataStructs;
		newMS.calleeSELeaf = new HashMap<Node, TreeSet<String>>();

		for (HashMap<Node, TreeSet<String>> se : this.calleeSELeaf.values()) {
			for (Node addr : se.keySet())
				newMS.calleeSELeaf.put(addr, se.get(addr));
		}
		newMS.sELeaf = new HashMap<Node, TreeSet<String>>();
		for (Node addr : this.sideeffect.keySet()) {
			newMS.sELeaf.put(addr, this.sideeffect.get(addr).leafSet);
		}

		newMS.calleeLoads = new HashSet<Node>();

		for (HashSet<Node> loads : this.calleeLoads.values()) {
			newMS.calleeLoads.addAll(loads);
		}
		newMS.loads = new HashSet<Node>();
		for (Node addr : this.loads.values()) {
			newMS.loads.add(addr);
		}

		TreeSet<String> ret = new TreeSet<String>();
		for (Node r : returns.values()) {
			ret.addAll(r.leafSet);
		}
		newMS.returns = ret;
//		System.out.println(newMS.returns);
		newMS.callingFunction = new HashSet<String>();
		for (Function calling : fset) {
			String name = calling.getName();
			if (calling.isThunk())
				name += "_thunk";
			newMS.callingFunction.add(name + "@" + calling.getEntryPoint().getOffset());
		}
		newMS.name = this.name;
		return newMS;
	}

	public String toString(HighFunction hfunction) {
		LocalSymbolMap lsm = hfunction.getLocalSymbolMap();
		Iterator<HighSymbol> symbols = lsm.getSymbols();
		String ret = "";
		while (symbols.hasNext()) {
			HighSymbol symbol = symbols.next();
			if (symbol.getHighVariable() == null)
				continue;
			for (Varnode vnode : symbol.getHighVariable().getInstances()) {
				if (this.m_vnode.get(vnode) == null)
					continue;
				this.m_vnode.get(vnode).recollectLeaf();
				ret += String.format("symbols: %s, vnode defined address: %s, type: %s, value: %s\n", symbol.getName(),
						vnode.getPCAddress(), symbol.getDataType(), this.m_vnode.get(vnode).toString());
			}
		}

		if (this.dataStructs != null) {
			for (int i = 0; i < this.paramLength; i++) {
				if (this.dataStructs.get(i).toJSON() != null) {
					ret += "arg" + String.valueOf(i + 1);
					ret += this.dataStructs.get(i).toJSON();
				}
			}
		}
		return ret;
	}
}