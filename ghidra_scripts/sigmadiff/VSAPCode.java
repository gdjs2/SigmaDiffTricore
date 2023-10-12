import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStreamWriter;
import java.io.Serializable;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Queue;
import java.util.Set;
import java.util.TreeSet;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import ghidra.app.decompiler.ClangBreak;
import ghidra.app.decompiler.ClangCommentToken;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.Option;
import ghidra.app.util.exporter.CppExporter;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.StringUTF8DataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.data.TerminatedUnicode32DataType;
import ghidra.program.model.data.TerminatedUnicodeDataType;
import ghidra.program.model.data.Unicode32DataType;
import ghidra.program.model.data.UnicodeDataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

public class VSAPCode extends GhidraScript {
	private DecompInterface decomplib;
	private HashMap<String, MachineStatePartial> mstateAll = new HashMap<String, MachineStatePartial>();
	public static HashMap<Address, String> stringLocationMap = new HashMap<Address, String>();
	public static HashMap<Address, HashMap<Long, String>> stringRefLocationSet = new HashMap<Address, HashMap<Long, String>>();
	HashMap<Integer, HashSet<Integer>> ddedges;
	HashMap<Integer, HashSet<Integer>> cdEdges;
	HashMap<Integer, HashSet<Integer>> extraEdges;
	HashMap<String, HashMap<String, Integer>> cuNodes;
	HashMap<String, Integer> stringAndLibcallID;
	ArrayList<String> printedNodes;
	HashMap<PcodeOp, String> corpus;
	HashSet<String> targetFuncs;
	HashSet<String> duplicateFuncNames;
	boolean useVSA = true;

	public DecompileResults decompileFunction(Function f) {
		DecompileResults dRes = null;

		try {
			dRes = decomplib.decompileFunction(f, decomplib.getOptions().getDefaultTimeout(), getMonitor());
//			DecompilerSwitchAnalysisCmd cmd = new DecompilerSwitchAnalysisCmd(dRes);
//			cmd.applyTo(currentProgram);
		} catch (Exception exc) {
			printf("EXCEPTION IN DECOMPILATION!\n");
			exc.printStackTrace();
		}

		return dRes;
	}

	public boolean ignoreNodes(ClangNode root) {
		if (root instanceof ClangBreak || root instanceof ClangCommentToken)
			return true;
		if (root instanceof ClangTokenGroup) {
			for (int i = 0; i < root.numChildren(); ++i) {
				if (root.Child(i) instanceof ClangBreak || root.Child(i) instanceof ClangCommentToken)
					continue;
				return false;
			}
			return true;
		}
		return false;
	}

	public int findVnodeInPcode(PcodeOp pcode, Varnode vnode) {
		if (pcode.getOutput() != null && pcode.getOutput().equals(vnode))
			return 0;
		for (int i = 0; i < pcode.getNumInputs(); i++) {
			if (pcode.getInput(i).equals(vnode))
				return i + 1;
		}
		return -1;
	}

	public void exportAllFun(String outdir) {
		FunctionManager functionManager = this.currentProgram.getFunctionManager();
		FunctionIterator functions = functionManager.getFunctions(true);
		for (Function function : functions) {
			Address addr = function.getEntryPoint();
			exportFun(addr, outdir + "/" + function.getName() + ".c");
		}
	}

	public void exportFun(Address FuncEntryPoint, String outfile) {
		AddressSet addressSet = new AddressSet();
		addressSet.add(FuncEntryPoint);
		File outputFile = new File(outfile);
		CppExporter cppExporter = new CppExporter();
		ArrayList<Option> options = new ArrayList<Option>();
		options.add(new Option("Create Header File (.h)", (Object) new Boolean(true)));
		try {
			cppExporter.setOptions(options);
			cppExporter.setExporterServiceProvider((ServiceProvider) this.state.getTool());
			cppExporter.export(outputFile, (DomainObject) this.currentProgram, (AddressSetView) addressSet,
					this.monitor);
		} catch (Exception exception) {
			// empty catch block
		}
//		System.out.println("Done export");
	}

	/**
	 * Recursive toplogical sort
	 * 
	 * @param bb
	 * @param v
	 * @param visited
	 * @param stack
	 * @param backwardEdges
	 */
	public void toplogicalSort(ArrayList<PcodeBlockBasic> bb, PcodeBlockBasic v, Boolean[] visited,
			ArrayList<PcodeBlockBasic> stack, HashMap<PcodeBlockBasic, PcodeBlockBasic> backwardEdges) {
		int vidx = bb.indexOf(v);
		visited[vidx] = true;

		int neighbours = v.getOutSize();
		for (int i = 0; i < neighbours; i++) {
			PcodeBlockBasic n = (PcodeBlockBasic) v.getOut(i);
			int dst_id = bb.indexOf(n);
			if (visited[dst_id]) {
				backwardEdges.put(v, n);
			}
			if (n != null && !visited[dst_id]) {
				toplogicalSort(bb, bb.get(dst_id), visited, stack, backwardEdges);
			}
		}
		stack.add(0, v);
		// System.out.print(v.toString());
	}

	/**
	 * Repeat the basic blocks in loop in order to get stable result for phi node,
	 * each backward edge represents a loop
	 * 
	 * @param stack
	 * @param backwardEdges
	 */
	public void addLoop(ArrayList<PcodeBlockBasic> stack, HashMap<PcodeBlockBasic, PcodeBlockBasic> backwardEdges) {
		HashMap<PcodeBlockBasic, Integer> backwardLength = new HashMap<PcodeBlockBasic, Integer>();

		for (PcodeBlockBasic name : backwardEdges.keySet()) {
			PcodeBlockBasic name2 = backwardEdges.get(name);
			int ind1 = stack.indexOf(name);
			int ind2 = stack.indexOf(name2);
			if (ind1 >= ind2) {
				backwardLength.put(name, ind1 - ind2);
			}
		}

		// Create a list from elements of HashMap backwardLength
		List<Map.Entry<PcodeBlockBasic, Integer>> list = new LinkedList<Map.Entry<PcodeBlockBasic, Integer>>(
				backwardLength.entrySet());

		// Sort the list according to the length of backward edge
		Collections.sort(list, new Comparator<Map.Entry<PcodeBlockBasic, Integer>>() {
			public int compare(Map.Entry<PcodeBlockBasic, Integer> o1, Map.Entry<PcodeBlockBasic, Integer> o2) {
				return (o1.getValue()).compareTo(o2.getValue());
			}
		});

		// Go over each loop one more time, start from the shortest loop,
		// which means for a double loop, the inner loop will repeat four times,
		// outer loop will repeat two times
		for (Map.Entry<PcodeBlockBasic, Integer> nn : list) {
			PcodeBlockBasic name2 = backwardEdges.get(nn.getKey());
			int ind1 = stack.lastIndexOf(nn.getKey());
			int ind2 = stack.indexOf(name2);
			if (ind1 >= ind2) {
				for (int i = 0; i <= ind1 - ind2; i++) {
					stack.add(ind1 + i + 1, stack.get(ind2 + i));
				}
			}
		}
	}

	public HashMap<PcodeOp, ArrayList<ClangToken>> mapPcodeOpToClangTokenList(ClangTokenGroup ccode) {
		List<ClangNode> lst = new ArrayList<ClangNode>();
		ccode.flatten(lst);
		ArrayList<ClangLine> lines = DecompilerUtils.toLines(ccode);
		HashMap<PcodeOp, ArrayList<ClangToken>> mapping = new HashMap<PcodeOp, ArrayList<ClangToken>>();

		for (ClangLine l : lines) {
//			println(l.toString());
			for (ClangToken c : l.getAllTokens()) {
				if (c.getPcodeOp() != null) {
//					println("--- " + c.toString() + " " + c.getPcodeOp().toString() + " " + c.getPcodeOp().getSeqnum().toString());
					if (!mapping.containsKey(c.getPcodeOp())) {
						mapping.put(c.getPcodeOp(), new ArrayList<ClangToken>());
					}
					mapping.get(c.getPcodeOp()).add(c);
				}
			}
		}
		return mapping;
	}

	public void export(ClangTokenGroup ccode, Function f) {
		try {
			String name;
			if (f.isThunk())
				name = f.getName() + "_thunk";
			else
				name = f.getName();
			if (this.duplicateFuncNames.contains(name))
				name = f.getPrototypeString(false, false).replace(' ', '_').replace(f.getName(), f.getName(true));
			File outFile = new File(this.getScriptArgs()[0] + "/decompiled/" + name + ".c");
			outFile.getParentFile().mkdirs();
			BufferedWriter out = new BufferedWriter(new OutputStreamWriter(
					new FileOutputStream(this.getScriptArgs()[0] + "/decompiled/" + name + ".c")));
			ArrayList<ClangLine> lines = DecompilerUtils.toLines(ccode);
			for (ClangLine l : lines) {
				out.write(l.toString());
				out.newLine();
			}
			out.close();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	public void analyzeFunction(Function f, HashMap<Address, Long> refSymbolLocationMap) {
		long start = System.currentTimeMillis();

		DecompileResults dRes = decompileFunction(f);
		HighFunction hfunction = dRes.getHighFunction();
		if (hfunction == null)
			return;

		ClangTokenGroup ccode = dRes.getCCodeMarkup();
		HashMap<PcodeOp, ArrayList<ClangToken>> mapping = mapPcodeOpToClangTokenList(ccode);
		// export(ccode, f);
		// currentProgram.getListing().
		Language language = currentProgram.getLanguage();
		if (hfunction == null) {
			printf("ERROR: Failed to decompile function!\n");
			return;
		}

		printf("number of parameters %d\n", hfunction.getFunctionPrototype().getNumParams());
		String output = this.getScriptArgs()[0];
		MachineStatePCode mstate = MachineStatePCode.createInitState(hfunction, output, refSymbolLocationMap, mapping);
		ArrayList<PcodeBlockBasic> bb = hfunction.getBasicBlocks();

		if (bb.size() == 0)
			return;

		Boolean[] visited = new Boolean[bb.size()];
		Arrays.fill(visited, Boolean.FALSE);
		ArrayList<PcodeBlockBasic> stack = new ArrayList<PcodeBlockBasic>();
		HashMap<PcodeBlockBasic, PcodeBlockBasic> backwardEdges = new HashMap<PcodeBlockBasic, PcodeBlockBasic>();
		for (int i = 0; i < bb.size(); i++) {
			if (!visited[i]) {
				toplogicalSort(bb, bb.get(i), visited, stack, backwardEdges);
			}
		}

		Queue<PcodeBlockBasic> workList = new LinkedList<>();
		workList.addAll(stack);

		int it = 0;
		while (!workList.isEmpty() && !monitor.isCancelled()) {
			boolean stateChanged = false;
			PcodeBlockBasic pBB = workList.remove();
			Iterator<PcodeOp> opIter = pBB.getIterator();
			it++;
			if (it / bb.size() > 50) {
				// this is for debugging
				printf("dead loop!!!");
				break;
			}
//			println(pBB.toString());

			while (opIter.hasNext()) {
				PcodeOp pcodeOp = opIter.next();
				boolean changed = analyzePcodeOp(pcodeOp, mstate);
				stateChanged = stateChanged || changed;
			}

			if (stateChanged) {
				int neighbours = pBB.getOutSize();
				for (int i = 0; i < neighbours; i++) {
					workList.add((PcodeBlockBasic) pBB.getOut(i));
				}
			}
		}
		long end = System.currentTimeMillis();
		// System.out.println("VSA costs: " + String.valueOf(end - start) + "ms");
		mstate.createStruct(mstateAll);
		start = end;
		end = System.currentTimeMillis();
		// System.out.println("Build struct & inter-procedual analysis costs: " + String.valueOf(end - start) + "ms");
		String binPath = this.currentProgram.getExecutablePath();
		if (!f.isThunk()) {
			String name = f.getName();
			if (this.duplicateFuncNames.contains(name))
				name = f.getPrototypeString(false, false).replace(' ', '_').replace(f.getName(), f.getName(true));
			// mstate.toJSON(output + "/" + name + ".json", hfunction);
		}
		if (!f.isThunk())
			getPDGIR(hfunction, mstate);
		Object calleeName = f.getName();
		if (f.isThunk()) {
			calleeName = (String) calleeName + "_thunk";
		}

		if (Runtime.getRuntime().freeMemory() > 500000000) {
			this.mstateAll.put((String) calleeName + "@" + f.getEntryPoint().getOffset(),
					mstate.copyUseful(f.getCallingFunctions(this.monitor)));
		} else {
			ObjectOutputStream oos;
			try {
				oos = new ObjectOutputStream(
						new FileOutputStream("/tmp/" + (String) calleeName + "@" + f.getEntryPoint().getOffset()));
				oos.writeObject(mstate.copyUseful(f.getCallingFunctions(this.monitor)));
				oos.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		start = end;
		end = System.currentTimeMillis();
		// System.out.println("File operation costs: " + String.valueOf(end - start) + "ms");
		mstateAll.clear();
	}

	public String getValueSet(PcodeOp pcode, MachineStatePCode mstate, int lineId, HighFunction hfunction, HashMap<PcodeOp, Integer> pdgNodes) {
		TreeSet<String> retValue = new TreeSet<String>();
		TreeSet<String> typeStr = new TreeSet<String>();
		TreeSet<String> address = new TreeSet<String>();
		String corpusStr = "";
		String functionName = hfunction.getFunction().getName();
		int numberOfAddedNodes = 1;
		String calleeValue = null;

		// get the address from pcode
		address.add(pcode.getSeqnum().getTarget().toString());

		// add call args nodes for interprocedural analysis
		if ((pcode.getOpcode() == PcodeOp.CALL || pcode.getOpcode() == PcodeOp.CALLIND)
				&& mstate.getCallArgs(pcode.getSeqnum()) != null) {
			Function f = this.currentProgram.getFunctionManager().getFunctionAt(pcode.getInput(0).getAddress());
			if (f == null)
				return null;
			String callee = f.getName();
			if (f.isThunk()) {
				callee = callee + "_thunk";
				if (stringAndLibcallID.containsKey(callee)) {
					int id = stringAndLibcallID.get(callee);
					addEdges(id, lineId, 3);
				} else {
					int id = lineId + numberOfAddedNodes;
					stringAndLibcallID.put(callee, id);
					printedNodes.add(String.valueOf(id) + "|&|" + callee + "|&|libcall|&|LIBCALL|&|null|&|null");
					addEdges(id, lineId, 3);
					numberOfAddedNodes++;
				}
			}
			if (!callee.startsWith("FUN_")) {
				if (this.duplicateFuncNames.contains(callee))
					callee = f.getPrototypeString(false, false).replace(' ', '_').replace(f.getName(), f.getName(true));
				calleeValue = "libcall_" + callee;
			} else {
				calleeValue = "func";
			}
			for (int i = 1; i < pcode.getNumInputs(); ++i) {
				Node input = mstate.getVnodeValue(pcode.getInput(i), false);
				String type = pcode.getInput(i).getHigh().getDataType().toString();
				if (type.contains("\n"))
					type = type.split("\n")[0];
				printedNodes.add(String.valueOf(lineId + numberOfAddedNodes) + "|&|" + calleeValue + "_arg"
						+ String.valueOf(i) + "|&|" + type + "|&|" + input.toString() + "|&|null|&|null");
				addEdges(lineId, lineId + numberOfAddedNodes, 3);
				if (cuNodes.containsKey(callee) && cuNodes.get(callee).containsKey("ARG" + String.valueOf(i))) {
					int targetArgId = cuNodes.get(callee).get("ARG" + String.valueOf(i));
					addEdges(lineId + numberOfAddedNodes, targetArgId, 3);
				}
				// add edges from def to args
				PcodeOp defI = pcode.getInput(i).getDef();
				if (defI != null) {
					int defId = getLineId(defI, pdgNodes, mstate, hfunction);
					addEdges(defId, lineId + numberOfAddedNodes, 2);
				}
				numberOfAddedNodes++;
			}
			Node retNode = handleCallPcode(pcode, mstate);
			if (retNode != null && pcode.getOutput() != null) {
				String type = hfunction.getFunctionPrototype().getReturnType().toString();
				if (type.contains("\n"))
					type = type.split("\n")[0];
				printedNodes.add(String.valueOf(lineId + numberOfAddedNodes) + "|&|" + calleeValue + "_return" + "|&|"
						+ type + "|&|" + retNode.toString() + "|&|null|&|null");
				addEdges(lineId, lineId + numberOfAddedNodes, 3);
				if (cuNodes.containsKey(callee) && cuNodes.get(callee).containsKey("RETURN")) {
					int targetId = cuNodes.get(callee).get("RETURN");
					addEdges(targetId, lineId + numberOfAddedNodes, 3);
				}
				numberOfAddedNodes++;
			}
			if (cuNodes.containsKey(callee) && cuNodes.get(callee).containsKey("EntryNode")) {
				int targetArgId = cuNodes.get(callee).get("EntryNode");
				addEdges(lineId, targetArgId, 3);
			}
		}

		if (pcode.getOpcode() == PcodeOp.RETURN && cuNodes.get(functionName).containsKey("RETURN")) {
			// connect current node to return summary node
			int sumId = cuNodes.get(functionName).get("RETURN");
			addEdges(lineId, sumId, 3);
		}

		retValue.add(pcode.getMnemonic());

		// go over the inputs of the pcode
		if (pcode.getOutput() != null) {
			Varnode vnode = pcode.getOutput();
			String normalValue = mstate.getVnodeValue(vnode, false).toString();
			retValue.add(normalValue);
			if (vnode.isConstant()) {
				corpusStr += normalize(vnode, normalValue, lineId);
			} else if (Node.isPureDigital(normalValue)) {
				corpusStr += "CONST";
			} else
				corpusStr += normalValue;
			if (vnode != null && vnode.getHigh() != null) {
				typeStr.add(vnode.getHigh().getDataType().getName());
			}
		}

		corpusStr += " " + pcode.getMnemonic() + " ";
		if (pcode.getOpcode() == PcodeOp.CBRANCH) {
			Varnode vnode = pcode.getInput(1);
			String cond = mstate.getVnodeValue(vnode, true).toString();
			corpusStr += cond;
			if (vnode != null && vnode.getDef() != null) {
				for (int i = 0; i < vnode.getDef().getNumInputs(); i++) {
					retValue.add(mstate.getVnodeValue(vnode.getDef().getInput(i), false).toString());
				}
			}
			if (vnode != null && vnode.getHigh() != null) {
				typeStr.add(vnode.getHigh().getDataType().getName());
			}
		} else {
			for (int i = 0; i < pcode.getNumInputs(); i++) {
				Varnode vnode = pcode.getInput(i);
				if (calleeValue != null && i == 0) {
					corpusStr += calleeValue;
				} else {
					String normalValue = mstate.getVnodeValue(vnode, false).toString();
					retValue.add(normalValue);
					if (vnode.isConstant())
						corpusStr += normalize(vnode, normalValue, lineId);
					else if (Node.isPureDigital(normalValue)) {
						corpusStr += "CONST";
					}else
						corpusStr += normalValue;
				}
				if (i < pcode.getNumInputs() - 1) {
					corpusStr += " ";
				}
				if (vnode != null && vnode.getHigh() != null) {
					typeStr.add(vnode.getHigh().getDataType().getName());
				}
//			if (!vnode.getPCAddress().toString().equals("NO ADDRESS")) {
//				address.add(vnode.getPCAddress().toString());
//			}
			}
		}

		if (useVSA)
			corpus.put(pcode, corpusStr);
		else
			corpus.put(pcode, toString(pcode, hfunction.getLanguage()));
		String tokenStr = "";
		if (mstate.getMapping().containsKey(pcode)) {
			for (ClangToken t : mstate.getMapping().get(pcode)) {
				ClangLine l = t.getLineParent();
				int lineNum = l.getLineNumber();
				int index = l.indexOfToken(t);
				int columnNum = 0;
				for (int i = 0; i < index; i++) {
					columnNum += l.getToken(i).getText().length();
				}
				tokenStr += String.valueOf(lineNum) + ":" + String.valueOf(columnNum) + "@*@" + t.getText() + "@*@";
			}
		} else
			tokenStr = "null";
		if (calleeValue != null && calleeValue.contains("libcall_"))
//			return toString(typeStr.toArray()) + "|&|" + calleeValue + "|&|" + toString(address.toArray());
			retValue.add(calleeValue);
		if (pcode.getOpcode() == PcodeOp.CBRANCH)
			return toString(typeStr.toArray()) + "|&|" + pcode.getMnemonic() + "@@"
					+ toString(retValue.toArray()) + "|&|" + tokenStr + "|&|" + toString(address.toArray());
		else if (pcode.getOpcode() == PcodeOp.BOOL_AND || pcode.getOpcode() == PcodeOp.BOOL_OR
				|| pcode.getOpcode() == PcodeOp.FLOAT_EQUAL || pcode.getOpcode() == PcodeOp.FLOAT_NOTEQUAL
				|| pcode.getOpcode() == PcodeOp.FLOAT_LESS || pcode.getOpcode() == PcodeOp.FLOAT_LESSEQUAL
				|| pcode.getOpcode() == PcodeOp.INT_EQUAL || pcode.getOpcode() == PcodeOp.INT_NOTEQUAL
				|| pcode.getOpcode() == PcodeOp.INT_SLESS || pcode.getOpcode() == PcodeOp.INT_SLESSEQUAL
				|| pcode.getOpcode() == PcodeOp.INT_LESS || pcode.getOpcode() == PcodeOp.INT_LESSEQUAL)
			return toString(typeStr.toArray()) + "|&|" + "CMP@@" + toString(retValue.toArray()) + "|&|" + tokenStr
					+ "|&|" + toString(address.toArray());

		return toString(typeStr.toArray()) + "|&|" + pcode.getMnemonic() + "@@" + toString(retValue.toArray()) + "|&|"
				+ tokenStr + "|&|" + toString(address.toArray());
	}

	public String toString(Object[] array) {
		if (array.length == 0)
			return "null";
		String ret = "";
		for (int i = 0; i < array.length; i++) {
			ret += array[i].toString();
			if (i < array.length)
				ret += "##";
		}
		if (ret.contains("\n"))
			ret = ret.split("\n")[0];
		return ret;
	}

	public void addEdges(int src, int des, int type) {
		if (type == 1) {// control dep edge
			if (!cdEdges.containsKey(src)) {
				cdEdges.put(src, new HashSet<Integer>());
			}
			cdEdges.get(src).add(des);
		} else if (type == 2) {// data dep edge
			if (!ddedges.containsKey(src)) {
				ddedges.put(src, new HashSet<Integer>());
			}
			ddedges.get(src).add(des);
		} else { // added edge
			if (!extraEdges.containsKey(src)) {
				extraEdges.put(src, new HashSet<Integer>());
			}
			extraEdges.get(src).add(des);
		}
	}

	/**
	 * Store the pcode to printedNodes list, return the index in the list
	 * @param line, pcode that wants to store
	 * @param pdgNodes, already stored pcode
	 * @param mstate, stores the machine state, the values of all varnodes
	 * @param hfunction, the current high-level function
	 * @return
	 */
	public int getLineId(PcodeOp line, HashMap<PcodeOp, Integer> pdgNodes, MachineStatePCode mstate,
			HighFunction hfunction) {
		int lineId;
		if (!pdgNodes.containsKey(line)) {
			if (line.getOpcode()==PcodeOp.CALL || line.getOpcode() == PcodeOp.CALLIND) {
				// if it is a call instruction, get the defs pcode's id first
				for (int i = 1; i < line.getNumInputs(); ++i) {
					PcodeOp defI = line.getInput(i).getDef();
					if (defI == null)
						continue;
					getLineId(defI, pdgNodes, mstate, hfunction);
				}
			}
			lineId = printedNodes.size();
			pdgNodes.put(line, lineId);
			String value = getValueSet(line, mstate, lineId, hfunction, pdgNodes);
			printedNodes.add(String.valueOf(lineId) + "|&|" + corpus.get(line) + "|&|" + value);
			
//			printedNodes.add(String.valueOf(lineId) + "|&|" + line.getMnemonic() + "##" + corpus.get(corpus.size() - 1) + "|&|" + value);
		} else
			lineId = pdgNodes.get(line);

		return lineId;
	}

	public void getPDGIR(HighFunction hfunction, MachineStatePCode mstate) {
		
		HashMap<Varnode, HashSet<PcodeOp>> entryDDEdgesLine = new HashMap<Varnode, HashSet<PcodeOp>>();
		for (int i = 0; i < hfunction.getFunctionPrototype().getNumParams(); ++i) {
			if (hfunction.getFunctionPrototype().getParam(i).getHighVariable() == null)
				continue;
			Varnode key = hfunction.getFunctionPrototype().getParam(i).getHighVariable().getRepresentative();
			entryDDEdgesLine.put(key, new HashSet<PcodeOp>());
		}
		HashSet<PcodeOp> entryCDEdgesLine = new HashSet<PcodeOp>();
		HashMap<PcodeOp, HashSet<PcodeOp>> cdEdgesLine = new HashMap<PcodeOp, HashSet<PcodeOp>>();
		HashMap<PcodeOp, HashSet<PcodeOp>> ddEdgesLine = new HashMap<PcodeOp, HashSet<PcodeOp>>();
		HashMap<PcodeOpAST, HashMap<Address, TreeSet<String>>> switchEdges = new HashMap<PcodeOpAST, HashMap<Address, TreeSet<String>>>();

		ConstructDDG ddg = new ConstructDDG(decomplib, monitor, null);
		corpus = new HashMap<PcodeOp, String>();
		ddg.genPDGIR(currentProgram, hfunction, ddEdgesLine, entryDDEdgesLine, entryCDEdgesLine, cdEdgesLine, switchEdges);

		HashMap<PcodeOp, Integer> pdgNodes = new HashMap<PcodeOp, Integer>();
		// add entry node
		int rootId = printedNodes.size();
		String functionName = hfunction.getFunction().getName();
		cuNodes.put(functionName, new HashMap<String, Integer>());
		cuNodes.get(functionName).put("EntryNode", rootId);
		printedNodes.add(String.valueOf(rootId) + "|&|" + hfunction.getFunction().getName()
				+ "|&|FunctionEntry|&|null|&|null|&|null");
		// add return summary node
		if (mstate.getReturnValues().size() > 0) {
			cuNodes.get(functionName).put("RETURN", rootId + 1);
			String type = hfunction.getFunctionPrototype().getReturnType().toString();
			if (type.contains("\n"))
				type = type.split("\n")[0];
			printedNodes.add(String.valueOf(rootId + 1) + "|&|RETURN" + "|&|" + type + "|&|"
					+ toString(mstate.getReturnValues().toArray()) + "|&|null|&|null");
			addEdges(rootId, rootId + 1, 3);
		}

		for (Varnode arg : entryDDEdgesLine.keySet()) {
			// add arguments node
			String value;
			if (useVSA)
				value = mstate.getVnodeValue(arg, false).toString();
			else
				value = arg.toString(hfunction.getLanguage());
			int id = printedNodes.size();
			String type = arg.getHigh().getDataType().toString();
			if (type.contains("\n"))
				type = type.split("\n")[0];
			printedNodes.add(String.valueOf(id) + "|&|" + value + "|&|" + type + "|&|null|&|null|&|null");
			cuNodes.get(functionName).put(value, id);
			addEdges(rootId, id, 2);
			// from arguments to the use of arguments
			for (PcodeOp line : entryDDEdgesLine.get(arg)) {
				int lineId = getLineId(line, pdgNodes, mstate, hfunction);
				addEdges(id, lineId, 2);
			}
		}

		for (PcodeOp line : entryCDEdgesLine) {
			int lineId = getLineId(line, pdgNodes, mstate, hfunction);
			addEdges(rootId, lineId, 1);
		}

		for (PcodeOp src : cdEdgesLine.keySet()) {
			if (src == null)
				continue;
			int srcId = getLineId(src, pdgNodes, mstate, hfunction);
			for (PcodeOp des : cdEdgesLine.get(src)) {
				if (des == null)
					continue;
				int desId = getLineId(des, pdgNodes, mstate, hfunction);
				addEdges(srcId, desId, 1);

			}
		}

		for (PcodeOp src : ddEdgesLine.keySet()) {
			if (src == null)
				continue;
			int srcId = getLineId(src, pdgNodes, mstate, hfunction);
			for (PcodeOp des : ddEdgesLine.get(src)) {
				if (des == null)
					continue;
				int desId = getLineId(des, pdgNodes, mstate, hfunction);
				// src is dependent on des
				addEdges(desId, srcId, 2);

			}
		}
		
		for (PcodeOp src : switchEdges.keySet()) {
			int srcId = getLineId(src, pdgNodes, mstate, hfunction);
			HashMap<String, Integer> idMap = new HashMap<String, Integer>();
			for (Address addr : switchEdges.get(src).keySet()) {
				TreeSet<String> caseSet = switchEdges.get(src).get(addr);
				if (caseSet.size() == 0)
					continue;
				String value = "case " + String.join(" ", caseSet);
				int id;
				if (!idMap.containsKey(value)) {
					id = printedNodes.size();
					printedNodes.add(String.valueOf(id) + "|&|" + value + "|&|SwitchCase|&|null|&|null|&|null");
					idMap.put(value, id);
					// add control dependency from branchind to case
					addEdges(srcId, id, 1);
				} else {
					id = idMap.get(value);
				}
				
				
				Iterator<PcodeOpAST> itr2 = hfunction.getPcodeOps(addr);
				while (itr2.hasNext()) {
					PcodeOpAST pcode2 = itr2.next();
					if (pcode2.getOpcode() == PcodeOp.INDIRECT || pcode2.getOpcode() == PcodeOp.MULTIEQUAL)
						continue;
					int dstId = getLineId(pcode2, pdgNodes, mstate, hfunction);
					addEdges(id, dstId, 1);
				}
			}
		}
		printPDG(hfunction, rootId, pdgNodes);
	}

	public void printPDG(HighFunction hfunction, int rootId, HashMap<PcodeOp, Integer> pdgNodes) {

		String outputPath = this.getScriptArgs()[0] + "/" + currentProgram.getName();
		try {
			BufferedWriter out = new BufferedWriter(
					new OutputStreamWriter(new FileOutputStream(outputPath + "_nodelabel.txt", true)));
			BufferedWriter outCorpus = new BufferedWriter(
					new OutputStreamWriter(new FileOutputStream(outputPath + "_corpus.txt", true)));
			String name = hfunction.getFunction().getName();
			if (this.duplicateFuncNames.contains(name)) {
				Function func = hfunction.getFunction();
				name = func.getPrototypeString(false, false).replace(' ', '_').replace(func.getName(), func.getName(true));
			}
			out.write("#" + name);
			out.newLine();
			for (int i = rootId; i < printedNodes.size(); i++) {
				String line = printedNodes.get(i);
				out.write(line);
				out.newLine();
			}
			out.close();
			Iterator<PcodeOpAST> iter = hfunction.getPcodeOps();
			outCorpus.write("#" + name);
			outCorpus.newLine();
			while (iter.hasNext()) {
				PcodeOp p = iter.next();
				outCorpus.write(String.valueOf(pdgNodes.get(p)) + "##" +  corpus.get(p));
				outCorpus.newLine();
			}
			outCorpus.close();

			out = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(outputPath + "_edges.txt", true)));
			for (int i = rootId; i < printedNodes.size(); i++) {
				if (cdEdges.containsKey(i)) {
					for (int j : cdEdges.get(i)) {
						String e = String.valueOf(i) + ", " + String.valueOf(j) + ", 1";
						out.write(e);
						out.newLine();
					}
				}
				if (ddedges.containsKey(i)) {
					for (int j : ddedges.get(i)) {
						String e = String.valueOf(i) + ", " + String.valueOf(j) + ", 2";
						out.write(e);
						out.newLine();
					}
				}
				if (extraEdges.containsKey(i)) {
					for (int j : extraEdges.get(i)) {
						String e = String.valueOf(i) + ", " + String.valueOf(j) + ", 3";
						out.write(e);
						out.newLine();
					}
				}

			}
			out.close();
		} catch (Exception e) {

		}
	}

	public String normalize(Varnode vnode, String normalValue, int lineId) {
		String str = MachineStatePCode.identifyStrings(vnode);
		if (str != null) {
			if (stringAndLibcallID.containsKey(str)) {
				int id = stringAndLibcallID.get(str);
				addEdges(id, lineId, 3);
			} else {
				int id = printedNodes.size() + 1;
				stringAndLibcallID.put(str, id);
				printedNodes.add(String.valueOf(id) + "|&|" + str + "|&|string|&|STR|&|null|&|null");
				addEdges(id, lineId, 3);
			}
			return "STR";
		} else if (vnode.getOffset() < 1024 && vnode.getOffset() > -1024) {
			return normalValue;
		} else {
			return "CONST";
		}

	}

	public void getAllOuts(PcodeBlockBasic pBB, ArrayList<PcodeBlockBasic> bSet) {
		int neighbours = pBB.getOutSize();
		for (int i = 0; i < neighbours; i++) {
			PcodeBlockBasic out = (PcodeBlockBasic) pBB.getOut(i);
			if (bSet.contains(out))
				continue;
			bSet.add(out);
			getAllOuts(out, bSet);
		}
	}

	public boolean analyzePcodeOp(PcodeOp pcodeOp, MachineStatePCode mstate) {
//		printf(toString(pcodeOp, mstate.language));

		switch (pcodeOp.getOpcode()) {
		case PcodeOp.UNIMPLEMENTED:
			break;
		case PcodeOp.COPY:
			return mstate.setVnodeValue(pcodeOp.getOutput(), mstate.getVnodeValue(pcodeOp.getInput(0), false));
		case PcodeOp.LOAD:
			Node output = mstate.touchMemAddr(pcodeOp.getInput(1));
			output.setSize(pcodeOp.getOutput().getSize());
			Node oldOutput = mstate.getVnodeValue(pcodeOp.getOutput(), false);
			Node s = mstate.getVnodeValue(pcodeOp.getInput(1), false);
			if ((s.toString().indexOf("ARG") != -1 || s.toString().contains("Symbol"))
					&& !s.toString().contains("RSP")) {
				mstate.addLoads(pcodeOp.getSeqnum(), s);
//				System.out.println(pcodeOp.getSeqnum().toString() + " " + s.toString());
				mstate.setMemAccess(s, "load");
			}
			if (!oldOutput.toString().equals("VZERO") && !oldOutput.toString().equals(output.toString())) {
				if (output instanceof PhiNode) {
					((PhiNode) output).merge(oldOutput);
					return mstate.setVnodeValue(pcodeOp.getOutput(), output);
				}
				PhiNode newOutput = new PhiNode(output.getSize());
				newOutput.merge(output);
				newOutput.merge(oldOutput);
				return mstate.setVnodeValue(pcodeOp.getOutput(), newOutput);
			}
			return mstate.setVnodeValue(pcodeOp.getOutput(), output);
		case PcodeOp.STORE:
			output = mstate.getVnodeValue(pcodeOp.getInput(2), false);
			Node address = mstate.getVnodeValue(pcodeOp.getInput(1), false);
			if ((address.toString().indexOf("ARG") != -1 || address.toString().contains("Symbol"))
					&& !address.toString().contains("RSP")) {
				mstate.addSideEffect(address, output);
				mstate.setMemAccess(address, "store");
//				System.out
//						.println(pcodeOp.getSeqnum().toString() + " " + address.toString() + ": " + output.toString());
			}
			return mstate.setMemValue(pcodeOp.getInput(1), output, pcodeOp);
		case PcodeOp.BRANCH:
			break;
		case PcodeOp.CBRANCH:
//			String cond = mstate.getVnodeValue(pcodeOp.getInput(1), true).toString();
//			mstate.addConditions(pcodeOp.getSeqnum(), cond);
			break;
		case PcodeOp.BRANCHIND:
			break;
		case PcodeOp.CALL:
		case PcodeOp.CALLIND:
			Node retNode = handleCallPcode(pcodeOp, mstate);
			if (retNode != null)
				return mstate.setVnodeValue(pcodeOp.getOutput(), retNode);
			break;
		case PcodeOp.CALLOTHER:
			break;
		case PcodeOp.RETURN:
			if (pcodeOp.getNumInputs() > 1) {
				mstate.addReturns(pcodeOp.getSeqnum(), mstate.getVnodeValue(pcodeOp.getInput(1), false));
			}
			break;
		case PcodeOp.BOOL_AND:
		case PcodeOp.BOOL_OR:
		case PcodeOp.FLOAT_EQUAL:
		case PcodeOp.FLOAT_NOTEQUAL:
		case PcodeOp.FLOAT_LESS:
		case PcodeOp.FLOAT_LESSEQUAL:
		case PcodeOp.INT_EQUAL:
		case PcodeOp.INT_NOTEQUAL:
		case PcodeOp.INT_SLESS:
		case PcodeOp.INT_SLESSEQUAL:
		case PcodeOp.INT_LESS:
		case PcodeOp.INT_LESSEQUAL:
			Node input1 = mstate.getVnodeValue(pcodeOp.getInput(0), false);
			Node input2 = mstate.getVnodeValue(pcodeOp.getInput(1), false);
			output = new Node(input1, input2, pcodeOp.getMnemonic(), pcodeOp.getOutput().getSize());
			return mstate.setVnodeValue(pcodeOp.getOutput(), output);
		case PcodeOp.INT_ZEXT:
		case PcodeOp.INT_SEXT:
			return mstate.setVnodeValue(pcodeOp.getOutput(),
					mstate.getVnodeValue(pcodeOp.getInput(0), false).resize(pcodeOp.getOutput().getSize()));

		case PcodeOp.FLOAT_ADD:
		case PcodeOp.INT_CARRY:
		case PcodeOp.INT_SCARRY:
		case PcodeOp.INT_ADD:
			input1 = mstate.getVnodeValue(pcodeOp.getInput(0), false);
			input2 = mstate.getVnodeValue(pcodeOp.getInput(1), false);
			return mstate.setVnodeValue(pcodeOp.getOutput(), input1.add(input2));
		case PcodeOp.FLOAT_SUB:
		case PcodeOp.INT_SBORROW:
		case PcodeOp.INT_SUB:
			input1 = mstate.getVnodeValue(pcodeOp.getInput(0), false);
			input2 = mstate.getVnodeValue(pcodeOp.getInput(1), false);
			return mstate.setVnodeValue(pcodeOp.getOutput(), input1.sub(input2));
		case PcodeOp.SUBPIECE:
			input1 = mstate.getVnodeValue(pcodeOp.getInput(0), false);
			input2 = mstate.getVnodeValue(pcodeOp.getInput(1), false);
			return mstate.setVnodeValue(pcodeOp.getOutput(), input1.subpiece(input2));
		case PcodeOp.BOOL_NEGATE:
		case PcodeOp.INT_NEGATE:
			return mstate.setVnodeValue(pcodeOp.getOutput(), mstate.getVnodeValue(pcodeOp.getInput(0), false).neg());
		case PcodeOp.INT_2COMP:
		case PcodeOp.FLOAT_NEG:
			return mstate.setVnodeValue(pcodeOp.getOutput(), mstate.getVnodeValue(pcodeOp.getInput(0), false).neg()
					.add(new Node(null, null, "1", pcodeOp.getInput(0).getSize())));
		case PcodeOp.INDIRECT:
			if (pcodeOp.getInput(0).getSpace() == 53) {
				long offset = pcodeOp.getInput(0).getOffset();
				mstate.addStackOffset(pcodeOp.getInput(1).getOffset(), Long.toHexString(offset));
			}
		case PcodeOp.FLOAT_NAN:
		case PcodeOp.FLOAT_ABS:
		case PcodeOp.FLOAT_SQRT:
		case PcodeOp.FLOAT_INT2FLOAT:
		case PcodeOp.FLOAT_FLOAT2FLOAT:
		case PcodeOp.FLOAT_TRUNC:
		case PcodeOp.FLOAT_CEIL:
		case PcodeOp.FLOAT_FLOOR:
		case PcodeOp.FLOAT_ROUND:
			return mstate.setVnodeValue(pcodeOp.getOutput(), mstate.getVnodeValue(pcodeOp.getInput(0), false));
		case PcodeOp.PIECE:
			input1 = mstate.getVnodeValue(pcodeOp.getInput(0), false);
			input2 = mstate.getVnodeValue(pcodeOp.getInput(1), false);
			output = input1.piece(input2);
			return mstate.setVnodeValue(pcodeOp.getOutput(), output);
		case PcodeOp.BOOL_XOR:
		case PcodeOp.INT_XOR:
			input1 = mstate.getVnodeValue(pcodeOp.getInput(0), false);
			input2 = mstate.getVnodeValue(pcodeOp.getInput(1), false);
			mstate.setVnodeValue(pcodeOp.getOutput(), input1.xor(input2));
			break;
		case PcodeOp.INT_LEFT:
			input1 = mstate.getVnodeValue(pcodeOp.getInput(0), false);
			input2 = mstate.getVnodeValue(pcodeOp.getInput(1), false);
			return mstate.setVnodeValue(pcodeOp.getOutput(), input1.ls(input2));
		case PcodeOp.INT_RIGHT:
		case PcodeOp.INT_SRIGHT:
			input1 = mstate.getVnodeValue(pcodeOp.getInput(0), false);
			input2 = mstate.getVnodeValue(pcodeOp.getInput(1), false);
			return mstate.setVnodeValue(pcodeOp.getOutput(), input1.rs(input2));
		case PcodeOp.INT_AND:
			input1 = mstate.getVnodeValue(pcodeOp.getInput(0), false);
			input2 = mstate.getVnodeValue(pcodeOp.getInput(1), false);
			output = input1.and(input2);
			return mstate.setVnodeValue(pcodeOp.getOutput(), output);
		case PcodeOp.INT_OR:
			input1 = mstate.getVnodeValue(pcodeOp.getInput(0), false);
			input2 = mstate.getVnodeValue(pcodeOp.getInput(1), false);
			output = input1.or(input2);
			return mstate.setVnodeValue(pcodeOp.getOutput(), output);
		case PcodeOp.INT_MULT:
		case PcodeOp.FLOAT_MULT:
			input1 = mstate.getVnodeValue(pcodeOp.getInput(0), false);
			input2 = mstate.getVnodeValue(pcodeOp.getInput(1), false);
			return mstate.setVnodeValue(pcodeOp.getOutput(), input1.mul(input2));
		case PcodeOp.INT_DIV:
		case PcodeOp.INT_SDIV:
		case PcodeOp.FLOAT_DIV:
			input1 = mstate.getVnodeValue(pcodeOp.getInput(0), false);
			input2 = mstate.getVnodeValue(pcodeOp.getInput(1), false);
			return mstate.setVnodeValue(pcodeOp.getOutput(), input1.div(input2));
		case PcodeOp.INT_REM:
		case PcodeOp.INT_SREM:
			input1 = mstate.getVnodeValue(pcodeOp.getInput(0), false);
			input2 = mstate.getVnodeValue(pcodeOp.getInput(1), false);
			output = new Node(input1, input2, "%", input1.getSize());
			return mstate.setVnodeValue(pcodeOp.getOutput(), output);
		case PcodeOp.MULTIEQUAL:
//			 System.out.println(pcodeOp.toString());
			PhiNode outP = new PhiNode(pcodeOp.getOutput().getSize());
			for (int i = 0; i < pcodeOp.getNumInputs(); i++) {
				Node input = mstate.getVnodeValue(pcodeOp.getInput(i), false);
				// System.out.println(pcodeOp.getSeqnum().toString() + " Phi " + input);
				outP.merge(input);
			}

			return mstate.setVnodeValue(pcodeOp.getOutput(), outP);
		case PcodeOp.CAST:
			return mstate.setVnodeValue(pcodeOp.getOutput(), mstate.getVnodeValue(pcodeOp.getInput(0), false));
		case PcodeOp.PTRADD:
			Node add = mstate.getVnodeValue(pcodeOp.getInput(1), false)
					.mul(mstate.getVnodeValue(pcodeOp.getInput(2), false));
			return mstate.setVnodeValue(pcodeOp.getOutput(), mstate.getVnodeValue(pcodeOp.getInput(0), false).add(add));
		case PcodeOp.PTRSUB:
			Node sub = mstate.getVnodeValue(pcodeOp.getInput(0), false)
					.add(mstate.getVnodeValue(pcodeOp.getInput(1), false));
			return mstate.setVnodeValue(pcodeOp.getOutput(), sub);
		case PcodeOp.CPOOLREF:
		case PcodeOp.NEW:
		default:

		}
		return false;
	}

	public Node handleCallPcode(PcodeOp pcodeOp, MachineStatePCode mstate) {
		ArrayList<Node> callargs = new ArrayList<Node>();
		for (int i = 1; i < pcodeOp.getNumInputs(); ++i) {
			Node input = mstate.getVnodeValue(pcodeOp.getInput(i), false);
			callargs.add(input);
		}
		Function f = this.currentProgram.getFunctionManager().getFunctionAt(pcodeOp.getInput(0).getAddress());
		if (f == null)
			return null;
		String calleeName = f.getName();
		if (f.isThunk()) {
			calleeName = calleeName + "_thunk";
		}
		if (!calleeName.startsWith("FUN_")) {
			mstate.addStringsAndFunctions(calleeName);
		}
		String callee = calleeName + "@" + f.getEntryPoint().getOffset();
//        this.printf(callee);
		callargs.add(new Node(null, null, callee, 0));
		mstate.addCallArgs(pcodeOp.getSeqnum(), callargs);
		if (pcodeOp.getOutput() == null)
			return null;
		if (!this.mstateAll.containsKey(callee)) {
			File tempFile = new File("/tmp/" + callee);
			boolean exists = tempFile.exists();
			if (exists) {
				ObjectInputStream ois;
				try {
					ois = new ObjectInputStream(new FileInputStream(tempFile));
					MachineStatePartial obj = (MachineStatePartial) ois.readObject(); // cast is needed.
					ois.close();
					this.mstateAll.put(callee, obj);
				} catch (IOException | ClassNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

			}
		}
		if (this.mstateAll.containsKey(callee)) {
			TreeSet<String> returns = (TreeSet<String>) this.mstateAll.get(callee).returns.clone();
			if (returns.size() == 0)
				return new Node(null, null, "RFC", pcodeOp.getOutput().getSize());
			HashMap<Object, Node> argReplaceMap = new HashMap<Object, Node>();
			for (int i = 0; i < callargs.size() - 1; ++i) {
				argReplaceMap.put("ARG" + String.valueOf(i + 1), callargs.get(i));
			}
			argReplaceMap.put("Symbol", new Node(null, null, "Symbol", 8));
//            this.printf(this.mstateAll.get(callee).returns.toString());
			for (String s1 : this.mstateAll.get(callee).returns) {
				if (!argReplaceMap.containsKey(s1))
					continue;
				returns.remove(s1);
				Node n = argReplaceMap.get(s1);
				if (n == null || n.isConstant())
					continue;
				if (n.isLeaf() && n.getOperation().equals("RFC")) {
					returns.addAll(n.leafSet);
					continue;
				}
				if (n.isLeaf()) {
					returns.add(n.toString());
					continue;
				}
				if (n instanceof PhiNode) {
					returns.addAll(n.getLeafSet());
					continue;
				}
				n.recollectLeaf();
				returns.addAll(n.getLeafSet());
			}
			Node returnNode = new Node(null, null, "RFC", pcodeOp.getOutput().getSize());
			returnNode.leafSet = returns;
//			this.printf(returns.toString());
			return returnNode;
		}
		return new Node(null, null, "RFC", pcodeOp.getOutput().getSize());
	}

	/*
	 * set up the decompiler
	 */
	private DecompInterface setUpDecompiler(Program program) {
		DecompInterface decompInterface = new DecompInterface();

		DecompileOptions options;
		options = new DecompileOptions();
		PluginTool tool = state.getTool();
		if (tool != null) {
			OptionsService service = tool.getService(OptionsService.class);
			if (service != null) {
				ToolOptions opt = service.getOptions("Decompiler");
				options.grabFromToolAndProgram(null, opt, program);
			}
		}
		decompInterface.setOptions(options);
		decompInterface.toggleCCode(true);
		decompInterface.toggleSyntaxTree(true);
		decompInterface.setSimplificationStyle("decompile");

		return decompInterface;
	}

	private void collectSymbolDataRefenceLocations(HashMap<Address, Long> referringLocationSet) {
		SymbolTable symtab = this.currentProgram.getSymbolTable();
		SymbolIterator symiter = symtab.getAllSymbols(true);
		int count = 0;
		while (symiter.hasNext() && !this.monitor.isCancelled()) {
			Function func;
			Symbol sym = symiter.next();
			if (!sym.hasReferences())
				continue;
			Address addr = sym.getAddress();
			if (count == 0) {
				this.monitor.setMessage("looking at : " + addr);
			}
			count = (count + 1) % 1024;
			Data data = this.currentProgram.getListing().getDataAt(addr);
			if (data == null && (func = this.currentProgram.getFunctionManager().getFunctionAt(addr)) == null)
				continue;
			Reference[] refs = sym.getReferences(null);
			for (int i = 0; i < refs.length && !this.monitor.isCancelled(); ++i) {
				Reference ref = refs[i];
				if (ref.getReferenceType().isFlow() || !ref.isMemoryReference())
					continue;
				referringLocationSet.put(ref.getFromAddress(), ref.getToAddress().getOffset());
			}
		}
	}

	private void collectStringDataReferenceLocations() {
		DataIterator dataIter = this.currentProgram.getListing().getDefinedData(true);
		while (dataIter.hasNext() && !this.monitor.isCancelled()) {
			String stringdata;
			Data data = dataIter.next();
			DataType dt = data.getDataType();
			try {
				if (dt instanceof StringDataType) {
					stringdata = new String(data.getBytes(), StandardCharsets.US_ASCII);
				} else if (dt instanceof TerminatedStringDataType) {
					stringdata = new String(data.getBytes(), StandardCharsets.US_ASCII);
				} else if (dt instanceof StringUTF8DataType) {
					stringdata = new String(data.getBytes(), StandardCharsets.UTF_8);
				} else if (dt instanceof TerminatedUnicodeDataType) {
					stringdata = new String(data.getBytes(), StandardCharsets.UTF_16);
				} else if (dt instanceof TerminatedUnicode32DataType) {
					stringdata = new String(data.getBytes());
				} else if (dt instanceof UnicodeDataType) {
					stringdata = new String(data.getBytes(), StandardCharsets.UTF_16);
				} else {
					if (!(dt instanceof Unicode32DataType))
						continue;
					stringdata = new String(data.getBytes());
				}
			} catch (MemoryAccessException e) {
				e.printStackTrace();
				continue;
			}
			stringLocationMap.put(data.getAddress(), stringdata);
			ReferenceIterator refIter = this.currentProgram.getReferenceManager().getReferencesTo(data.getAddress());
			while (refIter.hasNext()) {
				Reference ref = refIter.next();
				if (!stringRefLocationSet.containsKey(ref.getFromAddress())) {
					stringRefLocationSet.put(ref.getFromAddress(), new HashMap());
				}
				stringdata = stringdata.replaceAll("\n", " ");
				stringdata = stringdata.strip();
				stringdata = stringdata.replaceAll("[^\\x20-\\x7e]", "");
				stringRefLocationSet.get(ref.getFromAddress()).put(data.getAddress().getOffset(), stringdata);
			}
		}
	}

	public ArrayList<Function> generateCallGraph(FunctionIterator funcs) {
		ArrayList<Function> functionList = new ArrayList<Function>();
		for (Function fun : funcs) {
			functionList.add(fun);
			System.out.println(fun.getName().toString());
		}
		Object[] visited = new Boolean[functionList.size()];
		Arrays.fill(visited, Boolean.FALSE);
		ArrayList<Function> stack = new ArrayList<Function>();
		ArrayList<Integer> depthArray = new ArrayList<Integer>();
		for (int i = 0; i < functionList.size(); ++i) {
			if (((Boolean) visited[i]).booleanValue())
				continue;
			this.sortFuncs(functionList, i, (Boolean[]) visited, stack, depthArray);
		}
		return stack;
	}

	public int sortFuncs(ArrayList<Function> bb, int vidx, Boolean[] visited, ArrayList<Function> stack,
			ArrayList<Integer> depthArray) {
		visited[vidx] = true;
		int depth = 0;
		Function curFunc = bb.get(vidx);
		Set<Function> neighbours = curFunc.getCalledFunctions(monitor);
		for (Function callee : neighbours) {
			int dst_id = bb.indexOf(callee);
			if (dst_id != -1 && callee != null && !visited[dst_id]) {
				int depth_tmp = sortFuncs(bb, dst_id, visited, stack, depthArray);
				if (depth_tmp > depth)
					depth = depth_tmp;
			}
		}
		String funcname = curFunc.isThunk() ? curFunc.getName() + "_thunk" : curFunc.getName();
		if (!this.targetFuncs.contains(funcname) && this.targetFuncs.size() > 0)
			return depth + 1;
		boolean setMaxDepth = false;
		if (this.getScriptArgs().length > 1 && this.getScriptArgs()[1].equals("True"))
			setMaxDepth = true;
		if (depth > 30 && setMaxDepth) {
			return depth + 1;
		} else {
			int index = 0;
			while (index < depthArray.size() && depth < depthArray.get(index))
				index++;
			stack.add(index, bb.get(vidx));
			depthArray.add(index, depth);
		}
		return depth + 1;
	}

	public void processWholeFile() {
		String targetFunctionName = "FUN_004057b0";
//		currentProgram.getImageBase().getOffset();
		DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
		LocalDateTime now = LocalDateTime.now();
		this.printf("Analyse begin: %s\n", dtf.format(now));
		this.decomplib = this.setUpDecompiler(this.currentProgram);
		if (!this.decomplib.openProgram(this.currentProgram)) {
			this.printf("Decompiler error: %s\n", new Object[] { this.decomplib.getLastMessage() });
			return;
		}

		this.printedNodes = new ArrayList<String>();
		this.cuNodes = new HashMap<String, HashMap<String, Integer>>();
		this.cdEdges = new HashMap<Integer, HashSet<Integer>>();
		this.extraEdges = new HashMap<Integer, HashSet<Integer>>();
		this.ddedges = new HashMap<Integer, HashSet<Integer>>();
		this.stringAndLibcallID = new HashMap<String, Integer>();
		this.duplicateFuncNames = new HashSet<String>();
		
		this.collectStringDataReferenceLocations();
		HashMap<Address, Long> refSymbolLocationMap = new HashMap<Address, Long>();
		this.collectSymbolDataRefenceLocations(refSymbolLocationMap);
		FunctionIterator functionManager = this.currentProgram.getFunctionManager().getFunctions(true);
		printCallGraph();

		if (this.getScriptArgs().length > 1 && this.getScriptArgs()[1].equals("DumpCG")) {
			return;
		}
		this.targetFuncs = new HashSet<String>();
		// delete the previous files
		String outputPath = this.getScriptArgs()[0] + "/" + currentProgram.getName();
		try {
			long imagebase = currentProgram.getImageBase().getOffset();
			BufferedWriter outIB = new BufferedWriter(
				new OutputStreamWriter(new FileOutputStream(outputPath + "_imagebase.txt")));
			outIB.write(String.valueOf(imagebase));
			outIB.close();
			BufferedWriter out = new BufferedWriter(
					new OutputStreamWriter(new FileOutputStream(outputPath + "_nodelabel.txt")));
			BufferedWriter outCorpus = new BufferedWriter(
					new OutputStreamWriter(new FileOutputStream(outputPath + "_corpus.txt")));
			BufferedWriter outEdges = new BufferedWriter(
					new OutputStreamWriter(new FileOutputStream(outputPath + "_edges.txt")));
			out.close();
			outCorpus.close();
			outEdges.close();
			try (BufferedReader br = new BufferedReader(new FileReader(outputPath + "_set.txt"))) {
				for (String line; (line = br.readLine()) != null;) {
					this.targetFuncs.add(line.strip());
				}
			}
		} catch (Exception e) {

		}
		ArrayList<Function> funcList = this.generateCallGraph(functionManager);
		
		for (int i = funcList.size() - 1; i >= 0; --i) {
			Function function = funcList.get(i);
//			if (!function.getName().equals(targetFunctionName))
//				continue;
			printf("Found target function %s @ 0x%x %s, %.2f\n",
					new Object[] { function.getName(), function.getEntryPoint().getOffset(),
							this.currentProgram.getName(),
							(double) (funcList.size() - i) * 1.0 / (double) funcList.size() });

			analyzeFunction(function, refSymbolLocationMap);
		}

		//exportAllFun(this.getScriptArgs()[0] + "/decompiled");
	}

	public void toDot(HighFunction hfunction, HashMap<PcodeOp, HashSet<PcodeOp>> ddgraph,
			HashMap<Address, HashSet<Address>> cdgraph, HashSet<Address> entryEdges, MachineStatePCode mstate) {
		try {
			BufferedWriter out = new BufferedWriter(new OutputStreamWriter(new FileOutputStream("g.txt")));
			Language language = hfunction.getLanguage();
			for (int i = 0; i < hfunction.getFunctionPrototype().getNumParams(); ++i) {
				Varnode key = hfunction.getFunctionPrototype().getParam(i).getHighVariable().getRepresentative();
				Iterator<PcodeOp> desc = key.getDescendants();
				while (desc.hasNext()) {
					PcodeOp use = desc.next();
					out.write("\"" + "Entry" + "\" -> \"" + toString(use, language) + "\"");
					out.newLine();
				}
			}
			for (Address cur : entryEdges) {
				Iterator<PcodeOpAST> itr = hfunction.getPcodeOps(cur);
				while (itr.hasNext()) {
					PcodeOpAST pcode = itr.next();
					out.write("\"" + "Entry" + "\" -> \"" + toString(pcode, language) + "\"[style=dotted]");
					out.newLine();
				}
			}
			for (PcodeOp cur2 : ddgraph.keySet()) {
				for (PcodeOp def : ddgraph.get(cur2)) {
					out.write("\"" + toString(def, language) + "\" -> \"" + toString(cur2, language) + "\"");
					out.newLine();
				}
			}
			for (Address cur : cdgraph.keySet()) {
				Iterator<PcodeOpAST> itr = hfunction.getPcodeOps(cur);
				PcodeOpAST last = null;
				while (itr.hasNext()) {
					last = itr.next();
				}
				if (last != null) {
					if (last.getOpcode() != 5) {
						continue;
					}
					for (Address dep : cdgraph.get(cur)) {
						Iterator<PcodeOpAST> itr2 = hfunction.getPcodeOps(dep);
						while (itr2.hasNext()) {
							PcodeOpAST pcode2 = itr2.next();
							out.write("\"" + toString(last, language) + "\" -> \"" + toString(pcode2, language)
									+ "\"[style=dotted]");
							out.newLine();
						}
					}
				}
			}
			out.write("}");
			out.close();
		} catch (Exception ex) {
		}
	}

	public String toString(PcodeOp p, Language l) {
		String s;
		if (p.getOutput() != null)
			s = p.getOutput().toString(l);
		else
			s = " ";
		s += " " + p.getMnemonic() + " ";
		for (int i = 0; i < p.getNumInputs(); i++) {
			if (p.getInput(i) == null) {
				s += "null";
			} else {
				s += p.getInput(i).toString(l);
			}

			if (i < p.getNumInputs() - 1)
				s += " , ";
		}
//		s += " " + p.getSeqnum().toString();
		return s;
	}

	public void printCallGraph() {
		try {
			HashSet<String> funcSet = new HashSet<String>();
			for (Function func : this.currentProgram.getFunctionManager().getFunctions(true)) {
				if (func.isThunk())
					continue;
				else if (!funcSet.add(func.getName())) {
		            this.duplicateFuncNames.add(func.getName());
		        }
			}
			
			FileWriter myObj = new FileWriter(this.getScriptArgs()[0] + "/addr2funcname_stripped.txt");
			for (Function func : this.currentProgram.getFunctionManager().getFunctions(true)) {
				Object name = func.isThunk() ? func.getName() + "_thunk" : func.getName();
				if (this.duplicateFuncNames.contains(name))
					name = func.getPrototypeString(false, false).replace(' ', '_').replace(func.getName(), func.getName(true));
				myObj.append(func.getEntryPoint().getOffset() + ", " + (String) name + "\n");
			}
			myObj.close();
			myObj = new FileWriter(this.getScriptArgs()[0] + "/callgraph.txt");
			for (Function func : this.currentProgram.getFunctionManager().getFunctions(true)) {
				for (Function callee : func.getCalledFunctions(this.monitor)) {
					Object name = func.isThunk() ? func.getName() + "_thunk" : func.getName();
					Object calleename = callee.isThunk() ? callee.getName() + "_thunk" : callee.getName();
					if (this.duplicateFuncNames.contains(name))
						name = func.getPrototypeString(false, false).replace(' ', '_').replace(func.getName(), func.getName(true));
					if (this.duplicateFuncNames.contains(calleename))
						calleename = callee.getPrototypeString(false, false).replace(' ', '_').replace(callee.getName(), callee.getName(true));
					myObj.append((String) name + ", " + (String) calleename + "\n");
				}
			}
			for (Address addrRef : stringRefLocationSet.keySet()) {
				for (Long addrStr : stringRefLocationSet.get(addrRef).keySet()) {
					Function func = this.currentProgram.getFunctionManager().getFunctionContaining(addrRef);
					if (func == null) {
						Data rData = this.currentProgram.getListing().getDefinedDataAt(addrRef);
						if (rData == null || !rData.isPointer())
							continue;
						ReferenceIterator dataRefIter = rData.getReferenceIteratorTo();
						while (dataRefIter.hasNext()) {
							Reference dataRef = dataRefIter.next();
							func = this.currentProgram.getFunctionManager()
									.getFunctionContaining(dataRef.getFromAddress());
							if (func == null)
								continue;
							Object name = func.isThunk() ? func.getName() + "_thunk" : func.getName();
							if (this.duplicateFuncNames.contains(name))
								name = func.getPrototypeString(false, false).replace(' ', '_').replace(func.getName(), func.getName(true));
							String stringdata = stringRefLocationSet.get(addrRef).get(addrStr);
							myObj.append((String) name + ", string::" + stringdata + "\n");
						}
						continue;
					}
					Object name = func.isThunk() ? func.getName() + "_thunk" : func.getName();
					if (this.duplicateFuncNames.contains(name))
						name = func.getPrototypeString(false, false).replace(' ', '_').replace(func.getName(), func.getName(true));
					String stringdata = stringRefLocationSet.get(addrRef).get(addrStr);
					stringdata = stringdata.replaceAll("\n", " ");
					stringdata = stringdata.strip();
					stringdata = stringdata.replaceAll("[^\\x20-\\x7e]", "");
					myObj.append((String) name + ", string::" + stringdata + "\n");
				}
			}
			myObj.close();
		} catch (IOException e) {
			System.out.println("An error occurred.");
			e.printStackTrace();
		}
	}

	public void run() throws Exception {
		// currentProgram.setImageBase(toAddr(0), false);
		processWholeFile();
	}
}

