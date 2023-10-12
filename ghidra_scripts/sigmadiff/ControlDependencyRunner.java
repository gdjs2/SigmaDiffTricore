import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;

import ghidra.graph.GDirectedGraph;
import ghidra.graph.GEdge;
import ghidra.graph.GraphAlgorithms;
import ghidra.graph.GraphFactory;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ControlDependencyRunner {
	private Program currentProgram;
	private TaskMonitor monitor;
	private BasicBlockModel bbm;
	private PcodeBlockVertex stopCB;
	HashSet<Address> entryEdges;
	Map<PcodeBlockBasic, PcodeBlockVertex> instanceMap;

	public ControlDependencyRunner(Program currentProgram, TaskMonitor monitor, BasicBlockModel bbm) {
		this.currentProgram = currentProgram;
		this.monitor = monitor;
		this.bbm = bbm;
	}

	public static <T> T getLastElement(Iterator<T> iterator) {
		T lastElement = null;
		while (iterator.hasNext()) {
			lastElement = iterator.next();
		}
		return lastElement;
	}

	public void generateCDG(ArrayList<PcodeBlockBasic> blocks, HashMap<Address, HashSet<Address>> graph, PcodeBlockBasic entry) {
		try {
			this.stopCB = new PcodeBlockVertex("STOP");
			this.entryEdges = new HashSet<Address>();
			this.instanceMap = new HashMap<PcodeBlockBasic, PcodeBlockVertex>();
			GDirectedGraph<PcodeBlockVertex, PcodeBlockBasicEdge> rcfg = this.createReverseCFG(blocks);
			GDirectedGraph<PcodeBlockVertex, GEdge<PcodeBlockVertex>> postDominanceTree = GraphAlgorithms
					.findDominanceTree(rcfg, this.monitor);
			for (PcodeBlockBasicEdge edge : rcfg.getEdges()) {
				PcodeBlockVertex desBB = edge.getStart();
				PcodeBlockVertex srcBB = edge.getEnd();
				if (!GraphAlgorithms.findDominance(rcfg, desBB, this.monitor).contains(srcBB)) {
					Iterator<PcodeOp> iter = srcBB.getCodeBlock().getIterator();
					Address terminator = getLastElement(iter).getSeqnum().getTarget();
					this.addControlDepFromDominatedBlockToDominator(terminator, srcBB, desBB, postDominanceTree, graph);
				}
			}
			this.addControlDepFromDominatedBlockToEntry(this.instanceMap.get(entry), postDominanceTree);
		} catch (Exception e1) {
			e1.printStackTrace();
		}
	}

	private PcodeBlockVertex containsAny(Collection<PcodeBlockVertex> srcBB, Collection<PcodeBlockVertex> desBB) {
		for (PcodeBlockVertex des : desBB) {
			if (srcBB.contains(des)) {
				return des;
			}
		}
		return null;
	}

	public void addControlDepFromDominatedBlockToEntry(PcodeBlockVertex entryBB,
			GDirectedGraph<PcodeBlockVertex, GEdge<PcodeBlockVertex>> postDominanceTree) {
		Collection<PcodeBlockVertex> dominatedBlock = new HashSet<PcodeBlockVertex>();
		dominatedBlock.add(entryBB);
		while (true) {
			Collection<PcodeBlockVertex> newDominatedBlock = new HashSet<PcodeBlockVertex>();
			for (PcodeBlockVertex pd : dominatedBlock) {
				if (pd == null)
					break;
				if (postDominanceTree.getPredecessors(pd) == null)
					newDominatedBlock.add(this.stopCB);
				else
					newDominatedBlock.addAll(postDominanceTree.getPredecessors(pd));
				PcodeBlockBasic block = pd.getCodeBlock();
				Iterator<PcodeOp> ins_iter = block.getIterator();
				while (ins_iter.hasNext()) {
					PcodeOp pcode = ins_iter.next();
					this.entryEdges.add(pcode.getSeqnum().getTarget());

				}
			}
			if (newDominatedBlock.contains(this.stopCB) || newDominatedBlock.isEmpty()) {
				break;
			}
			dominatedBlock = newDominatedBlock;
		}
	}

	public void addControlDepFromDominatedBlockToDominator(Address node, PcodeBlockVertex srcBB, PcodeBlockVertex desBB,
			GDirectedGraph<PcodeBlockVertex, GEdge<PcodeBlockVertex>> postDominanceTree,
			HashMap<Address, HashSet<Address>> graph) {
		Collection<PcodeBlockVertex> pdOfSrc = postDominanceTree.getPredecessors(srcBB);
		Collection<PcodeBlockVertex> dominatedBlock = new HashSet<PcodeBlockVertex>();
		dominatedBlock.add(desBB);
		PcodeBlockVertex nearestCommonDominator;
		// walk up along the Post Dominance Tree, start from desBB
		while (true) {
			Collection<PcodeBlockVertex> newDominatedBlock = new HashSet<PcodeBlockVertex>();
			for (PcodeBlockVertex pd : dominatedBlock) {
				newDominatedBlock.addAll(postDominanceTree.getPredecessors(pd));
				this.addControlDepFromNodeToBB(node, pd.getCodeBlock(), graph);
			}
			nearestCommonDominator = this.containsAny(pdOfSrc, newDominatedBlock);
			if (nearestCommonDominator != null) {
				break;
			}
			dominatedBlock = newDominatedBlock;
		}
		if (nearestCommonDominator.equals(srcBB)) {
			this.addControlDepFromNodeToBB(node, srcBB.getCodeBlock(), graph);
		}
	}

	public void addControlDepFromNodeToBB(Address node, PcodeBlockBasic block,
			HashMap<Address, HashSet<Address>> graph) {
		Iterator<PcodeOp> ins_iter = block.getIterator();
		if (!graph.containsKey(node)) {
			graph.put(node, new HashSet<Address>());
		}
		HashSet<Address> control = graph.get(node);
		while (ins_iter.hasNext()) {
			PcodeOp p = ins_iter.next();
			control.add(p.getSeqnum().getTarget());

		}
	}

	public void DFSUtil(GDirectedGraph<PcodeBlockVertex, PcodeBlockBasicEdge> graph, PcodeBlockVertex vertex, HashSet<PcodeBlockVertex> visited)
    {
        visited.add(vertex);                         //mark the node as explored
        
        for (PcodeBlockVertex succ : graph.getSuccessors(vertex))  //iterate through the linked list and then propagate to the next few nodes
            {
                if (!visited.contains(succ))                    //only propagate to next nodes which haven't been explored
                {
                    DFSUtil(graph, succ, visited);
                }
            }  
    }

	protected GDirectedGraph<PcodeBlockVertex, PcodeBlockBasicEdge> createReverseCFG(ArrayList<PcodeBlockBasic> blocks)
			throws CancelledException {
		GDirectedGraph<PcodeBlockVertex, PcodeBlockBasicEdge> graph = GraphFactory.createDirectedGraph();

		PcodeBlockBasic block = null;
		while (!blocks.isEmpty()) {
			block = blocks.remove(0);
			PcodeBlockVertex fromVertex = this.instanceMap.get(block);
			if (fromVertex == null) {
				fromVertex = new PcodeBlockVertex(block, block.toString());
				this.instanceMap.put(block, fromVertex);
				graph.addVertex(fromVertex);
			}
			this.addEdgesForDestinations(graph, fromVertex, block, blocks);
		}
		if (block != null && !graph.containsVertex(this.stopCB))
			graph.addEdge(new PcodeBlockBasicEdge(this.stopCB, this.instanceMap.get(block)));

		HashSet<PcodeBlockVertex> visited = new HashSet<PcodeBlockVertex>();
		DFSUtil(graph, this.stopCB, visited);
		for (PcodeBlockVertex v : graph.getVertices()) {
			if (!visited.contains(v)) {
				graph.addEdge(new PcodeBlockBasicEdge(this.stopCB, v));
			}
		}
		return graph;
	}

	private void addEdgesForDestinations(GDirectedGraph<PcodeBlockVertex, PcodeBlockBasicEdge> graph,
			PcodeBlockVertex fromVertex, PcodeBlockBasic sourceBlock, ArrayList<PcodeBlockBasic> blocks)
			throws CancelledException {
		boolean noDes = true;
		for (int i = 0; i < sourceBlock.getOutSize(); i++) {
			PcodeBlockBasic targetBlock = (PcodeBlockBasic) sourceBlock.getOut(i);
			if (targetBlock == null) {
				continue;
			}
//			Address start = targetBlock.getFirstStartAddress();
//			Symbol symbol = this.currentProgram.getSymbolTable().getPrimarySymbol(start);
//			if (symbol != null && !symbol.getName().startsWith("LAB_")) {
//				continue;
//			}
			PcodeBlockVertex targetVertex = this.instanceMap.get(targetBlock);
			if (targetVertex == null) {
				targetVertex = new PcodeBlockVertex(targetBlock, targetBlock.toString());
				this.instanceMap.put(targetBlock, targetVertex);
//				blocks.add(targetBlock);
			}
			if (!graph.containsVertex(targetVertex))
				graph.addVertex(targetVertex);
			if (targetVertex != fromVertex)
				noDes = false;
			if (graph.containsEdge(targetVertex, fromVertex)) {
				continue;
			}
			graph.addEdge(new PcodeBlockBasicEdge(targetVertex, fromVertex));
		}
		if (noDes) {
			graph.addEdge(new PcodeBlockBasicEdge(this.stopCB, fromVertex));
		}
	}
}
