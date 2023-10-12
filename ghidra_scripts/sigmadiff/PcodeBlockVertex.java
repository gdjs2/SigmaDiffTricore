import ghidra.program.model.pcode.PcodeBlockBasic;

public class PcodeBlockVertex {
	private final PcodeBlockBasic codeBlock;
	private final String name;

	/**
	 * Constructor.
	 * 
	 * @param codeBlock the code block for this vertex
	 */
	public PcodeBlockVertex(PcodeBlockBasic codeBlock, String name) {
		this.codeBlock = codeBlock;
		this.name = name;
	}

	/**
	 * A constructor that allows for the creation of dummy nodes. This is useful in
	 * graphs where multiple entry or exit points need to be parented by a single
	 * vertex.
	 * 
	 * @param name the name of this vertex
	 */
	public PcodeBlockVertex(String name) {
		this.codeBlock = null;
		this.name = name;
	}

	public PcodeBlockBasic getCodeBlock() {
		return codeBlock;
	}

	public String getName() {
		return name;
	}
}