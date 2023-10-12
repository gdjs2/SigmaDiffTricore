//
//@author 
//@category 
//@keybinding
//@menupath
//@toolbar

import java.io.FileWriter;
import java.io.IOException;
import java.util.HashSet;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class CollectGroundTruth extends GhidraScript {

	public void generateGroundTruth() {
		try {
			HashSet<String> funcSet = new HashSet<String>();
			HashSet<String> duplicateFuncNames = new HashSet<String>();
			for (Function func : this.currentProgram.getFunctionManager().getFunctions(true)) {
				if (func.isThunk())
					continue;
				else if (!funcSet.add(func.getName())) {
		            duplicateFuncNames.add(func.getName());
		        }
			}
			FileWriter myObj = new FileWriter(this.getScriptArgs()[0] + "/addr2funcname.txt");
			for (Function func : this.currentProgram.getFunctionManager().getFunctions(true)) {
				String name;
				if (func.isThunk()) {
					name = func.getName() + "_thunk";
				} else {
					name = func.getName();
				}
				if (duplicateFuncNames.contains(name))
					name = func.getPrototypeString(false, false).replace(' ', '_').replace(func.getName(), func.getName(true));
				myObj.append(func.getEntryPoint().getOffset() + ", " + name + "\n");
			}
			myObj.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}
	
	@Override
	protected void run() throws Exception {
		// currentProgram.setImageBase(toAddr(0), false);
		generateGroundTruth();
	}
}
