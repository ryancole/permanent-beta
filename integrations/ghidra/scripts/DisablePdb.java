// Pre-script for analyzeHeadless: turn every PDB analyzer off before analysis.
//
// The export measures Ghidra's own function discovery on a binary without symbols. Ghidra finds a PDB through the
// path in the executable's debug directory, even when the .exe was copied away from it, so the analyzers are
// switched off rather than relying on the PDB being absent (design §4.3, §4.4).
//@category PermanentBeta

import ghidra.app.script.GhidraScript;
import java.util.Map;

public class DisablePdb extends GhidraScript {
    @Override
    public void run() throws Exception {
        Map<String, String> options = getCurrentAnalysisOptionsAndValues(currentProgram);
        int disabled = 0;
        for (Map.Entry<String, String> e : options.entrySet()) {
            String name = e.getKey();
            // Analyzer on/off switches only ("PDB Universal"), not their sub-options ("PDB Universal.Search ...").
            boolean isSwitch = !name.contains(".")
                && ("true".equals(e.getValue()) || "false".equals(e.getValue()));
            if (name.startsWith("PDB") && isSwitch) {
                setAnalysisOption(currentProgram, name, "false");
                println("disabled analyzer: " + name);
                disabled++;
            }
        }
        if (disabled == 0) {
            throw new IllegalStateException("no PDB analyzer found to disable; Ghidra's option names changed?");
        }
    }
}
