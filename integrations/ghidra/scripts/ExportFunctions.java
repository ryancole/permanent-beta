// Post-script for analyzeHeadless: write Ghidra's functions as JSON for `pbeta analyze --functions-from`.
//
// Usage (script arguments): <out.json> [pseudocode]
//
// Writes boundaries, names and signatures with where each came from, and optionally decompiler pseudocode. It
// computes no hashes: Rust hashes every function from these boundaries, so hashes from Ghidra-based and native
// analyses are comparable (design §4.3). Which names and signatures are trusted is decided on the Rust side
// (permanent-beta-analysis/src/ghidra.rs), not here: this script writes what Ghidra has.
//@category PermanentBeta

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;

public class ExportFunctions extends GhidraScript {
    /** Decompiler time limit per function, in seconds. */
    private static final int DECOMPILE_TIMEOUT = 30;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException("usage: ExportFunctions.java <out.json> [pseudocode]");
        }
        boolean pseudocode = args.length > 1 && "pseudocode".equals(args[1]);
        long base = currentProgram.getImageBase().getOffset();

        DecompInterface decompiler = null;
        if (pseudocode) {
            decompiler = new DecompInterface();
            decompiler.openProgram(currentProgram);
        }

        int count = 0;
        try (Writer w = new OutputStreamWriter(new FileOutputStream(args[0]), StandardCharsets.UTF_8)) {
            w.write("{\n");
            w.write("  \"producer\": \"ghidra-export\",\n");
            w.write("  \"ghidra_version\": " + str(Application.getApplicationVersion()) + ",\n");
            w.write("  \"sha256\": " + str(currentProgram.getExecutableSHA256()) + ",\n");
            w.write("  \"image_base\": " + hex(base) + ",\n");
            w.write("  \"functions\": [");
            boolean first = true;
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                monitor.checkCancelled();
                if (f.isExternal()) {
                    continue;
                }
                StringBuilder o = new StringBuilder();
                o.append(first ? "\n" : ",\n").append("    {");
                o.append("\"entry\": ").append(hex(f.getEntryPoint().getOffset() - base));
                o.append(", \"body\": [");
                boolean firstRange = true;
                for (AddressRange r : f.getBody()) {
                    o.append(firstRange ? "" : ", ");
                    o.append("[").append(hex(r.getMinAddress().getOffset() - base)).append(", ")
                        .append(hex(r.getMaxAddress().getOffset() + 1 - base)).append("]");
                    firstRange = false;
                }
                o.append("]");
                o.append(", \"name\": ").append(str(f.getName()));
                o.append(", \"name_source\": ").append(str(f.getSymbol().getSource().name()));
                o.append(", \"thunk\": ").append(f.isThunk());
                o.append(", \"signature_source\": ").append(str(f.getSignatureSource().name()));
                o.append(", \"calling_convention\": ").append(str(f.getCallingConventionName()));
                o.append(", \"return_type\": ").append(str(f.getReturnType().getDisplayName()));
                o.append(", \"params\": [");
                Parameter[] params = f.getParameters();
                for (int i = 0; i < params.length; i++) {
                    o.append(i == 0 ? "" : ", ").append(str(params[i].getDataType().getDisplayName()));
                }
                o.append("]");
                if (decompiler != null) {
                    DecompileResults res = decompiler.decompileFunction(f, DECOMPILE_TIMEOUT, monitor);
                    String c = res.decompileCompleted() && res.getDecompiledFunction() != null
                        ? res.getDecompiledFunction().getC()
                        : null;
                    o.append(", \"pseudocode\": ").append(str(c));
                }
                o.append("}");
                w.write(o.toString());
                first = false;
                count++;
            }
            w.write("\n  ]\n}\n");
        } finally {
            if (decompiler != null) {
                decompiler.dispose();
            }
        }
        println("exported " + count + " functions to " + args[0]);
    }

    private static String hex(long v) {
        return "\"0x" + Long.toHexString(v) + "\"";
    }

    /** A JSON string literal, or null. */
    private static String str(String s) {
        if (s == null) {
            return "null";
        }
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
            }
        }
        return b.append('"').toString();
    }
}
