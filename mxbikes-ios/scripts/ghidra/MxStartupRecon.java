// @category MXBikes
// Metadata-only headless reconnaissance. Do not export proprietary bytes or decompilation.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.HashMap;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class MxStartupRecon extends GhidraScript {
    static class Node {
        final Function func;
        final int depth;
        Node(Function func, int depth) { this.func = func; this.depth = depth; }
    }

    static String quote(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r") + "\"";
    }

    String rva(Address address) {
        if (address == null) return "unknown";
        if (!address.getAddressSpace().equals(currentProgram.getImageBase().getAddressSpace())) {
            return "external@" + address.toString();
        }
        long delta = address.subtract(currentProgram.getImageBase());
        return "0x" + Long.toHexString(delta);
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("Pass one metadata output JSON path");
        Path output = Path.of(args[0]).toAbsolutePath();
        Files.createDirectories(output.getParent());

        FunctionManager funcs = currentProgram.getFunctionManager();
        FunctionIterator it = funcs.getFunctions(true);
        int total = 0, thunks = 0, externals = 0;
        while (it.hasNext() && !monitor.isCancelled()) {
            Function f = it.next();
            total++;
            if (f.isThunk()) thunks++;
            if (f.isExternal()) externals++;
        }

        // PE entry RVA is already verified with the read-only PE inventory.
        // This is intentionally revision-specific; changed game builds should fail upstream.
        Address entryAddress = currentProgram.getImageBase().add(0x2ab31cL);
        Function entry = funcs.getFunctionContaining(entryAddress);
        if (entry == null) entry = funcs.getFunctionAt(entryAddress);

        final int maxNodes = 450;
        final int maxEdges = 2500;
        final int maxDepth = 5;
        ArrayDeque<Node> queue = new ArrayDeque<>();
        Set<String> seen = new HashSet<>();
        List<String> nodes = new ArrayList<>();
        List<String> edges = new ArrayList<>();
        int entryCalls = 0;
        long sampledInstructions = 0L;
        Map<String, Integer> mnemonicFrequency = new HashMap<>();
        if (entry != null) queue.addLast(new Node(entry, 0));

        while (!queue.isEmpty() && nodes.size() < maxNodes && edges.size() < maxEdges && !monitor.isCancelled()) {
            Node next = queue.removeFirst();
            Function fn = next.func;
            if (fn == null) continue;
            String key = fn.getEntryPoint().toString();
            if (!seen.add(key)) continue;
            String entryRva = rva(fn.getEntryPoint());
            int codeInstructions = 0;
            int callInstructions = 0;
            int jumpInstructions = 0;
            boolean instructionScanTruncated = false;
            if (!fn.isExternal()) {
                InstructionIterator instIterator = currentProgram.getListing()
                    .getInstructions(fn.getBody(), true);
                while (instIterator.hasNext() && !monitor.isCancelled()) {
                    if (codeInstructions >= 200000) {
                        instructionScanTruncated = true;
                        break;
                    }
                    Instruction ins = instIterator.next();
                    codeInstructions++;
                    sampledInstructions++;
                    if (ins.getFlowType().isCall()) callInstructions++;
                    if (ins.getFlowType().isJump()) jumpInstructions++;
                    String mnemonic = ins.getMnemonicString().toUpperCase();
                    mnemonicFrequency.put(mnemonic, mnemonicFrequency.getOrDefault(mnemonic, 0) + 1);
                }
            }
            String node = "{\"rva\":" + quote(entryRva) +
                    ",\"depth\":" + next.depth +
                    ",\"external\":" + fn.isExternal() +
                    ",\"thunk\":" + fn.isThunk() +
                    ",\"body_addresses\":" + fn.getBody().getNumAddresses() +
                    ",\"instruction_count\":" + codeInstructions +
                    ",\"call_instruction_count\":" + callInstructions +
                    ",\"jump_instruction_count\":" + jumpInstructions +
                    ",\"instruction_scan_truncated\":" + instructionScanTruncated + "}";
            nodes.add(node);
            if (next.depth >= maxDepth || fn.isExternal()) continue;
            try {
                Set<Function> called = fn.getCalledFunctions(monitor);
                if (next.depth == 0) entryCalls = called.size();
                for (Function callee : called) {
                    if (edges.size() >= maxEdges) break;
                    String to = rva(callee.getEntryPoint());
                    edges.add("{\"from\":" + quote(entryRva) + ",\"to\":" + quote(to) +
                            ",\"external\":" + callee.isExternal() +
                            (callee.isExternal() ? ",\"api\":" + quote(callee.getName(true)) : "") + "}");
                    if (next.depth < maxDepth && !seen.contains(callee.getEntryPoint().toString())) {
                        queue.addLast(new Node(callee, next.depth + 1));
                    }
                }
            } catch (Exception exception) {
                println("Unable to enumerate callees for " + entryRva + ": " + exception.getClass().getSimpleName());
            }
        }

        List<Map.Entry<String, Integer>> rankedMnemonics =
            new ArrayList<>(mnemonicFrequency.entrySet());
        rankedMnemonics.sort((a, b) -> {
            int countOrder = Integer.compare(b.getValue(), a.getValue());
            return countOrder == 0 ? a.getKey().compareTo(b.getKey()) : countOrder;
        });
        List<String> topMnemonics = new ArrayList<>();
        for (int i = 0; i < Math.min(50, rankedMnemonics.size()); i++) {
            Map.Entry<String, Integer> e = rankedMnemonics.get(i);
            topMnemonics.add("{\"mnemonic\":" + quote(e.getKey()) +
                             ",\"count\":" + e.getValue() + "}");
        }
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"engine\": \"Ghidra 12.1.4 headless\",\n");
        json.append("  \"image_base\": ").append(quote(currentProgram.getImageBase().toString())).append(",\n");
        json.append("  \"entry_rva\": \"0x2ab31c\",\n");
        json.append("  \"entry_function_found\": ").append(entry != null).append(",\n");
        json.append("  \"entry_function_rva\": ").append(quote(entry != null ? rva(entry.getEntryPoint()) : "unknown")).append(",\n");
        json.append("  \"discovered_functions\": ").append(total).append(",\n");
        json.append("  \"thunk_functions\": ").append(thunks).append(",\n");
        json.append("  \"external_functions\": ").append(externals).append(",\n");
        json.append("  \"direct_entry_callee_count\": ").append(entryCalls).append(",\n");
        json.append("  \"graph_node_limit\": ").append(maxNodes).append(",\n");
        json.append("  \"graph_edge_limit\": ").append(maxEdges).append(",\n");
        json.append("  \"graph_depth_limit\": ").append(maxDepth).append(",\n");
        json.append("  \"graph_node_count\": ").append(nodes.size()).append(",\n");
        json.append("  \"graph_edge_count\": ").append(edges.size()).append(",\n");
        json.append("  \"sampled_startup_instructions\": ").append(sampledInstructions).append(",\n");
        json.append("  \"unique_mnemonics\": ").append(mnemonicFrequency.size()).append(",\n");
        json.append("  \"top_mnemonics\": [").append(String.join(",", topMnemonics)).append("],\n");
        json.append("  \"graph_nodes\": [").append(String.join(",", nodes)).append("],\n");
        json.append("  \"graph_edges\": [").append(String.join(",", edges)).append("],\n");
        json.append("  \"scope\": \"Addresses and structure only; no executable bytes, code, or decompilation. Static calls are not proof of reachable game execution.\"\n");
        json.append("}\n");
        Files.writeString(output, json.toString(), StandardCharsets.UTF_8);
        println("MX_STARTUP_METADATA_WRITTEN=" + output);
        println("MX_ENTRY_FUNCTION_FOUND=" + (entry != null));
        println("MX_DISCOVERED_FUNCTIONS=" + total);
        println("MX_GRAPH_NODES=" + nodes.size());
        println("MX_GRAPH_EDGES=" + edges.size());
        println("MX_SAMPLED_INSTRUCTIONS=" + sampledInstructions);
    }
}
