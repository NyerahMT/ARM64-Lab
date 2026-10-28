// @category MXBikes
// Private, metadata-only independent corroboration of three native-linked
// MX Bikes code bodies. Never exports instructions, bytes, strings, or pseudocode.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.address.Address;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class MxLinkedBodiesVerify extends GhidraScript {
    final long[] beginnings={0x2412e0L,0x241960L,0x15c240L};
    final long[] exclusiveEnds={0x2412f7L,0x241977L,0x15c269L};
    final int[] expectedInstructionCounts={6,6,12};
    final long expectedCallee=0x15c240L;

    static String q(String str) {
        return "\"" + str.replace("\\","\\\\").replace("\"","\\\"")
            .replace("\n","\\n").replace("\r","\\r") + "\"";
    }
    String rva(Address a) {
        if (a==null) return "unknown";
        try { return "0x"+Long.toHexString(a.subtract(currentProgram.getImageBase())); }
        catch(Exception exception) {return "external";}
    }
    @Override public void run() throws Exception {
        String[] argv=getScriptArgs();
        if(argv.length!=1) throw new IllegalArgumentException("Expected only output metadata path");
        Path out=Path.of(argv[0]).toAbsolutePath();
        Files.createDirectories(out.getParent());
        FunctionManager fm=currentProgram.getFunctionManager();
        List<String> entries=new ArrayList<>();
        boolean allEntryMatches=true;
        boolean allInstructionCounts=true;
        boolean allDirectCalls=true;
        for(int index=0;index<beginnings.length;index++) {
            Address at=currentProgram.getImageBase().add(beginnings[index]);
            Function f=fm.getFunctionAt(at);
            Function containing=fm.getFunctionContaining(at);
            boolean exact=f!=null && f.getEntryPoint().equals(at);
            allEntryMatches &= exact;
            int count=0;
            int calls=0;
            int callsToExpected=0;
            int jumps=0;
            long maximumExclusive=0L;
            boolean allInside=true;
            boolean isThunk=false;
            int bodyAddressCount=0;
            if(f!=null){
                isThunk=f.isThunk();
                bodyAddressCount=(int)Math.min(Integer.MAX_VALUE,f.getBody().getNumAddresses());
                InstructionIterator iterator=currentProgram.getListing().getInstructions(f.getBody(),true);
                while(iterator.hasNext() && count<1024 && !monitor.isCancelled()){
                    Instruction instruction=iterator.next();
                    count++;
                    long offset=instruction.getAddress().subtract(currentProgram.getImageBase());
                    long end=offset+instruction.getLength();
                    if(offset<beginnings[index] || end>exclusiveEnds[index])allInside=false;
                    maximumExclusive=Math.max(end,maximumExclusive);
                    if(instruction.getFlowType().isCall()){
                        calls++;
                        for(Address target:instruction.getFlows()){
                            if(rva(target).equals("0x"+Long.toHexString(expectedCallee)))
                                callsToExpected++;
                        }
                    }
                    if(instruction.getFlowType().isJump())jumps++;
                }
            }
            boolean instructionMatch=count==expectedInstructionCounts[index];
            allInstructionCounts &= instructionMatch && allInside && maximumExclusive==exclusiveEnds[index];
            if(index<2) allDirectCalls &= callsToExpected==1;
            else allDirectCalls &= calls==0;
            StringBuilder row=new StringBuilder();
            row.append("{\"requested_rva\":").append(q("0x"+Long.toHexString(beginnings[index])));
            row.append(",\"requested_unwind_end\":").append(q("0x"+Long.toHexString(exclusiveEnds[index])));
            row.append(",\"ghidra_exact_function_entry\":").append(exact);
            row.append(",\"ghidra_containing_function_rva\":")
                .append(q(containing==null?"none":rva(containing.getEntryPoint())));
            row.append(",\"ghidra_function_byte_count\":").append(bodyAddressCount);
            row.append(",\"ghidra_instruction_count\":").append(count);
            row.append(",\"matches_expected_instruction_count\":").append(instructionMatch);
            row.append(",\"all_recovered_instructions_inside_unwind\":").append(allInside);
            row.append(",\"recovered_exclusive_end\":").append(q("0x"+Long.toHexString(maximumExclusive)));
            row.append(",\"call_instruction_count\":").append(calls);
            row.append(",\"direct_calls_to_shared_callee\":").append(callsToExpected);
            row.append(",\"jump_instruction_count\":").append(jumps);
            row.append(",\"ghidra_thunk\":").append(isThunk);
            row.append("}");
            entries.add(row.toString());
        }
        String json="{\n"+
            "\"engine\":\"Ghidra 12.1.4 FunctionManager, private PE\",\n"+
            "\"all_three_exact_function_entries\":"+allEntryMatches+",\n"+
            "\"all_three_instruction_ranges_match_pdata\":"+allInstructionCounts+",\n"+
            "\"two_original_callers_directly_call_shared_callee\":"+allDirectCalls+",\n"+
            "\"code_bodies\":["+String.join(",",entries)+"],\n"+
            "\"limitations\":\"Independent static function recovery, not whole program or original code execution. No binary bytes or decompilation exported.\"\n"+
            "}\n";
        Files.writeString(out,json,StandardCharsets.UTF_8);
        println("MX_LINKED_GHIDRA_METADATA_WRITTEN="+out);
        println("MX_LINKED_EXACT_ENTRIES="+allEntryMatches);
        println("MX_LINKED_RANGE_MATCH="+allInstructionCounts);
        println("MX_LINKED_CALL_EDGES="+allDirectCalls);
    }
}
