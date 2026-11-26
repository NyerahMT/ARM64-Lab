#include "mxb_observed_runtime.h"

#define MAX_BUDGET UINT64_C(16777216)

mxb_observed_result mxb_observed_run(mxb_observed_cpu *cpu,mxb_observed_step step,
                                     mxb_observed_import service,void *context,
                                     uint64_t stop,uint64_t budget){
    mxb_observed_result out={0,0,cpu?cpu->rip:0,MXB_RUN_INVALID};
    if(!cpu||!step||budget>MAX_BUDGET)return out;
    out.status=MXB_RUN_BUDGET;
    while(budget){
        if(stop&&cpu->rip==stop){out.status=MXB_RUN_STOP;break;}
        --budget;
        uint64_t pc=cpu->rip;
        int status=step(cpu);
        if(status==1){++out.instructions;continue;}
        if(status==2){
            if(cpu->rip!=pc){out.status=MXB_RUN_STEP_CONTRACT;break;}
            if(!service){out.status=MXB_RUN_UNKNOWN;break;}
            int serviced=service(context,cpu);
            if(serviced==1){
                if(cpu->rip==pc){out.status=MXB_RUN_IMPORT_NO_PROGRESS;break;}
                ++out.imports;continue;
            }
            if(serviced==0){
                out.status=cpu->rip==pc?MXB_RUN_UNKNOWN:MXB_RUN_STEP_CONTRACT;
                break;
            }
            out.status=serviced<0?serviced:MXB_RUN_STEP_CONTRACT;
            break;
        }
        out.status=status<0?status:MXB_RUN_STEP_CONTRACT;
        break;
    }
    if(out.status==MXB_RUN_BUDGET&&stop&&cpu->rip==stop)out.status=MXB_RUN_STOP;
    out.terminal_pc=cpu->rip;
    return out;
}
