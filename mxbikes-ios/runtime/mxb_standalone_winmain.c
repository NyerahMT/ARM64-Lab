#include "mxb_standalone_winmain.h"
static int printable(uint8_t c){return c>32u&&c<=126u;}
int mxb_winmain_prepare(mxb_winmain_prefix *out,uint64_t entry_rsp,uint64_t cookie,
                         uint64_t instance,uint64_t previous,uint32_t show,
                         uint64_t guest_command,uint64_t argv0,
                         uint8_t *command,size_t size){
    if(!out||!command||!size||size>MXB_WINMAIN_MAX_COMMAND||
       !guest_command||guest_command>UINT64_MAX-size||!argv0||
       entry_rsp<0x288u||(entry_rsp&15u)!=8u)return 0;
    size_t end=0;
    while(end<size&&command[end])end++;
    if(end==size)return 0;
    mxb_winmain_prefix r={0};
    r.frame_rsp=entry_rsp-0x288u;
    r.saved_cookie=cookie^r.frame_rsp;
    r.instance=instance;r.previous_instance=previous;r.show=show;
    r.argc=1;r.argv[0]=argv0;
    size_t p=0;
    while(command[p]&&r.argc<MXB_WINMAIN_MAX_ARGS){
        while(command[p]&&!printable(command[p]))p++;
        if(!command[p])break;
        size_t close=p;
        if(command[p]=='"'){
            size_t q=p+1;
            while(command[q]>=32u&&command[q]<=126u){
                if(command[q]=='"'){close=q;break;}
                q++;
            }
        }
        if(close!=p){
            command[close]=0;
            r.argv[r.argc++]=guest_command+p+1;
            p=close+1;
        }else{
            r.argv[r.argc++]=guest_command+p;
            while(printable(command[p]))p++;
        }
        if(command[p])command[p++]=0;
    }
    *out=r;return 1;
}
int mxb_winmain_module_directory(uint8_t *out,size_t capacity,
                                 const uint8_t *path,size_t size){
    if(!out||!path||!size||capacity<MXB_WINMAIN_PATH_CAP||size>MXB_WINMAIN_PATH_CAP)return 0;
    size_t n=0,slash=SIZE_MAX,colon=SIZE_MAX;
    while(n<size&&path[n]){
        if(path[n]=='/'||path[n]=='\\')slash=n;
        if(path[n]==':')colon=n;
        n++;
    }
    if(n==size||(slash==SIZE_MAX&&colon!=SIZE_MAX&&colon+2>=MXB_WINMAIN_PATH_CAP))return 0;
    for(size_t i=0;i<=n;i++)out[i]=path[i];
    if(slash!=SIZE_MAX)out[slash+1]=0;
    else if(colon!=SIZE_MAX){out[colon+1]='\\';out[colon+2]=0;}
    else out[0]=0;
    return 1;
}
