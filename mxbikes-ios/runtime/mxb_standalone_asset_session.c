#define _POSIX_C_SOURCE 200809L
#include "mxb_standalone_asset_session.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
static int source_read(void *opaque,uint64_t offset,uint8_t *out,size_t n){
    mxb_asset_source *s=opaque;
    if(!s||s->fd<0||!out||n>MXB_FILE_CHUNK||offset>s->size||n>s->size-offset)return 0;
    size_t done=0;
    while(done<n){
        ssize_t count=pread(s->fd,out+done,n-done,(off_t)(offset+done));
        if(count<0&&errno==EINTR)continue;
        if(count<=0)return 0;
        done+=(size_t)count;
    }
    return 1;
}
int mxb_asset_session_init(mxb_asset_session *s,mxb_files *files){
    if(!s||!files||s->files)return 0;
    for(unsigned i=0;i<MXB_FILE_MOUNTS;i++)if(files->mounts[i].data||files->mounts[i].read_at)return 0;
    for(unsigned i=0;i<MXB_FILE_HANDLES;i++)if(files->handles[i].token)return 0;
    s->files=files;s->count=0;
    for(unsigned i=0;i<MXB_FILE_MOUNTS;i++){s->sources[i].fd=-1;s->sources[i].size=0;}
    return 1;
}
int mxb_asset_session_mount(mxb_asset_session *s,const char *name,const char *path,uint64_t expected_size){
    if(!s||!s->files||s->count>=MXB_FILE_MOUNTS||!name||!path||!path[0])return 0;
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    if(fd<0)return 0;
    struct stat st;
    if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_size<0||(uint64_t)st.st_size>MXB_FILE_MAX||
        (expected_size!=UINT64_MAX&&(uint64_t)st.st_size!=expected_size)){
        close(fd);return 0;
    }
    mxb_asset_source *src=&s->sources[s->count];
    src->fd=fd;src->size=(uint64_t)st.st_size;
    if(!mxb_files_mount_source(s->files,name,src->size,source_read,src)){
        close(fd);src->fd=-1;src->size=0;return 0;
    }
    s->count++;return 1;
}
void mxb_asset_session_close(mxb_asset_session *s){
    if(!s||!s->files)return;
    /* Preserve generation so old handle tokens cannot alias after reopening. */
    uint64_t generation=s->files->generation;
    *s->files=(mxb_files){0};s->files->generation=generation;
    for(unsigned i=0;i<s->count;i++){
        if(s->sources[i].fd>=0)close(s->sources[i].fd);
        s->sources[i].fd=-1;s->sources[i].size=0;
    }
    s->count=0;s->files=0;
}
