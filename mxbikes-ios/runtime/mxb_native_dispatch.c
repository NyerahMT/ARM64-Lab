#include "mxb_native_dispatch.h"

static int contains(const MXBNativeUnit*u,uint64_t pc){
 size_t lo=0,hi=u->count;
 while(lo<hi){size_t mid=lo+(hi-lo)/2u;if(u->pcs[mid]<pc)lo=mid+1u;else hi=mid;}
 return lo<u->count&&u->pcs[lo]==pc;
}
int mxb_native_registry_valid(const MXBNativeRegistry*r){
 if(!r||!r->units||!r->count||r->count>MXB_NATIVE_MAX_UNITS)return 0;
 for(size_t i=0;i<r->count;i++){
  const MXBNativeUnit*u=&r->units[i];
  if(!u->pcs||!u->count||u->count>MXB_NATIVE_MAX_UNIT_PCS||!u->resume)return 0;
  for(size_t j=0;j<u->count;j++)
   if(!u->pcs[j]||(j&&u->pcs[j]<=u->pcs[j-1u]))return 0;
  for(size_t k=0;k<i;k++){
   const MXBNativeUnit*v=&r->units[k];
   if(u->pcs[0]>v->pcs[v->count-1u]||v->pcs[0]>u->pcs[u->count-1u])continue;
   for(size_t j=0;j<u->count;j++)if(contains(v,u->pcs[j]))return 0;
  }
 }
 return 1;
}
int mxb_native_dispatch(const MXBNativeRegistry*r,MXBGuestState*s,
                       MXBNativeCursor*c,unsigned quota,uint64_t final_pc){
 if(!s||!c||s->fault||!final_pc)return MXB_NATIVE_MEMORY_FAULT;
 if(!mxb_native_registry_valid(r))return MXB_NATIVE_BAD_REGISTRY;
 while(c->pc!=final_pc){
  if(!quota)return MXB_NATIVE_YIELD;
  const MXBNativeUnit*unit=0;
  for(size_t i=0;i<r->count;i++)if(contains(&r->units[i],c->pc)){unit=&r->units[i];break;}
  if(!unit)return MXB_NATIVE_UNKNOWN_PC;
  unsigned before=c->steps;
  int rc=unit->resume(s,c,quota);
  if(rc!=MXB_NATIVE_DONE&&rc!=MXB_NATIVE_YIELD)return rc;
  if(c->steps<before||c->steps-before>quota||c->steps==before||s->fault)
   return MXB_NATIVE_BAD_PROGRESS;
  quota-=c->steps-before;
  if(rc==MXB_NATIVE_YIELD){
   if(quota||c->pc==final_pc)return MXB_NATIVE_BAD_PROGRESS;
   return MXB_NATIVE_YIELD;
  }
 }
 return MXB_NATIVE_DONE;
}
