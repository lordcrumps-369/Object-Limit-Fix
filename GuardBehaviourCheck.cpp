#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <array>
#include <cstdint>
#include <cstring>
#include "CombinedPatch.h"
extern "C" {
std::uint32_t savedGuardESP=0,guardEntry=0,guardOutput=0,guardRoute=0;
void InvokeGuard(void* entry,std::uint32_t esi,std::uint32_t edi,std::uint32_t flags,std::uint32_t* out);
void CaptureGuard();
}
asm(
".text\n.globl _InvokeGuard\n_InvokeGuard:\n"
"pushfl\npushal\nmovl %esp,_savedGuardESP\n"
"movl 40(%esp),%eax\nmovl %eax,_guardEntry\nmovl 56(%esp),%eax\nmovl %eax,_guardOutput\n"
"movl 44(%esp),%esi\nmovl 48(%esp),%edi\npushl 52(%esp)\npopfl\n"
"movl $0x11223344,%ebx\nmovl $0x55667788,%eax\nmovl $0x99aabbcc,%edx\nmovl $0xaabbccdd,%ecx\nmovl $0xddeeff00,%ebp\njmp *_guardEntry\n"
".globl _CaptureGuard\n_CaptureGuard:\n"
"pushfl\npushal\nmovl %esp,%esi\nmovl _guardOutput,%edi\nmovl $9,%ecx\ncld\nrep movsl\n"
"movl _savedGuardESP,%esp\npopal\npopfl\nret\n");
static void jump(unsigned char* at,const void* target){at[0]=0xe9;std::uint32_t rel=(std::uint32_t)(std::uintptr_t)target-(std::uint32_t)(std::uintptr_t)(at+5);std::memcpy(at+1,&rel,4);}
static void route(unsigned char* at,unsigned value){at[0]=0xc7;at[1]=0x05;std::uint32_t target=(std::uint32_t)(std::uintptr_t)&guardRoute;std::memcpy(at+2,&target,4);std::memcpy(at+6,&value,4);jump(at+10,(void*)CaptureGuard);}
int main(){
 constexpr size_t size=0xdd3000;
 auto* reference=(unsigned char*)VirtualAlloc(nullptr,size,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);
 auto* merged=(unsigned char*)VirtualAlloc(nullptr,size,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);if(!reference||!merged)return 2;
 std::memcpy(merged+0x412130,getter,sizeof(getter));std::memcpy(merged+0x410e70,site1,11);std::memcpy(merged+0x410f38,site2,11);std::memcpy(merged+0x411010,site3,11);
 for(const auto& g:combined::Guards())std::memcpy(merged+g.site,g.native,8);
 if(combined::Apply(merged,size)!=combined::Active)return 1;
 unsigned cases=0;std::uint32_t object=0x13572468,otherObject=0x24681357;
 for(const auto& g:combined::Guards()){
  // Behavioural reference: the original guard's TEST/JZ, same displaced effects,
  // and same resume/skip addresses. Its equivalent MOV encoding is retained here.
  auto old=combined::BuildGuard(g);if(g.test!=(g.site==0x410e81?0xff:0xf6)){std::puts("FAIL incorrect pointer register in guard plan");return 1;}
  old[11]=0x89;old[12]=(g.test==0xf6?0xf1:0xf9);
  std::memcpy(reference+g.cave,old.data(),old.size());jump(reference+g.site,reference+g.cave);
  for(auto* image:{reference,merged}){route(image+g.site+5,1);route(image+g.skip,0);FlushInstructionCache(GetCurrentProcess(),image,size);}
  for(unsigned bits=0;bits<128;bits++)for(unsigned nonnull=0;nonnull<2;nonnull++)for(unsigned other=0;other<2;other++){
   const unsigned mask[]={1,4,0x10,0x40,0x80,0x400,0x800};unsigned flags=0x202;for(unsigned i=0;i<7;i++)if(bits&(1u<<i))flags|=mask[i];
   std::array<std::uint32_t,9> a{},b{};std::uint32_t ptr=nonnull?(std::uint32_t)(std::uintptr_t)&object:0;
   std::uint32_t alt=other?(std::uint32_t)(std::uintptr_t)&otherObject:0;
   bool usesEDI=(g.site==0x410e81);
   std::uint32_t esi=usesEDI?alt:ptr,edi=usesEDI?ptr:alt;
   InvokeGuard(reference+g.site,esi,edi,flags,a.data());a[3]-=savedGuardESP;unsigned oldRoute=guardRoute;
   InvokeGuard(merged+g.site,esi,edi,flags,b.data());b[3]-=savedGuardESP;
   if(a!=b||guardRoute!=oldRoute||guardRoute!=nonnull||b[3]!=(nonnull?0xfffffff8u:0xfffffffcu)){
    std::printf("FAIL guard=%x flags=%x pointer=%u route=%u/%u stack=%x/%x\n",g.site,flags,nonnull,oldRoute,guardRoute,a[3],b[3]);return 1;
   }
   if(nonnull&&(b[5]!=object||b[6]!=ptr)){std::puts("FAIL displaced native register effects");return 1;}
   cases++;
  }
 }
 std::printf("PASS %u native-x86 equivalence cases: all three guards, null/non-null, independent ESI/EDI, registers, flags, stack and exact skip/resume paths\n",cases);
 VirtualFree(reference,0,MEM_RELEASE);VirtualFree(merged,0,MEM_RELEASE);return 0;
}
