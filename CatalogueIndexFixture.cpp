#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <array>
#include <climits>
#include "CombinedPatch.h"
using U=std::uint32_t;
using Fn=U(__stdcall*)(int,void*);
static_assert(sizeof(void*)==4,"Requires native x86 fixture");
struct Allocation {
 unsigned char* p;
 Allocation(const unsigned char* bytes,size_t n){p=(unsigned char*)VirtualAlloc(nullptr,4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);if(!p)ExitProcess(2);std::memcpy(p,bytes,n);DWORD old;if(!VirtualProtect(p,4096,PAGE_EXECUTE_READ,&old))ExitProcess(2);FlushInstructionCache(GetCurrentProcess(),p,n);}
 ~Allocation(){VirtualFree(p,0,MEM_RELEASE);}
};
static std::vector<unsigned char> wrapper(const unsigned char* site,size_t size,bool patched){
 // Preserve nonvolatile registers; load index into EBP and mock manager into EBX/EDI.
 std::vector<unsigned char> out={0x53,0x55,0x56,0x57,0x8b,0x6c,0x24,0x14,0x8b,0x5c,0x24,0x18,0x8b,0xfb};
 size_t start=out.size();out.insert(out.end(),site,site+size);
 if(patched){auto plan=combined::MakePlan();unsigned i=(site==site1?0u:site==site2?1u:2u);std::memcpy(out.data()+start+2,plan[i].after.data(),3);}
 const unsigned char end[]={0x5f,0x5e,0x5d,0x5b,0xc2,0x08,0x00};out.insert(out.end(),end,end+sizeof(end));return out;
}
int main(){
 Allocation lookup(getter,sizeof(getter));std::array<U,32> vtable{};vtable[0x34/4]=(U)lookup.p;
 std::array<unsigned char,0x100> manager{};*(U*)&manager[0]=(U)vtable.data();manager[0xc]=1;
 const unsigned char* sites[]={site1,site2,site3};unsigned long long checks=0,regressions=0,corrected=0;
 for(int which=0;which<3;which++){
  auto a=wrapper(sites[which],11,false),b=wrapper(sites[which],11,true);Allocation original(a.data(),a.size()),fixed(b.data(),b.size());Fn native=(Fn)original.p,patch=(Fn)fixed.p;
  for(U primaryCount:{0u,1u,32767u,32768u,32769u,50000u,65535u,65536u,70000u})for(U secondaryCount:{0u,1u,35000u}){
   std::vector<U> primary(primaryCount),secondary(secondaryCount);for(U i=0;i<primaryCount;i++)primary[i]=0x20000000u+i*8;for(U i=0;i<secondaryCount;i++)secondary[i]=0x40000000u+i*8;
   std::array<U,2> secondaryHeader={(U)secondary.data(),(U)(secondary.data()+secondary.size())};
   *(U*)&manager[0x4c]=(U)primary.data();*(U*)&manager[0x50]=(U)(primary.data()+primary.size());*(U*)&manager[0x68]=secondaryCount?(U)secondaryHeader.data():0;
   U total=primaryCount+secondaryCount;
   auto expected=[&](int index)->U{if(index<0||(U)index>=total)return 0;if((U)index<primaryCount)return primary[index];return secondary[index-primaryCount];};
   for(U i=0;i<total+2;i++){
    U before=native((int)i,manager.data()),after=patch((int)i,manager.data());
    if(before!=expected((std::int16_t)i)||after!=expected((int)i)){std::printf("FAIL site=%d index=%u primary=%u secondary=%u before=%08x after=%08x expected=%08x\n",which,i,primaryCount,secondaryCount,before,after,expected(i));return 1;}
    if(i<32768&&before!=after)regressions++;
    if(before!=after)corrected++;
    checks++;
   }
   for(int invalid:{-1,-32768,INT_MIN,INT_MAX}){if(patch(invalid,manager.data())!=expected(invalid))return 1;checks++;}
   manager[0xc]=0;for(int index:{0,32767,32768,65535,65536}){if(patch(index,manager.data())||native(index,manager.data()))return 1;checks++;}manager[0xc]=1;
  }
 }
 std::printf("PASS %llu native-x86 lookup checks across all three actual call sequences and the original getter\n",checks);
 std::printf("PASS %llu behaviour differences explained by the removed signed-16 truncation; below-boundary regressions=%llu\n",corrected,regressions);
 std::puts("PASS primary and secondary arrays, indices crossing 32768 and 65536, invalid indices and disabled manager");
 std::puts("Fixture only: does not establish live catalogue selection, placement, Sim behaviour or save compatibility.");return regressions?1:0;
}
