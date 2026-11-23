#pragma once
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <array>
#include "fixture_bytes.h"
#include "guard_bytes.h"
// Independent implementation of the original guard behaviour and tested index correction.
// Original object-limit crash research/fix: Will/spockthewok and the user.
namespace combined {
static_assert(sizeof(void*)==4,"Build this ASI for x86");
enum Result:LONG {Active=1,AlreadyActive=2,UnsupportedExecutable=-1,Conflict=-2,ProtectionFailure=-3,InvalidImage=-4,WorkerFailure=-5,LegacyFilePresent=-6,CacheFailure=-7};
using ProtectFn=BOOL(WINAPI*)(LPVOID,SIZE_T,DWORD,PDWORD);
using FlushFn=BOOL(WINAPI*)(HANDLE,LPCVOID,SIZE_T);
struct Guard {unsigned site,cave,skip;unsigned char test;const unsigned char* native;};
inline const std::array<Guard,3>& Guards(){static const std::array<Guard,3> value={{{0x41101d,0xdd2eb0,0x41105c,0xf6,guardA},{0x410f45,0xdd2ec2,0x410f79,0xf6,guardB},{0x410e81,0xdd2ed4,0x410ec9,0xff,guardC}}};return value;}
inline void Relative(unsigned char* bytes,unsigned from,unsigned to){const std::uint32_t delta=to-from;std::memcpy(bytes,&delta,4);}
inline std::array<unsigned char,18> BuildGuard(const Guard& g){
 std::array<unsigned char,18> bytes{};
 bytes[0]=0x85;bytes[1]=g.test; // TEST ESI/EDI,ESI/EDI, preserving the original guard's flag effects.
 bytes[2]=0x0f;bytes[3]=0x84;Relative(bytes.data()+4,g.cave+8,g.skip);
 std::memcpy(bytes.data()+8,g.native,5); // Execute the displaced native instructions on non-null.
 bytes[13]=0xe9;Relative(bytes.data()+14,g.cave+18,g.site+5);
 return bytes;
}
struct Write {unsigned rva,length;std::array<unsigned char,18> before{},after{};};
using Plan=std::array<Write,9>;
inline Plan MakePlan(){
 Plan p{};const unsigned index[]={0x410e72,0x410f3a,0x411012};const unsigned char* source[]={site1+2,site2+2,site3+2};
 for(unsigned i=0;i<3;i++){p[i].rva=index[i];p[i].length=3;std::memcpy(p[i].before.data(),source[i],3);p[i].after[0]=0x8b;p[i].after[1]=i?0xcd:0xc5;p[i].after[2]=0x90;}
 for(unsigned i=0;i<3;i++){
  const auto& g=Guards()[i];auto& entry=p[3+i];entry.rva=g.site;entry.length=5;std::memcpy(entry.before.data(),g.native,5);entry.after[0]=0xe9;Relative(entry.after.data()+1,g.site+5,g.cave);
  auto& cave=p[6+i];cave.rva=g.cave;cave.length=18;cave.after=BuildGuard(g); // Verified original padding is zero.
 }
 return p;
}
inline Result Apply(unsigned char* image,size_t size,ProtectFn protect=VirtualProtect,FlushFn flush=FlushInstructionCache){
 if(!image||size<0xdd2ee6)return InvalidImage;
 if(std::memcmp(image+0x412130,getter,sizeof(getter)))return Conflict;
 const unsigned starts[]={0x410e70,0x410f38,0x411010};const unsigned char* sources[]={site1,site2,site3};
 for(unsigned i=0;i<3;i++)if(std::memcmp(image+starts[i],sources[i],2)||std::memcmp(image+starts[i]+5,sources[i]+5,6))return Conflict;
 for(const auto& g:Guards())if(std::memcmp(image+g.site+5,g.native+5,3))return Conflict;
 const Plan plan=MakePlan();bool original=true,patched=true;
 for(const auto& w:plan){original=original&&!std::memcmp(image+w.rva,w.before.data(),w.length);patched=patched&&!std::memcmp(image+w.rva,w.after.data(),w.length);}
 if(patched)return AlreadyActive;
 if(!original)return Conflict;
 SYSTEM_INFO info;GetSystemInfo(&info);const auto mask=~(std::uintptr_t)(info.dwPageSize-1);
 std::array<void*,9> pages{};std::array<DWORD,9> old{};unsigned pageCount=0;
 for(const auto& w:plan){void* page=(void*)((std::uintptr_t)(image+w.rva)&mask);bool found=false;for(unsigned i=0;i<pageCount;i++)found=found||pages[i]==page;if(!found)pages[pageCount++]=page;}
 for(unsigned i=0;i<pageCount;i++)if(!protect(pages[i],info.dwPageSize,PAGE_EXECUTE_READWRITE,&old[i])){
  for(unsigned j=0;j<i;j++){DWORD unused;if(!protect(pages[j],info.dwPageSize,old[j],&unused))VirtualProtect(pages[j],info.dwPageSize,old[j],&unused);}return ProtectionFailure;
 }
 // All pages are writable before any code is touched. Publish stubs before branches.
 for(unsigned i=6;i<9;i++)std::memcpy(image+plan[i].rva,plan[i].after.data(),plan[i].length);
 bool cacheOK=flush(GetCurrentProcess(),image+0xdd2eb0,54)!=FALSE;
 if(cacheOK)for(unsigned i=0;i<6;i++)std::memcpy(image+plan[i].rva,plan[i].after.data(),plan[i].length);
 if(cacheOK)for(unsigned i=0;i<pageCount;i++)if(!flush(GetCurrentProcess(),pages[i],info.dwPageSize))cacheOK=false;
 bool restoreOK=true;
 if(cacheOK)for(unsigned i=0;i<pageCount;i++){DWORD unused;if(!protect(pages[i],info.dwPageSize,old[i],&unused))restoreOK=false;}
 if(!cacheOK||!restoreOK){
  bool writable=true;for(unsigned i=0;i<pageCount;i++){DWORD unused;if(!VirtualProtect(pages[i],info.dwPageSize,PAGE_EXECUTE_READWRITE,&unused))writable=false;}
  if(writable){for(const auto& w:plan)std::memcpy(image+w.rva,w.before.data(),w.length);for(unsigned i=0;i<pageCount;i++)FlushInstructionCache(GetCurrentProcess(),pages[i],info.dwPageSize);}
  for(unsigned i=0;i<pageCount;i++){DWORD unused;VirtualProtect(pages[i],info.dwPageSize,old[i],&unused);}return cacheOK?ProtectionFailure:CacheFailure;
 }
 return Active;
}
}
