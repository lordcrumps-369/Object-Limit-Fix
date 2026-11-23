#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <fstream>
#include <vector>
#include <algorithm>
#include "CombinedPatch.h"
#include "LayoutValidation.h"
int main(int argc,char** argv){
 if(argc!=3)return 2;
 std::ifstream input(argv[1],std::ios::binary);std::vector<unsigned char> raw((std::istreambuf_iterator<char>(input)),{});
 if(raw.size()<4096)return 2;
 bool expected=std::strcmp(argv[2],"allow")==0;
 auto* dos=(IMAGE_DOS_HEADER*)raw.data();if(dos->e_magic!=IMAGE_DOS_SIGNATURE||dos->e_lfanew<0||(size_t)dos->e_lfanew+sizeof(IMAGE_NT_HEADERS32)>raw.size())return 2;
 auto* nt=(IMAGE_NT_HEADERS32*)(raw.data()+dos->e_lfanew);if(nt->Signature!=IMAGE_NT_SIGNATURE||nt->FileHeader.Machine!=IMAGE_FILE_MACHINE_I386||nt->OptionalHeader.Magic!=0x10b)return 2;
 size_t size=nt->OptionalHeader.SizeOfImage;if(size>128*1024*1024||size<nt->OptionalHeader.SizeOfHeaders||raw.size()<nt->OptionalHeader.SizeOfHeaders)return 2;
 auto* image=(unsigned char*)VirtualAlloc(nullptr,size,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);if(!image)return 2;
 std::memcpy(image,raw.data(),nt->OptionalHeader.SizeOfHeaders);
 auto* sections=IMAGE_FIRST_SECTION(nt);
 for(unsigned i=0;i<nt->FileHeader.NumberOfSections;i++){
  const auto& s=sections[i];if(s.VirtualAddress>=size||(size_t)s.PointerToRawData+s.SizeOfRawData>raw.size())return 2;
  size_t count=std::min<size_t>(s.SizeOfRawData,size-s.VirtualAddress);std::memcpy(image+s.VirtualAddress,raw.data()+s.PointerToRawData,count);
 }
 std::vector<unsigned char> before(image,image+size);auto plan=combined::MakePlan();SYSTEM_INFO info;GetSystemInfo(&info);std::vector<void*> pages;
 for(const auto& w:plan){void* page=(void*)((uintptr_t)(image+w.rva)&~(uintptr_t)(info.dwPageSize-1));if(std::find(pages.begin(),pages.end(),page)==pages.end())pages.push_back(page);}
 for(void* page:pages){DWORD old;if(!VirtualProtect(page,info.dwPageSize,PAGE_EXECUTE_READ,&old))return 2;}
 auto result=layout::Install(image,size);
 if(!expected){
  if(result==combined::Active||result==combined::AlreadyActive||std::memcmp(image,before.data(),size)){std::puts("FAIL unsupported image changed");return 1;}
  std::puts("PASS unsupported full PE image refused without code writes");VirtualFree(image,0,MEM_RELEASE);return 0;
 }
 if(result!=combined::Active){std::printf("FAIL supported full PE Apply=%ld\n",(long)result);return 1;}
 size_t changed=0;
 for(size_t i=0;i<size;i++)if(before[i]!=image[i]){
  changed++;bool allowed=false;for(const auto& w:plan)allowed=allowed||(w.rva<=i&&i<w.rva+w.length);
  if(!allowed){std::printf("FAIL non-target byte changed at %zx\n",i);return 1;}
 }
 if(changed!=78){std::printf("FAIL changed-byte count %zu\n",changed);return 1;}
 for(const auto& w:plan)if(std::memcmp(image+w.rva,w.after.data(),w.length)){std::puts("FAIL patch content");return 1;}
 for(void* page:pages){MEMORY_BASIC_INFORMATION m{};if(!VirtualQuery(page,&m,sizeof(m))||m.Protect!=PAGE_EXECUTE_READ){std::puts("FAIL original protection not restored");return 1;}}

 // Mutation coverage exercises the same layout validator used in production.
 for(const auto& r:layout::ranges){
  for(size_t index : {size_t(0),r.size/2,r.size-1}){
   unsigned rva=r.rva+(unsigned)index;bool target=false;
   for(const auto& w:plan)target=target||(rva>=w.rva&&rva-w.rva<w.length);
   if(target)continue;
   DWORD oldProtect;if(!VirtualProtect(image+rva,1,PAGE_EXECUTE_READWRITE,&oldProtect))return 2;
   image[rva]^=1;std::vector<unsigned char> altered(image,image+size);
   auto refusal=layout::Install(image,size);
   if(refusal!=combined::Conflict||std::memcmp(image,altered.data(),size)){std::puts("FAIL changed dependency was not refused without writes");return 1;}
   image[rva]^=1;DWORD unused;if(!VirtualProtect(image+rva,1,oldProtect,&unused))return 2;
  }
 }
 // Header checksum/LAA changes and an unrelated mapped-data change are allowed.
 auto* mappedNt=(IMAGE_NT_HEADERS32*)(image+dos->e_lfanew);
 mappedNt->OptionalHeader.CheckSum^=0x12345678;
 mappedNt->FileHeader.Characteristics^=IMAGE_FILE_LARGE_ADDRESS_AWARE;
 image[size-1]^=1;
 if(layout::Install(image,size)!=combined::AlreadyActive){std::puts("FAIL irrelevant changes rejected");return 1;}
 before.assign(image,image+size);if(layout::Install(image,size)!=combined::AlreadyActive||std::memcmp(image,before.data(),size)){std::puts("FAIL repeat application");return 1;}
 std::printf("PASS supported full PE: 78 planned bytes only; all other %zu mapped bytes, headers, code, data and page protections preserved; repeat application unchanged\n",size-78);
 VirtualFree(image,0,MEM_RELEASE);return 0;
}
