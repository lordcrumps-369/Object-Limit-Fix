#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include "CombinedPatch.h"
static int pc=0,pfail=0,fc=0,ffail=0;
static BOOL WINAPI ProtectTest(LPVOID a,SIZE_T n,DWORD p,PDWORD old){if(++pc==pfail){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}return VirtualProtect(a,n,p,old);}
static BOOL WINAPI FlushTest(HANDLE p,LPCVOID a,SIZE_T n){if(++fc==ffail){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}return FlushInstructionCache(p,a,n);}
static void require(bool ok,const char* text){if(!ok){std::printf("FAIL %s\n",text);ExitProcess(1);}std::printf("PASS %s\n",text);}
static void seed(unsigned char* image,size_t size){
 std::memset(image,0,size);std::memcpy(image+0x412130,getter,sizeof(getter));
 std::memcpy(image+0x410e70,site1,11);std::memcpy(image+0x410f38,site2,11);std::memcpy(image+0x411010,site3,11);
 for(const auto& g:combined::Guards())std::memcpy(image+g.site,g.native,8);
}
int main(int argc,char** argv){
 constexpr size_t size=0xdd3000;auto* image=(unsigned char*)VirtualAlloc(nullptr,size,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);if(!image)return 2;seed(image,size);
 auto plan=combined::MakePlan();
 require(combined::Apply(nullptr,size)==combined::InvalidImage&&combined::Apply(image,size-0x1000)==combined::InvalidImage,"invalid/truncated image refused");
 for(unsigned i=0;i<plan.size();i++){seed(image,size);image[plan[i].rva]^=1;std::vector<unsigned char> before(image,image+size);require(combined::Apply(image,size)==combined::Conflict&&!std::memcmp(image,before.data(),size),"each conflicting index, guard or cave refused without any writes");}
 seed(image,size);image[0x412131]^=1;std::vector<unsigned char> before(image,image+size);require(combined::Apply(image,size)==combined::Conflict&&!std::memcmp(image,before.data(),size),"modified getter refused");
 seed(image,size);std::memcpy(image+plan[0].rva,plan[0].after.data(),3);before.assign(image,image+size);require(combined::Apply(image,size)==combined::Conflict&&!std::memcmp(image,before.data(),size),"partial/legacy index installation refused without modifying it");
 for(int fail=1;fail<=6;fail++){
  seed(image,size);before.assign(image,image+size);pc=0;pfail=fail;
  require(combined::Apply(image,size,ProtectTest)==combined::ProtectionFailure&&!std::memcmp(image,before.data(),size),"page preparation/restore failure rolls back both fixes together");
 }
 for(int fail=1;fail<=4;fail++){
  seed(image,size);before.assign(image,image+size);fc=0;ffail=fail;
  require(combined::Apply(image,size,VirtualProtect,FlushTest)==combined::CacheFailure&&!std::memcmp(image,before.data(),size),"instruction-cache failure restores all original bytes");
 }
 seed(image,size);before.assign(image,image+size);require(combined::Apply(image,size)==combined::Active,"both fixes installed from original code");
 size_t changes=0;bool onlyPlanned=true;
 for(size_t i=0;i<size;i++)if(image[i]!=before[i]){changes++;bool planned=false;for(const auto& w:plan)planned=planned||(w.rva<=i&&i<w.rva+w.length);onlyPlanned=onlyPlanned&&planned;}
 bool exact=true;for(const auto& w:plan)exact=exact&&!std::memcmp(image+w.rva,w.after.data(),w.length);
 require(changes==78&&onlyPlanned&&exact,"exact combined plan: 9 index bytes, 15 branch bytes and 54 guard-stub bytes");
 before.assign(image,image+size);require(combined::Apply(image,size)==combined::AlreadyActive&&!std::memcmp(image,before.data(),size),"complete repeated installation idempotent");
 VirtualFree(image,0,MEM_RELEASE);
 if(argc>1){HMODULE module=LoadLibraryA(argv[1]);require(module!=nullptr,"single ASI loads in isolated host");auto* status=(volatile LONG*)GetProcAddress(module,"TS2_ObjectLimitFix_Status");require(status!=nullptr,"RAM-only status export present");auto* count=(unsigned*)GetProcAddress(module,"TS2_ObjectLimitFix_CompatibilityMode");require(count&&*count==1,"compiled ASI uses code-layout validation without a hash allowlist");for(int i=0;i<1000&&(*status==0||*status==10);i++)Sleep(10);LONG expected=argc>2?std::strtol(argv[2],nullptr,10):combined::InvalidImage;require(*status==expected,"unsupported executable or legacy-mod setup refused without patching host");}
 return 0;
}
