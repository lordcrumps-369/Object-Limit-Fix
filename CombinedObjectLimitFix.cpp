// Independent combined implementation. No EXE file reads, hashes, or filename gates.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "LayoutValidation.h"
extern "C" {
__declspec(dllexport) volatile LONG TS2_ObjectLimitFix_Status=0;
__declspec(dllexport) unsigned TS2_ObjectLimitFix_CompatibilityMode=1; // relevant in-memory code/layout
__declspec(dllexport) unsigned TS2_ObjectLimitFix_Version=10300;
}
namespace {
DWORD WINAPI Install(void*){
 TS2_ObjectLimitFix_Status=10;
 auto* image=(unsigned char*)GetModuleHandleW(nullptr);
 if(!image||!layout::Readable(image,sizeof(IMAGE_DOS_HEADER))){TS2_ObjectLimitFix_Status=combined::InvalidImage;return 0;}
 auto* dos=(IMAGE_DOS_HEADER*)image;
 if(dos->e_magic!=IMAGE_DOS_SIGNATURE||dos->e_lfanew<=0||dos->e_lfanew>0x1000||!layout::Readable(image+dos->e_lfanew,sizeof(IMAGE_NT_HEADERS32))){TS2_ObjectLimitFix_Status=combined::InvalidImage;return 0;}
 auto* nt=(IMAGE_NT_HEADERS32*)(image+dos->e_lfanew);
 TS2_ObjectLimitFix_Status=layout::Install(image,nt->OptionalHeader.SizeOfImage);
 return 0;
}
}
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID){
 if(reason==DLL_PROCESS_ATTACH){
  DisableThreadLibraryCalls(module);HANDLE thread=CreateThread(nullptr,0,Install,nullptr,0,nullptr);
  if(thread)CloseHandle(thread);else TS2_ObjectLimitFix_Status=combined::WorkerFailure;
 }
 return TRUE;
}
