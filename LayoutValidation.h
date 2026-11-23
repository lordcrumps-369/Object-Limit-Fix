#pragma once
#include "LayoutBytes.h"
namespace layout {
inline bool Readable(const unsigned char* address,size_t size){
 while(size){
  MEMORY_BASIC_INFORMATION m{};
  if(!VirtualQuery(address,&m,sizeof(m))||m.State!=MEM_COMMIT||(m.Protect&(PAGE_GUARD|PAGE_NOACCESS)))return false;
  DWORD p=m.Protect&0xff;
  if(p!=PAGE_READONLY&&p!=PAGE_READWRITE&&p!=PAGE_WRITECOPY&&p!=PAGE_EXECUTE_READ&&p!=PAGE_EXECUTE_READWRITE&&p!=PAGE_EXECUTE_WRITECOPY)return false;
  size_t available=(const unsigned char*)m.BaseAddress+m.RegionSize-address;
  size_t step=size<available?size:available;if(!step)return false;address+=step;size-=step;
 }
 return true;
}
inline combined::Result Validate(unsigned char* image,size_t size){
 if(!image||size<sizeof(IMAGE_DOS_HEADER)||!Readable(image,sizeof(IMAGE_DOS_HEADER)))return combined::InvalidImage;
 auto* dos=(IMAGE_DOS_HEADER*)image;
 if(dos->e_magic!=IMAGE_DOS_SIGNATURE||dos->e_lfanew<=0||dos->e_lfanew>0x1000)return combined::InvalidImage;
 size_t offset=(size_t)dos->e_lfanew;
 if(offset>size||sizeof(IMAGE_NT_HEADERS32)>size-offset||!Readable(image+offset,sizeof(IMAGE_NT_HEADERS32)))return combined::InvalidImage;
 auto* nt=(IMAGE_NT_HEADERS32*)(image+offset);
 if(nt->Signature!=IMAGE_NT_SIGNATURE||nt->FileHeader.Machine!=IMAGE_FILE_MACHINE_I386||nt->OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR32_MAGIC||nt->FileHeader.SizeOfOptionalHeader<sizeof(IMAGE_OPTIONAL_HEADER32)||nt->OptionalHeader.SizeOfImage!=size)return combined::InvalidImage;
 size_t sectionOffset=offset+24+nt->FileHeader.SizeOfOptionalHeader;
 size_t sectionBytes=(size_t)nt->FileHeader.NumberOfSections*sizeof(IMAGE_SECTION_HEADER);
 if(!sectionBytes||sectionOffset>size||sectionBytes>size-sectionOffset||!Readable(image+sectionOffset,sectionBytes))return combined::InvalidImage;
 auto* sections=(IMAGE_SECTION_HEADER*)(image+sectionOffset);
 auto inSection=[&](unsigned rva,size_t bytes,bool executable){
  if(rva>size||bytes>size-rva||!Readable(image+rva,bytes))return false;
  for(unsigned i=0;i<nt->FileHeader.NumberOfSections;i++){
   const auto& s=sections[i];size_t span=s.Misc.VirtualSize>s.SizeOfRawData?s.Misc.VirtualSize:s.SizeOfRawData;
   if(s.VirtualAddress>size||span>size-s.VirtualAddress)continue;
   if(rva>=s.VirtualAddress&&rva-s.VirtualAddress<=span&&bytes<=span-(rva-s.VirtualAddress)&&
      (s.Characteristics&IMAGE_SCN_MEM_READ)&&(!executable||(s.Characteristics&IMAGE_SCN_MEM_EXECUTE)))return true;
  }
  return false;
 };
 const auto plan=combined::MakePlan();
 for(const auto& r:ranges){
  if(!inSection(r.rva,r.size,r.executable))return combined::InvalidImage;
  for(size_t i=0;i<r.size;i++){
   unsigned rva=r.rva+(unsigned)i;bool patchByte=false;
   for(const auto& w:plan)if(rva>=w.rva&&rva-w.rva<w.length){patchByte=true;break;}
   if(!patchByte&&image[rva]!=r.bytes[i])return combined::Conflict;
  }
 }
 for(const auto& w:plan)if(!inSection(w.rva,w.length,true))return combined::InvalidImage;
 return combined::Active;
}
inline combined::Result Install(unsigned char* image,size_t size){
 auto result=Validate(image,size);if(result!=combined::Active)return result;
 return combined::Apply(image,size);
}
}
