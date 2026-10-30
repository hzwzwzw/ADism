#include "partition_picker.h"
#include "ui_log.h"
#include <iostream>
#include <algorithm>
std::string U(const std::wstring&s){int n=WideCharToMultiByte(CP_UTF8,0,s.data(),int(s.size()),nullptr,0,nullptr,nullptr);std::string r(n,0);WideCharToMultiByte(CP_UTF8,0,s.data(),int(s.size()),r.data(),n,nullptr,nullptr);return r;}
std::string Q(const std::wstring&s){std::string r="\"";for(char c:U(s)){if(c=='\\'||c=='"')r+='\\';if(c>=32)r+=c;}return r+'"';}
int wmain(int argc,wchar_t**argv){std::wstring error;auto rows=workbench::EnumeratePartitions(error);std::cout<<"{\"error\":"<<Q(error)<<",\"partitions\":[";bool first=true;for(const auto&c:rows){if(!first)std::cout<<',';first=false;std::cout<<"{\"disk\":"<<c.disk<<",\"partition\":"<<c.partition<<",\"bytes\":"<<c.bytes<<",\"volume\":"<<Q(c.volume)<<",\"label\":"<<Q(c.label)<<",\"letters\":"<<Q(c.letters)<<",\"diskId\":"<<Q(c.diskId)<<",\"selectable\":"<<(c.selectable?"true":"false")<<"}";}std::cout<<"]}"<<std::endl;
 if(argc<3)return rows.empty()?1:0;std::wstring volume=argv[1],label=argv[2];auto it=std::find_if(rows.begin(),rows.end(),[&](const auto&c){return c.volume==volume&&c.label==label;});if(it==rows.end()||!it->selectable||!it->letters.empty()){std::cerr<<"target must be explicit GUID + matching test label + no letter\n";return 2;}
 auto choice=*it;workbench::PartitionAccess access;auto bad=choice;bad.diskId+=L"wrong";std::wstring root;if(access.Resolve(bad,root,error)){std::cerr<<"identity mismatch accepted\n";return 3;}if(!access.Resolve(choice,root,error)){std::cerr<<U(error)<<std::endl;return 4;}std::cout<<"mounted="<<U(root)<<std::endl;
 wchar_t actual[1024]{};if(!GetVolumeNameForVolumeMountPointW(root.c_str(),actual,1024)||choice.volume!=actual)return 5;std::wstring again;if(!access.Resolve(choice,again,error)||again!=root)return 6;
 auto file=root+L"ADism-probe-"+std::to_wstring(GetCurrentProcessId())+L".txt";HANDLE h=CreateFileW(file.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,0,nullptr);if(h==INVALID_HANDLE_VALUE)return 7;DWORD n=0;bool ok=WriteFile(h,"probe",5,&n,nullptr)&&n==5;CloseHandle(h);if(!DeleteFileW(file.c_str())||!ok)return 8;access.Clear();if(GetVolumeNameForVolumeMountPointW(root.c_str(),actual,1024))return 9;
 rows=workbench::EnumeratePartitions(error);it=std::find_if(rows.begin(),rows.end(),[&](const auto&c){return c.volume==volume;});if(it==rows.end()||!it->letters.empty())return 10;std::cout<<"identity-reject=PASS; repeat-resolve=PASS; file-access=PASS; cleanup=PASS\n";return 0;
}
