#include <Windows.h>
#include <stdio.h>

#include "nt_init_func.hpp"

NtCreateSection_t pNtCreateSection = NULL;
NtQueryInformationProcess_t pNtQueryInformationProcess = NULL;
NtCreateProcessEx_t pNtCreateProcessEx = NULL;
RtlCreateProcessParametersEx_t pRtlCreateProcessParametersEx = NULL;
RtlInitUnicodeString_t pRtlInitUnicodeString = NULL;
NtSetInformationFile_t pNtSetInformationFile = NULL;


void nt_init() {
	HINSTANCE hinstStub = GetModuleHandleA("ntdll.dll");
	if (hinstStub)
	{
		pNtCreateSection = (NtCreateSection_t)::GetProcAddress(hinstStub, "NtCreateSection");
		if (!pNtCreateSection)
		{
			printf("Could not find NtCreateSection entry point in NTDLL.DLL");
			exit(0);
		}
		pNtCreateProcessEx = (NtCreateProcessEx_t)::GetProcAddress(hinstStub, "NtCreateProcessEx");
		if (!pNtCreateProcessEx)
		{
			printf("Could not find NtCreateProcessEx entry point in NTDLL.DLL");
			exit(0);
		}
		pNtQueryInformationProcess = (NtQueryInformationProcess_t)::GetProcAddress(hinstStub, "NtQueryInformationProcess");
		if (!pNtQueryInformationProcess)
		{
			printf("Could not find NtQueryInformationProcess entry point in NTDLL.DLL");
			exit(0);
		}
		pRtlCreateProcessParametersEx = (RtlCreateProcessParametersEx_t)::GetProcAddress(hinstStub, "RtlCreateProcessParametersEx");
		if (!pRtlCreateProcessParametersEx)
		{
			printf("Could not find RtlCreateProcessParametersEx entry point in NTDLL.DLL");
			exit(0);
		}
		pRtlInitUnicodeString = (RtlInitUnicodeString_t)::GetProcAddress(hinstStub, "RtlInitUnicodeString");
		if (!pRtlInitUnicodeString)
		{
			printf("Could not find RtlInitUnicodeString entry point in NTDLL.DLL");
			exit(0);
		}
		pNtSetInformationFile = (NtSetInformationFile_t)::GetProcAddress(hinstStub, "NtSetInformationFile");
		if (!pNtSetInformationFile)
		{
			printf("Could not find NtSetInformationFile entry point in NTDLL.DLL");
			exit(0);
		}
	}
	else
	{
		printf("Could not GetModuleHandle of NTDLL.DLL");
		exit(0);
	}
}