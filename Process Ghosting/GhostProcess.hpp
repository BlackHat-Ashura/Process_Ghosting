#pragma once

// https://www.hackingarticles.in/process-ghosting-attack/
// https://github.com/hasherezade/process_ghosting/tree/master
// https://dosxuz.gitlab.io/post/processghosting/

#define PS_INHERIT_HANDLES 4

struct payload_data {
	DWORD size;
	BYTE* buf = NULL;
};

void GhostProcess(CHAR* ghostFile, WCHAR* coverFile, payload_data payload);
