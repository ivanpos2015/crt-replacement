#pragma once

bool ManualMap32(DWORD dwPID, PBYTE pDll, DWORD dwDllLen); //inject 32-bit dll into 32-bit process.
bool ManualMap64(DWORD dwPID, PBYTE pDll, DWORD dwDllLen); //inject 64-bit dll into 64-bit process.