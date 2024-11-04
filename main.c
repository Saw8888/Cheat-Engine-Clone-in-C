#include <stdio.h>
#include <Windows.h>

#define MAX_ADDRESSES 100000
HANDLE handle;

unsigned char** firstScan(char* name, int TARGET_VALUE) {
 int foundCounter = 0;
 static unsigned char *ptrArr[MAX_ADDRESSES] = {NULL};

 HWND hwnd = FindWindowA(NULL, name);
 if (hwnd == NULL) {
  printf("Cannot find window\n");
  return NULL;
 }

 DWORD procID;
 GetWindowThreadProcessId(hwnd, &procID);
 handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, procID);
 if (handle == NULL) {
  printf("Cannot obtain process\n");
  return NULL;
 }

 SYSTEM_INFO systemInfo;
 GetSystemInfo(&systemInfo);

 MEMORY_BASIC_INFORMATION mbi;
 unsigned char *addressPtr = (unsigned char *)systemInfo.lpMinimumApplicationAddress;
 SIZE_T bytesRead;

 while (addressPtr < systemInfo.lpMaximumApplicationAddress && foundCounter < MAX_ADDRESSES) {
  // Query the memory region
  if (VirtualQueryEx(handle, addressPtr, &mbi, sizeof(mbi)) != 0) {
   // Check if it's a committed and readable region
   if (mbi.State == MEM_COMMIT && 
      (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY || mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_READ)) {

    unsigned char *buffer = (unsigned char *)malloc(mbi.RegionSize);
    if (buffer != NULL) {
     if (ReadProcessMemory(handle, addressPtr, buffer, mbi.RegionSize, &bytesRead)) {
      // Search for the target value in the buffer
      for (SIZE_T i = 0; i < bytesRead - sizeof(int); i++) {
       // Ensure that the comparison aligns correctly with the int size
       if (*(int *)(buffer + i) == TARGET_VALUE) {
        ptrArr[foundCounter++] = addressPtr + i;
        if (foundCounter >= MAX_ADDRESSES) {
         break;
        }
       }
      }
     }
     free(buffer);
    }
   }
   // Move to the next memory region
   addressPtr += mbi.RegionSize;
  } else {
   // If VirtualQueryEx fails, move to the next page
   addressPtr += 0x1000; // 4KB
  }
 }
 return ptrArr;
}

int main(void) {
 int target;
 printf("First value: ");
 scanf("%d", &target);

 unsigned char **arr = firstScan("Your Target Program", target);
 if (arr == NULL) {
  printf("Error in scanning memory.\n");
  return 1;
 }

 int i = 0;
 while (arr[i] != NULL) {
  printf("%p\n", arr[i]);
  i++;
 }

 // Continue scanning for updated target values until the user inputs 8008
 while (target != 8008) {
  printf("Next value: ");
  scanf("%d", &target);

  int i = 0;
  int newPos = 0;
  int tempValue;

  // Check each stored address for the new target value
  while (arr[i] != NULL) {
   if (ReadProcessMemory(handle, arr[i], &tempValue, sizeof(int), NULL)) {
    if (tempValue == target) {
     arr[newPos++] = arr[i];
    }
   }
   i++;
  }

  // Nullify remaining unused positions in arr after filtering
  int m = newPos;
  while (m < MAX_ADDRESSES && arr[m] != NULL) {
   arr[m] = NULL;
   m++;
  }

  i = 0;
  while (arr[i] != NULL) {
   printf("%p\n", arr[i]);
   i++;
  }
 }

 CloseHandle(handle);
 return 0;
}

