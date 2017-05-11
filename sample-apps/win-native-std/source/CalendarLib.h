/*********************************************************************
* Microsoft Security Risk Detection
* Developer Center Demo Application
* (c) 2017 Microsoft Corp
*
* CalendarLib.h : Calendar library header file
*
*********************************************************************/

#include <iostream>
#include <fstream>
#include <windows.h>

using namespace std;

#define BUG_1 1		// Integer overflow via addition
#define BUG_2 2		// Uninitialized variable
#define BUG_3 3		// Integer overflow via multiplication
#define BUG_4 4		// Double free
#define BUG_5 5		// Unvalidated length field
#define BUG_6 6		// NULL pointer dereference
#define BUG_7 7		// Typo in error-handling code causes hang
#define BUG_8 8		// Unchecked use of tainted data
#define BUG_9 9		// Format string bug
#define BUG_10 10	// String-based stack buffer overflow

#define TRYEXCEPT 31

#define BugOn(x)  { BugBitmask |= (1 << x); printf("->BugOn(%d)\n", x); }
#define BugOff(x) { BugBitmask &= (~(1 << x)); printf("->BugOff(%d)\n", x); }
#define BugIsOn(x) BugBitmask & (1 << x)
#define BugIsOff(x) !(BugBitmask & (1 << x))

#define DllImport   __declspec( dllimport )

extern "C"
{
	DllImport unsigned int BugBitmask;

	void *CreateCalendarFromMemoryInput(unsigned char *in, size_t len);
	void *CreateCalendarFromFileStreamInput(ifstream *inputfile);
	void *CreateCalendarFromFilePtrInput(FILE *fp);
	void *CreateCalendarFromFileWindowsHandleInput(HANDLE h);
	void *CreateCalendarFromFileNameInput(const char *filename);
	int MergeCalendars(void *dest, void *source);

	int GetCalendarEntryCount(HANDLE cal);
	HANDLE FindFirstCalendarEntry(HANDLE cal);
	HANDLE FindNextCalendarEntry(HANDLE entry);
	enum EntryType GetCalendarType(HANDLE entry);

	HANDLE GetSender(HANDLE entry);
	char *GetContactName(HANDLE c);
	char *GetContactEmail(HANDLE c);
	HANDLE FindFirstRecipient(HANDLE entry);
	HANDLE FindNextRecipient(HANDLE c);
	
	char *GetLocation(HANDLE entry);
	char *GetTimeZone(HANDLE entry);
	int GetStartTime(HANDLE entry, int *hours, int *minutes, int *seconds);
	int GetStartDate(HANDLE entry, int *year, int *month, int *day);
	int GetDuration(HANDLE entry, int *hours, int *minutes, int *seconds);
	char *GetSubject(HANDLE entry);
	char *GetContent(HANDLE entry);
	char *GetContentType(HANDLE entry);
	unsigned int GetContentLength(HANDLE entry);
	unsigned int GetContentData(HANDLE entry, PVOID dst, unsigned int len);

	int GetAttachmentCount(HANDLE entry);
	HANDLE FindFirstAttachment(HANDLE entry);
	HANDLE FindNextAttachment(HANDLE a);
	char *GetAttachmentName(HANDLE a);
	unsigned int GetAttachmentBlobLength(HANDLE a);
	int GetAttachmentBlob(HANDLE a, void *p, unsigned int len);
}