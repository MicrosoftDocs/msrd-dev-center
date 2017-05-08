/*********************************************************************
* Microsoft Security Risk Detection
* Developer Center Demo Application
* (c) 2017 Microsoft Corp
*
* CalendarApi.cpp:  Definitions of functions exported by
* CalendarLib.dll
*
*********************************************************************/

#include "stdafx.h"
#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <iostream>
#include <fstream>
#include "CalendarStructures.h"
#include "CalendarParser.h"

using namespace std;

Calendar *ParseInput(unsigned char *in, size_t len);
CalendarEntry *CopyCalendarEntry(CalendarEntry *srcEntry);

#define DllExport   __declspec( dllexport )

extern "C"
{
	DllExport /*extern*/ unsigned int BugBitmask = ~0;

	DllExport void *CreateCalendarFromMemoryInput(unsigned char *in, size_t len)
	{
		if (BugIsOn(TRYEXCEPT))
		{
			__try
			{
				return ParseInput(in, len);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return NULL;
			}
		}
		else
		{
			return ParseInput(in, len);
		}
	}

	DllExport void *CreateCalendarFromFileStreamInput(ifstream *inputfile)
	{
		inputfile->seekg(0, inputfile->end);
		size_t size = (size_t)inputfile->tellg();
		inputfile->seekg(0, inputfile->beg);

		unsigned char * buffer = new unsigned char[size];
		if (!buffer)
		{
			return NULL;
		}
		inputfile->read((char *)buffer, size);
		inputfile->close();

		void *p = CreateCalendarFromMemoryInput(buffer, size);
		delete[] buffer;
		return (void *)p;
	}

	DllExport void *CreateCalendarFromFilePtrInput(FILE *pFile)
	{
		fseek(pFile, 0L, SEEK_END);
		size_t size = ftell(pFile);
		fseek(pFile, 0L, SEEK_SET);

		unsigned char *p = (unsigned char *)malloc(size);
		if (!p)
		{
			return NULL;
		}

		fread(p, 1, size, pFile);
		void *t = CreateCalendarFromMemoryInput(p, size);
		free(p);
		return (void *)t;
	}

	DllExport void *CreateCalendarFromFileWindowsHandleInput(HANDLE h)
	{
		DWORD size = GetFileSize(h, NULL);
		HANDLE MappingHandle = CreateFileMapping(h, NULL, PAGE_READONLY, 0, 0, NULL);
		if (MappingHandle == NULL)
		{
			return NULL;
		}

		void *p = MapViewOfFile(MappingHandle, FILE_MAP_READ, 0, 0, 0);
		if (!p)
		{
			CloseHandle(MappingHandle);
			return NULL;
		}

		void *t = CreateCalendarFromMemoryInput((unsigned char *)p, size);
		UnmapViewOfFile(p);
		CloseHandle(MappingHandle);
		return t;
	}

	DllExport void *CreateCalendarFromFileNameInput(const char *pszFileName)
	{
		ifstream inputfile(pszFileName, ios::binary);
		if (inputfile)
		{
			return CreateCalendarFromFileStreamInput(&inputfile);
		}
		else
		{
			printf("ERROR: no return from inputfile");
			return NULL;
		}
	}

	DllExport int MergeCalendars(void *dest, void *source)
	{
		Calendar *dst = (Calendar *)dest;
		Calendar *src = (Calendar *)source;

		if (!dst || !src) return -1;
		if (src->Version != dst->Version) return -1;
		CalendarEntry *srcEntry = src->Entry;
		CalendarEntry *dstEntry = dst->Entry;

		CalendarEntry *temp = NULL, *copy = NULL;
		temp = CopyCalendarEntry(srcEntry);
		copy = temp;
		srcEntry = srcEntry->NextEntry;

		while (srcEntry)
		{
			if (temp) temp->NextEntry = CopyCalendarEntry(srcEntry); // todo, set prev
			if (!temp)
			{
				goto ERROR_EXIT;
			}

			temp = temp->NextEntry;
			srcEntry = srcEntry->NextEntry;
		}

		while (dstEntry->NextEntry) dstEntry = dstEntry->NextEntry;
		dstEntry->NextEntry = copy; // todo set prev
		return 0;

	ERROR_EXIT:
		DestroyCalendarEntry(copy);
		return -1;
	}

	DllExport int GetCalendarEntryCount(Calendar *pCalendar)
	{
		return pCalendar->EntryCount;
	}

	DllExport CalendarEntry *FindFirstCalendarEntry(Calendar *pCalendar)
	{
		return pCalendar->Entry;
	}

	DllExport CalendarEntry *FindNextCalendarEntry(CalendarEntry *pEntry)
	{
		if (!pEntry)
		{
			return NULL;
		}
		return pEntry->NextEntry;
	}

	DllExport enum EntryType GetCalendarType(CalendarEntry *pEntry)
	{
		return pEntry->EntryType;
	}

	DllExport Contact *GetSender(CalendarEntry *pEntry)
	{
		return pEntry->Sender;
	}

	DllExport char *GetContactName(Contact *pContact)
	{
		return (char *)pContact->Name->Short.Value;
	}

	DllExport char *GetContactEmail(Contact *pContact)
	{
		return (char *)pContact->Email->Short.Value;
	}

	DllExport Contact *FindFirstRecipient(CalendarEntry *pEntry)
	{
		return pEntry->Recipient;
	}

	DllExport Contact *FindNextRecipient(Contact *pContact)
	{
		if (!pContact)
		{
			return NULL;
		}
		return pContact->NextContact;
	}

	DllExport char *GetLocation(CalendarEntry *pEntry)
	{
		if (pEntry->Location)
		{
			return (char *)pEntry->Location->Long.Value;
		}
		else return NULL;
	}

	DllExport char *GetTimeZone(CalendarEntry *pEntry)
	{
		return (char *)pEntry->TimeZone->Short.Value;
	}

	DllExport int GetStartTime(CalendarEntry *pEntry, int *hours, int *minutes, int *seconds)
	{
		if (!hours || !minutes || !seconds)
		{
			return -1;
		}

		*hours = pEntry->StartTime->Hour;
		*minutes = pEntry->StartTime->Minute;
		*seconds = pEntry->StartTime->Second;
		return 0;
	}

	DllExport int GetStartDate(CalendarEntry *pEntry, int *year, int *month, int *day)
	{
		if (!year || !month || !day)
		{
			return -1;
		}

		*year = pEntry->StartDate->Year;
		*month = pEntry->StartDate->Month;
		*day = pEntry->StartDate->Day;

		return 0;
	}

	DllExport int GetDuration(CalendarEntry *pEntry, int *hours, int *minutes, int *seconds)
	{
		if (!hours || !minutes || !seconds)
		{
			return -1;
		}

		*hours = pEntry->Duration->Hour;
		*minutes = pEntry->Duration->Minute;
		*seconds = pEntry->Duration->Second;
		return 0;
	}

	DllExport char *GetSubject(CalendarEntry *pEntry)
	{
		if (pEntry->Subject)
		{
			return (char *)pEntry->Subject->Long.Value;
		}
		else return NULL;
	}

	DllExport char *GetContent(CalendarEntry *pEntry)
	{
		if (pEntry->Content)
		{
			return (char *)pEntry->Content->Long.Value;
		}
		else return NULL;
	}

	DllExport unsigned int GetContentLength(CalendarEntry *pEntry)
	{
		if (pEntry->Content)
		{
			return pEntry->Content->Long.Length;
		}
		return 0;
	}

	DllExport unsigned int GetContentData(CalendarEntry *pEntry, PVOID dst, unsigned int len)
	{
		if (!pEntry->Content) return 0;
		unsigned int rlen = min(len, pEntry->Content->Long.Length);
		memcpy(dst, pEntry->Content->Long.Value, rlen);
		return rlen;
	}

	DllExport char *GetContentType(CalendarEntry *pEntry)
	{
		if (pEntry->ContentType)
			return (char *)pEntry->ContentType->Long.Value;
		else
			return NULL;
	}

	DllExport int GetAttachmentCount(CalendarEntry *pEntry)
	{
		if (!pEntry->Attachments) return 0;
		return pEntry->Attachments->Count;
	}

	DllExport Attachment *FindFirstAttachment(CalendarEntry *pEntry)
	{
		if (!pEntry->Attachments)
		{
			return NULL;
		}
		return pEntry->Attachments->Attachment;
	}

	DllExport Attachment *FindNextAttachment(Attachment *a)
	{
		a++;
		return a;
	}

	DllExport char *GetAttachmentName(Attachment *a)
	{
		return (char *)a->Name->Short.Value;
	}

	DllExport unsigned int GetAttachmentBlobLength(Attachment *a)
	{
		return a->Blob->Length;
	}

	DllExport int GetAttachmentBlob(Attachment *a, void *p, unsigned int len)
	{
		int ret = -1;

		if (!(len < a->Blob->Length))
		{
			memcpy(p, a->Blob->Data, a->Blob->Length);
			ret = 0;
		}

		return ret;
	}
}