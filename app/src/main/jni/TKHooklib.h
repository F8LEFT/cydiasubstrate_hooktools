#ifndef _TKHOOKLIB_H
#define _TKHOOKLIB_H

#define SOINFO_NAME_LEN 128

#define HOOK_SUCCESS 0
#define HOOK_FAILED -1

typedef struct _HookStruct{
	char SOName[SOINFO_NAME_LEN];
	char FunctionName[SOINFO_NAME_LEN];
	void *NewFunc;
	void *OldFunc;
	void *occPlace;
}HookStruct;

#ifdef __cplusplus
extern "C" {
#endif

void TK_UnHookExportFunction(HookStruct *pHookStruct);

void TK_UnHookImportFunction(HookStruct *pHookStruct);

int TK_HookImportFunction(HookStruct *pHookStruct);

int TK_HookExportFunction(HookStruct *pHookStruct);

int TK_InlineHookFunction(void *TargetFunc, void *NewFunc, void** OldFunc);

#ifdef __cplusplus
};
#endif

#endif
