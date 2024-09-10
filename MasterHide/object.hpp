#pragma once

namespace masterhide
{
namespace object
{
using TYPE_ALLOCATE_PROCEDURE = PVOID (*)(_In_ SIZE_T);
using TYPE_INITIALIZE_PROCEDURE = NTSTATUS (*)(_Inout_ PVOID, _In_opt_ PVOID);
using TYPE_DELETE_PROCEDURE = void (*)(_Inout_ PVOID);
using TYPE_FREE_PROCEDURE = void (*)(_In_ PVOID);

typedef struct _OBJECT_HEADER
{
    volatile SSIZE_T PointerCount;
    UCHAR TypeIndex;

} OBJECT_HEADER, *POBJECT_HEADER;

#define ObjectToObjectHeader(x) ((POBJECT_HEADER)CONTAINING_RECORD((PCHAR)x, OBJECT_HEADER, TypeIndex))
#define ObjectHeaderToObject(x) ((PVOID) & ((POBJECT_HEADER)(x))->TypeIndex)
#define AddObjectHeaderSize(x) ((SIZE_T)(x) + FIELD_OFFSET(OBJECT_HEADER, TypeIndex))

typedef struct _OBJECT_TYPE_INFO
{
    TYPE_ALLOCATE_PROCEDURE Allocate;
    TYPE_INITIALIZE_PROCEDURE Initialize;
    TYPE_DELETE_PROCEDURE Delete;
    TYPE_FREE_PROCEDURE Free;

} OBJECT_TYPE_INFO, *POBJECT_TYPE_INFO;

typedef struct _OBJECT_TYPE
{
    UNICODE_STRING Name;
    UCHAR Index;
    volatile SIZE_T TotalNumberOfObjects;
    volatile SIZE_T HighWaterNumberOfObjects;
    OBJECT_TYPE_INFO TypeInfo;

} OBJECT_TYPE, *POBJECT_TYPE;

void ObjectDelete(_In_ POBJECT_HEADER header);
void ReferenceObject(_In_ PVOID object);
void DereferenceObject(_In_ PVOID object);

void CreateObjectType(_In_ PCUNICODE_STRING typeName, _In_ POBJECT_TYPE_INFO typeInfo,
                      _Outptr_ POBJECT_TYPE *objectType);

_Must_inspect_result_ NTSTATUS CreateObject(_In_ POBJECT_TYPE objectType, _In_ ULONG objectBodySize,
                                            _Outptr_result_nullonfailure_ PVOID *object, _In_opt_ PVOID parameter);
} // namespace object
} // namespace masterhide