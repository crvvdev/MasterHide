#include "includes.hpp"

namespace masterhide
{
namespace object
{
OBJECT_TYPE g_objectTypes[3]{};
volatile LONG g_objectTypeCount = 0;

void ObjectDelete(_In_ POBJECT_HEADER header)
{
    const POBJECT_TYPE type = &g_objectTypes[header->TypeIndex];

    if (type->TypeInfo.Delete)
    {
        type->TypeInfo.Delete(ObjectHeaderToObject(header));
    }

    type->TypeInfo.Free(header);

    InterlockedDecrementSizeT(&type->TotalNumberOfObjects);
}

void ReferenceObject(_In_ PVOID object)
{
    POBJECT_HEADER header = ObjectToObjectHeader(object);

    NT_VERIFY(InterlockedIncrementSSizeT(&header->PointerCount) > 0);
}

void DereferenceObject(_In_ PVOID object)
{
    POBJECT_HEADER header = ObjectToObjectHeader(object);

    const SSIZE_T refCount = InterlockedDecrementSSizeT(&header->PointerCount);
    if (refCount > 0)
    {
        return;
    }

    NT_ASSERT(refCount == 0);

    ObjectDelete(header);
}

void CreateObjectType(_In_ PCUNICODE_STRING typeName, _In_ POBJECT_TYPE_INFO typeInfo,
                      _Outptr_ POBJECT_TYPE *objectType)
{
    const LONG index = (InterlockedIncrement(&g_objectTypeCount) - 1);

    //
    // We have failure free object type creation, to achieve this we have
    // a pre-reserved sized array above. If this asserts the array wasn't
    // expanded correctly to support a new type.
    //
    NT_ASSERT((index >= 0) && (index < ARRAYSIZE(g_objectTypes)));
    NT_ASSERT(index < MAXUCHAR);

    POBJECT_TYPE type = &g_objectTypes[index];

    type->Name.Buffer = typeName->Buffer;
    type->Name.MaximumLength = typeName->MaximumLength;
    type->Name.Length = typeName->Length;

    type->Index = (UCHAR)index;
    type->TotalNumberOfObjects = 0;
    type->HighWaterNumberOfObjects = 0;

    RtlCopyMemory(&type->TypeInfo, typeInfo, sizeof(*typeInfo));

    *objectType = type;
}

NTSTATUS CreateObject(_In_ POBJECT_TYPE objectType, _In_ ULONG objectBodySize,
                      _Outptr_result_nullonfailure_ PVOID *object, _In_opt_ PVOID parameter)
{
    NTSTATUS status;

    *object = nullptr;

    auto header = static_cast<POBJECT_HEADER>(objectType->TypeInfo.Allocate(AddObjectHeaderSize(objectBodySize)));
    if (!header)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    header->PointerCount = 1;
    header->TypeIndex = objectType->Index;

    PVOID obj = ObjectHeaderToObject(header);

    if (objectType->TypeInfo.Initialize)
    {
        status = objectType->TypeInfo.Initialize(obj, parameter);
        if (!NT_SUCCESS(status))
        {
            objectType->TypeInfo.Free(header);
            return status;
        }
    }

    const SIZE_T total = InterlockedIncrementSizeT(&objectType->TotalNumberOfObjects);

    InterlockedExchangeIfGreaterSizeT(&objectType->HighWaterNumberOfObjects, total);

    *object = obj;

    return STATUS_SUCCESS;
}
} // namespace object
} // namespace masterhide