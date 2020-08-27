#pragma once

static UCHAR jmp_trampoline[] = { 0x50, 0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0x48, 0x87, 0x04, 0x24, 0xC3 };

inline KIRQL WPOFF()
{
	KIRQL Irql = KeRaiseIrqlToDpcLevel();
	UINT_PTR cr0 = __readcr0();

	cr0 &= ~0x10000;
	__writecr0( cr0 );
	_disable();

	return Irql;
}

inline void WPON( KIRQL Irql )
{
	UINT_PTR cr0 = __readcr0();

	cr0 |= 0x10000;
	_enable();
	__writecr0( cr0 );

	KeLowerIrql( Irql );
}

inline PVOID FindSuitableCave( PUCHAR Code, ULONG ulCodeSize, size_t CaveLength )
{
	for ( unsigned i = 0, j = 0; i < ulCodeSize; i++ )
	{
		if ( Code[ i ] == 0x90 || Code[ i ] == 0xCC )
			j++;
		else
			j = 0;

		if ( j == CaveLength )
			return ( PVOID )( ( ULONG_PTR )Code + i - CaveLength + 1 );
	}
	return nullptr;
}

extern void DestroySSDT();
extern void InitializeSSDT();
