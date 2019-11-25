#pragma once
#include "raii.hpp"
#include <tlhelp32.h>
#include <string_view>

namespace utilities {
	std::uint32_t process_id( const std::string_view process_name ) 
	{
		raii::handle snap32( CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0u ) );

		PROCESSENTRY32 entry{ sizeof( PROCESSENTRY32 ) };

		for ( Process32First( snap32.get( ), &entry ); Process32Next( snap32.get( ), &entry ); )
			if ( !std::strcmp( process_name.data( ), entry.szExeFile ) ) 
				return entry.th32ProcessID;

		return 0u;
	}
}
