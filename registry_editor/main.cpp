#include <chrono>
#include <thread>
#include <random>
#include <algorithm>
#include <array>
#include <filesystem>
#include "utilities.hpp"
#include "raii.hpp"
#include "privilege_editor.hpp"

#define out( text, ... ) std::printf( text, ##__VA_ARGS__ )
#pragma warning( disable : 4312 )

raii::hkey registry_hkey( const std::string_view key ) {
	HKEY output = nullptr;
	const LSTATUS status = RegOpenKeyExA( HKEY_LOCAL_MACHINE, key.data( ), 0, KEY_ALL_ACCESS, &output );

	if ( status != ERROR_SUCCESS ) {
		out( "[-] failed to open handle to %s\n", key.data( ) );
		return nullptr;
	}

	return raii::hkey( output );
}

int main( ) {
	out( "[+] registry spoofer by paracord initiated\n" );

	constexpr auto string_length = 16ull;
	const auto start_time = std::chrono::steady_clock::now( ).time_since_epoch( );

	auto spoof_key = [ ]( HKEY current_key, auto sub_keys, bool is_string ) 
	{
		auto randomized_dword = 0ul;
		std::string randomized_string;

		thread_local std::mt19937_64 mersenne_generator( std::random_device{}( ) );
		
		if ( is_string )
		{
			randomized_string.reserve( string_length );
			std::generate_n( std::back_inserter( randomized_string ), string_length, [ & ] ( ) {
				std::uniform_int_distribution<> distribution( 97, 122 );
				return static_cast< unsigned char >( distribution( mersenne_generator ) );
			} );
		} 
		else
		{
			std::uniform_int_distribution<DWORD> distribution( 0, MAXUINT32 );
			randomized_dword = distribution( mersenne_generator );
		}

		auto set_status = ERROR_SUCCESS;

		for ( const auto& current : sub_keys ) 
		{
			is_string ? set_status = RegSetValueExA( current_key, current, 0, REG_SZ, ( std::uint8_t* )randomized_string.c_str( ), string_length ) : set_status = RegSetValueExA( current_key, current, 0, REG_DWORD, ( std::uint8_t* )&randomized_dword, sizeof( DWORD ) );
			( set_status == ERROR_SUCCESS ) ? ( is_string ? out( "[+] set %s to: %s\n", current, randomized_string.c_str( ) ) : out( "[+] set %s to: %i\n", current, randomized_dword ) ) : out( "[-] failed to set %s\n", current );
		}
	};

	auto control_key = registry_hkey( "System\\CurrentControlSet\\Control" );
	{
		spoof_key( control_key.get( ), std::array{ "SystemInformation", "ComputerHardwareId" }, 1 );
	}

	auto scsi_key = registry_hkey( "Hardware\\DeviceMap\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" );
	{
		spoof_key( scsi_key.get( ), std::array{ "Identifier", "SerialNumber" }, 1 );
	}

	auto desc_key = registry_hkey( "System\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000" );
	{
		spoof_key( desc_key.get( ), std::array{ "DriverDesc" }, 2 );
	}

	auto nt_key = registry_hkey( "Software\\Microsoft\\Windows NT\\CurrentVersion" );
	{
		spoof_key( nt_key.get( ), std::array{ "InstallTime", "BuildGUID", "ProductID" }, 2 );
	}
	
	HKEY raw_hkey = nullptr;
	RegCreateKeyExA( HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Control\\WMI\\Restrictions", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &raw_hkey, 0 );

	raii::hkey unique_hkey( raw_hkey ); 
	{
		std::uint8_t extracted_data;
		DWORD extracted_size;
		RegQueryValueExA( unique_hkey.get( ), "HideMachine", nullptr, nullptr, &extracted_data, &extracted_size );

		if ( ( DWORD )extracted_data != 1 ) {
			const auto value = 1;
			const auto status = RegSetValueExA( unique_hkey.get( ), "HideMachine", 0, REG_DWORD, ( std::uint8_t* )&value, sizeof( DWORD ) );
			status ? out( "[+] successfully set HideMachine flag to prevent SMBIOS queries!\n" ) : out( "[-] failed to set HideMachine flag\n" );
		}
	}

	raii::handle wmi_handle( OpenProcess( PROCESS_ALL_ACCESS, FALSE, utilities::process_id( "WmiPrvSE.exe" ) ) );
	{
		if ( wmi_handle.get( ) != INVALID_HANDLE_VALUE )
			TerminateProcess( wmi_handle.get( ), EXIT_SUCCESS );
	}

	constexpr auto machine_guid = "C:\\Windows\\System32\\restore\\MachineGuid.txt";
	
	if ( std::filesystem::exists( machine_guid ) )
	{
		privilege::take_ownership( machine_guid );

		auto file_attributes = GetFileAttributesA( machine_guid );
		file_attributes &= FILE_ATTRIBUTE_READONLY;
		
		SetFileAttributesA( machine_guid, file_attributes );
		std::remove( machine_guid );
		
		out( "[+] deleted %s\n", machine_guid );
	}

	auto elapsed_time = std::chrono::duration_cast< std::chrono::milliseconds >( std::chrono::steady_clock::now( ).time_since_epoch( ) - start_time ).count( );

	out( "[+] done in %llums\n", elapsed_time );

	std::this_thread::sleep_for( std::chrono::seconds( 10 ) );

	return EXIT_SUCCESS;
}
