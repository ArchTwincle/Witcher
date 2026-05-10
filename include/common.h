#pragma once

namespace witcher {

	inline constexpr wchar_t kServiceName[] = L"WitcherTrayService";
	inline constexpr wchar_t kServiceDisplayName[] = L"WitcherTrayService";

	inline constexpr wchar_t kServiceExeName[] = L"WitcherTrayService.exe";
	inline constexpr wchar_t kTrayAppExeName[] = L"TrayWin32App.exe";

	inline constexpr wchar_t kRpcEndpoint[] = L"WitcherTrayServiceRpcEndpoint";

	// Пользовательская ошибка для случаев, когда антивирусная функциональность
	// вызвана без активной лицензии.
	inline constexpr long kErrorNoLicense = 0x20000001;

}