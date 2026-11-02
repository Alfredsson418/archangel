#include <exception>
#include <iostream>

void runFirewallBundleTests();
void runAuthProviderTests();
void runRuntimeConfigTests();
void runNftStatisticsTests();
void runNftImportTests();
void runNftRuleTests();
void runRulesApiTests();
void runStatsApiTests();
void runStatusApiTests();
void runFirewallBundleCommandTests();
void runNetworkAddressTests();
void runHttpAuthenticationTests();
void runAuthApiTests();
void runAccountsApiTests();
void runLoggingTests();
void runTlsTests();

int main() {
	try {
		runAuthProviderTests();
		runRuntimeConfigTests();
		runFirewallBundleTests();
		runNftStatisticsTests();
		runNftImportTests();
		runNftRuleTests();
		runRulesApiTests();
		runStatsApiTests();
		runStatusApiTests();
		runFirewallBundleCommandTests();
		runNetworkAddressTests();
		runHttpAuthenticationTests();
		runAuthApiTests();
		runAccountsApiTests();
		runLoggingTests();
		runTlsTests();
	} catch (const std::exception &error) {
		std::cerr << "Backend test failure: " << error.what() << '\n';
		return 1;
	}

	std::cout << "Backend tests passed\n";
	return 0;
}
