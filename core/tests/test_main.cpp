#include <exception>
#include <iostream>

void runConfigTests();
void runNftStatisticsTests();
void runNftImportTests();
void runRulesApiTests();
void runStatisticsApiTests();

int main() {
	try {
		runConfigTests();
		runNftStatisticsTests();
		runNftImportTests();
		runRulesApiTests();
		runStatisticsApiTests();
	} catch (const std::exception &error) {
		std::cerr << "Backend test failure: " << error.what() << '\n';
		return 1;
	}

	std::cout << "Backend tests passed\n";
	return 0;
}
