#include <exception>
#include <iostream>

void runNftStatisticsTests();
void runRulesApiTests();

int main() {
	try {
		runNftStatisticsTests();
		runRulesApiTests();
	} catch (const std::exception &error) {
		std::cerr << "Backend test failure: " << error.what() << '\n';
		return 1;
	}

	std::cout << "Backend tests passed\n";
	return 0;
}
