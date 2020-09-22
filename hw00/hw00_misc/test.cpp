#include <iostream>

using namespace std;

int main() {

	string name;
	cout << "Give me your name and surname:"<< endl;
	cin >> name;
	cin.ignore(10000, '\n'); //time to remove "Wlodarczyk" the wood log and make the stream flow
	int age;
	cout << "Give me your age:" << endl;
	cin >> age;
	//cin.clear();
	//cin.ignore(10000, '\n'); //time to remove "Wlodarczyk" the wood log and make the stream flo

	return 0;
}
