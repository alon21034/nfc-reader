#include <iostream>
#include <stdlib.h>
#include <string>

using namespace std;

int main(int argc, char** argv) {
	//cout << "--get signature--" << endl;

	// cout << argc << endl;

	string str1 = "sudo ./test ";
	string str2 = " | grep 'Received bits:.*' -o | grep ':.*' -o | grep '[0-9a-f]'";
	str1.append(argv[1]);
	str1.append(str2);

	// cout << "exec: " << str1 << endl;
	
	system(str1.c_str());

    // system("sh kill.sh");
}
