#include <iostream>
#include <stdlib.h>

using namespace std;

int main() {
	cout << "--get uuid--" << endl;
    
    system("sudo ./test | grep 'Received bits:.*' -o | grep ':.*' -o | grep '[0-9a-f]'");

    system("sh kill.sh");
}
