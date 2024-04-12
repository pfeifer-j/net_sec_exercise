#include <iostream>

int main() {
        /* 
        Note that the compiled stack layout may be different
        In The compiled binary it looks like this:
        +─────────────+
        | Stack       |
        +─────────────+
        | ...         |
        | name        |
        | secret      |
        | ...         |
        +─────────────+
    */
   
    int secret = 0x1234; // this is different on remote
    char name[10];
    int secret_input;

    std::cout << "Name:";
    std::cin >> name;
    
    std::cout << "Secret:";
    std::cin >> secret_input;

    if (secret_input == secret) {
        std::cout << "Authenticated! Proof: DIFFERENT-ON-REMOTE!";
    } else {
        std::cout << "Wrong :|";
    }

    return 0;
}