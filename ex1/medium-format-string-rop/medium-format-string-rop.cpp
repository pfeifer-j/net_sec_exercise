#include <iostream>

void win() {
    std::cout << "\nAuthenticated! Proof: DIFFERENT-ON-REMOTE!\n" << std::flush;
}

int main() {
    /* 
        Note that the compiled stack layout may be different
        In The compiled binary it looks like this:
        +─────────────+
        | Stack       |
        +─────────────+
        | ...         |
        | win         |
        | secret      |
        | marker      |
        | stack_addr  |
        | target_addr |
        | …           |
        | return_addr |
        +─────────────+
    */

    unsigned long target_addr = (unsigned long)&win; // get the address of win and save it as a target
    unsigned long stack_addr = (unsigned long)&target_addr; // an address on the current stack
    unsigned long marker = 0x123456789ABCDEF; // a marker to help you
    int secret = 0xc0ffe; // This is different on the remote!
    char name[500];
    int secret_input;

    std::cout << "Name:";
    std::cin.getline(name, 500);

    std::cout << "Secret:";
    std::cin >> secret_input;
    
    std::cout << "Hallo: ";
    std::printf(name);

    if (secret_input == secret) {
        std::cout << "\nAuthenticated! Proof: DIFFERENT-ON-REMOTE!\n";
        std::cout << "cool! \n\n";
    } else {
        std::cout << "\nWrong :|\n";
        std::cout << "Anyway... \n\n";
    }

    std::cout << "could you call win for me?\n";
    std::cout << "what was your name again?:";
    std::cin.ignore();
    std::cin.getline(name, 500); 
    std::cout << "Oh true its: ";
    std::printf(name);
    
    // win()    
    return 0;
}
