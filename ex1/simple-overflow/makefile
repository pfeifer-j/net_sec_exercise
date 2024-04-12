all:
	g++ -D_FORTIFY_SOURCE=2,-D_GLIBCXX_ASSERTIONS,-fpie,-Wl,-pie,-fstack-clash-protection,-fstack-protector,-O2 simple-overflow.cpp -o simple-overflow