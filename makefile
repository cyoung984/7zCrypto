BOOST_INC_PATH := /home/cam/boost_1_52_0/
BOOST_LIB_PATH := /home/cam/boost_1_52_0/stage/lib/
CRYPTO_INC_PATH := /home/cam/crypto++/
CRYPTO_LIB_PATH := /home/cam/crypto++/
BIN_PATH := bin/

LIBRARY_PATH := -L$(CRYPTO_LIB_PATH) -L$(BOOST_LIB_PATH)
INCLUDE_PATH := -I$(BOOST_INC_PATH) -I$(CRYPTO_INC_PATH)
CFLAGS := 

OBJECTS_TO_LINK := objs/*.o
LIBRARIES_TO_LINK  := -lcryptopp -lboost_filesystem
OUTPUT = -o $(BIN_PATH)7zCrypto

7zCrypto: objs/MyRSA.o objs/CmdLineParser.o objs/7zCrypto.o
	g++ $(LIBRARY_PATH) $(OUTPUT)  $(OBJECTS_TO_LINK) $(LIBRARIES_TO_LINK) 

objs/7zCrypto.o: objs/MyRSA.o objs/CmdLineParser.o 7zCrypto.cpp
	g++ -c $(CFLAGS)  $(INCLUDE_PATH) -DCP_IGNORE_REST 7zCrypto.cpp -o objs/7zCrypto.o
	
objs/MyRSA.o: objs/PEMCleanser.o MyRSA.h MyRSA.cpp
	g++ -c $(CFLAGS) $(INCLUDE_PATH) MyRSA.cpp -o objs/MyRSA.o
	
objs/CmdLineParser.o: CmdLineParser.cpp CmdLineParser.h
	g++ -c $(CFLAGS) $(INCLUDE_PATH) -DCP_IGNORE_REST CmdLineParser.cpp -o objs/CmdLineParser.o
	
objs/PEMCleanser.o: PEMCleanser.cpp
	g++ -c $(CFLAGS) $(INCLUDE_PATH) PEMCleanser.cpp -o objs/PEMCleanser.o
	
clean: 
	rm objs/*.o 
	rm $(BIN_PATH)7zCrypto
