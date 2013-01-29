BOOST_INC_PATH := /home/cam/boost_1_52_0/
BOOST_LIB_PATH := /home/cam/boost_1_52_0/stage/lib/
CRYPTO_INC_PATH := /home/cam/crypto++/
CRYPTO_LIB_PATH := /home/cam/crypto++/

BIN_DIR = bin/
OBJ_DIR = $(BIN_DIR)
EXEC = $(BIN_DIR)7zcrypto

SRC_FILES = CmdLineParser.cpp MyRSA.cpp PEMCleanser.cpp 7zCrypto.cpp
OBJS = $(SRC_FILES:%.cpp=%.o)
OBJ_FILES= $(addprefix $(OBJ_DIR),$(OBJS))

LIBRARY_PATH := -L$(CRYPTO_LIB_PATH) -L$(BOOST_LIB_PATH)
INCLUDE_PATH := -I$(BOOST_INC_PATH) -I$(CRYPTO_INC_PATH)
LIBRARIES_TO_LINK  := -lcryptopp -lboost_filesystem

CC = g++
CCFLAGS = -O2
CPPFLAGS = $(INCLUDE_PATH) -DCP_IGNORE_REST
LNKFLAGS = $(LIBRARY_PATH) $(LIBRARIES_TO_LINK)

all: $(EXEC)

$(EXEC): $(OBJ_FILES)
	$(CC) $(CPPFLAGS) $(OBJ_FILES) -o $(EXEC) $(LNKFLAGS)

$(OBJ_DIR)%.o:%.cpp
	$(CC) -c $(CCFLAGS) $(CPPFLAGS) $< -o $@

depend: 
	makedepend $(CPPFLAGS) $(SRC_FILES)
	
clean:
	$(RM) $(OBJ_FILES)

