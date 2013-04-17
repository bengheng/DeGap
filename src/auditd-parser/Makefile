TARGET=ausecure
SRC=ausecure.cpp \
		aumake.cpp \
		auwork.cpp \
		aussemble.cpp \
		auread.cpp \
		process.cpp \
		program.cpp \
		progfile.cpp \
		file.cpp \
		fileinstance.cpp \
		syscall.cpp \
		utilities.cpp \
		strhash.cpp \
		db.cpp
OBJ=$(SRC:.cpp=.o)
CFLAGS=-O3 \
			 -DNDEBUG -DVERBOSE -DNDUMP_SLOW -DNLOAD_SLOW -DUSE_DB\
			 -DUSE_AUREAD \
			 -I./ \
			 -I/usr/local/include \
			 -I/usr/include/libxml2 \
			 -std=c++0x
LDFLAGS=-L/usr/local/lib \
				-lauparse \
				-Wl,-Bstatic \
				-lboost_system \
				-lboost_filesystem \
				-lboost_regex \
				-lxml2 \
				-lz \
				-lmagic \
				-Wl,-Bdynamic \
				-lsqlite3 \
				-lpthread

all:$(TARGET)

$(TARGET):$(SRC)
	g++ $(CFLAGS) $(SRC) $(LDFLAGS) -o ${TARGET}
	mv ${TARGET} ../../bin/${TARGET}

validator:validator.cpp
	g++ $(CFLAGS) validator.cpp strhash.cpp backup.cpp $(LDFLAGS) -o validator
	mv validator ../bin/validator

dieter:dieter.cpp
	g++ $(CFLAGS) utilities.cpp dieter.cpp $(LDFLAGS) -o dieter
	mv dieter ../bin/dieter

hasher:hasher.cpp
	g++ hasher.cpp strhash.cpp -std=c++0x -o hasher
	mv hasher ../bin/hasher

duration:duration.cpp
	g++ duration.cpp -lauparse -o duration
	mv duration ../bin/duration

splitlog:splitlog.cpp
	g++ splitlog.cpp -lauparse -o splitlog
	mv splitlog ../bin/splitlog

staging:staging.cpp
	g++ staging.cpp -o staging
	sudo ./prep.sh

clean:
	rm $(TARGET)
