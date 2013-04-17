SRC=main.cpp \
		dedup.c \
		dedup_event.c \
		dedup_hash.c \
		dedup_sig.c \
		avltree.c \
		dedup_shatree.c \
		../auditd-parser/auread.cpp
CXX=g++
CFLAGS=-O3 -I../auditd-parser
LDFLAGS=-lcrypto \
				-L/usr/local/lib -lboost_filesystem

dedup:$(SRC)
	$(CXX) $(CFLAGS) $(SRC) $(LDFLAGS) -o dedup

dedup_test_mt:dedup_test.c dedup.c dedup_event.c dedup_hash.c dedup_sig.c avltree.c
	$(CXX) $(CFLAGS) -DMT $(SRC) $(LDFLAGS) -lpthread -o dedup_test

dedup_shatree_test:dedup_shatree_test.c dedup_shatree.c
	$(CXX) -g dedup_shatree_test.c dedup_shatree.c -o dedup_shatree_test

clean:
	rm dedup dedup_shatree_test
	sudo rm ~/mylog.log ./dedup.log
