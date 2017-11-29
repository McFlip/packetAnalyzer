#use make all for normal project
#FLAGS = -std=c++11 -ggdb -g3 -O0 -fno-inline -Wall -pedantic
FLAGS = -std=c++11 -ggdb -g3 -Wall -pedantic
PROGRAM = pAnalyzer.x
OBJECT = pAnalyzer.o
SOURCE = pAnalyzer.cpp
HEADER = pAnalyzer.h
all:     $(OBJECT) $(OBJECT2)
	g++ -o $(PROGRAM) $(OBJECT) 2>> log.txt
$(OBJECT):       $(SOURCE) $(HEADER)
	g++ $(FLAGS) -o $(OBJECT) -c $(SOURCE) 2>> log.txt
clean:
	rm -f *.o *.so $(PROGRAM)
	rm -f log.txt
