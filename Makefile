vminfo : main.cpp ProcessGroup.cpp Process.cpp
	g++ -o vminfo main.cpp ProcessGroup.cpp Process.cpp
clean :
	rm vminfo 
