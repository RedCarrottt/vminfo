#if !defined(_PROCESS_GROUP_H)
#define _PROCESS_GROUP_H
#include <vector>
#include "Process.h"

class ProcessGroup {
public:
	ProcessGroup(const char* process_name);
	~ProcessGroup();
	const char* getProcessName();
	void getTotalMessage(char* buffer, int bufferSize);

  static int sMaxPss;

private:
	Process& getProcess(int index);

	int getSize();
	void setProcesses();
	std::vector<Process*> mProcesses;
	char* mProcessName;
};

#endif // !defined(_PROCESS_GROUP_H)
