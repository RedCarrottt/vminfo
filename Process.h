#if !defined(_PROCESS_H)
#define _PROCESS_H

class Process {
public:
	Process(int pid);

	int getPid();
	int getText();
	int getData();
//	int getBssHeap();
	int getStack();
	int getSharedLibrary();
	int getPss();
private:
	void getProcessInfo();
	void getPssFromSmaps();

	int mPid;

	int mTextSegment;
	int mStackSegment;
	int mDataSegment;
//	int mDataStack;
	int mSharedLibrary;
	int mPss;

	int mInitFailed;
};

#endif
