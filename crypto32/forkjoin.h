#ifndef CRYPTOPP_FORKJOIN_H
#define CRYPTOPP_FORKJOIN_H

#include "cryptlib.h"
#include "filters.h"
#include "queue.h"

NAMESPACE_BEGIN(CryptoPP)

class Fork : public BufferedTransformation
{
public:
	Fork(unsigned int number_of_outports, BufferedTransformation *const *outports = NULL);
	Fork(BufferedTransformation *outport0, BufferedTransformation *outport1 = NULL);

	void SelectOutPort(unsigned int portNumber);

	bool Attachable() {return true;}
	void Detach(BufferedTransformation *newOut = NULL);
	void Attach(BufferedTransformation *newOut);
	void Close();

	unsigned long MaxRetrieveable()
		{return outPorts[currentPort]->MaxRetrieveable();}

	unsigned int Get(byte &outByte)
		{return outPorts[currentPort]->Get(outByte);}
	unsigned int Get(byte *outString, unsigned int getMax)
		{return outPorts[currentPort]->Get(outString, getMax);}
	unsigned int Peek(byte &outByte) const
		{return outPorts[currentPort]->Peek(outByte);}
	unsigned int Peek(byte *outString, unsigned int peekMax) const
		{return outPorts[currentPort]->Peek(outString, peekMax);}
	unsigned long CopyTo(BufferedTransformation &target) const
		{return outPorts[currentPort]->CopyTo(target);}
	unsigned int CopyTo(BufferedTransformation &target, unsigned int copyMax) const
		{return outPorts[currentPort]->CopyTo(target, copyMax);}

	void Put(byte inByte);
	void Put(const byte *inString, unsigned int length);

protected:
	unsigned int NumberOfPorts() const {return numberOfPorts;}
	BufferedTransformation& AccessPort(unsigned int i) {return *outPorts[i];}

private:
	Fork(const Fork &); // no copying allowed

	unsigned int numberOfPorts, currentPort;
	vector_member_ptrs<BufferedTransformation> outPorts;
};

class Join;

class JoinInterface : public BufferedTransformation
{
public:
	JoinInterface(Join &p, ByteQueue &b, int i)
		: parent(p), bq(b), id(i) {}

	unsigned long MaxRetrieveable();
	void Close();
	bool Attachable() {return true;}
	void Detach(BufferedTransformation *bt);
	void Attach(BufferedTransformation *bt);

	void Put(byte inByte);
	void Put(const byte *inString, unsigned int length);
	unsigned int Get(byte &outByte);
	unsigned int Get(byte *outString, unsigned int getMax);
	unsigned int Peek(byte &outByte) const;
	unsigned int Peek(byte *outString, unsigned int peekMax) const;
	unsigned long CopyTo(BufferedTransformation &target) const;
	unsigned int CopyTo(BufferedTransformation &target, unsigned int copyMax) const;

private:
	Join &parent;
	ByteQueue &bq;
	const int id;
};

class Join : public Filter
{
public:
	Join(unsigned int number_of_inports, BufferedTransformation *outQ = NULL);

	// Note that ReleaseInterface is similar but not completely compatible 
	// with SelectInterface of version 2.0.  ReleaseInterface can be called
	// only once for each interface, and if an interface is released,
	// the caller will be responsible for deleting it.
	JoinInterface *ReleaseInterface(unsigned int i);

	virtual void NotifyInput(unsigned int interfaceId, unsigned int length);
	virtual void NotifyClose(unsigned int interfaceId);

	void Put(byte inByte) {AttachedTransformation()->Put(inByte);}
	void Put(const byte *inString, unsigned int length)
		{AttachedTransformation()->Put(inString, length);}

protected:
	unsigned int NumberOfPorts() const {return numberOfPorts;}
	ByteQueue& AccessPort(unsigned int i) {return *inPorts[i];}
	unsigned int InterfacesOpen() const {return interfacesOpen;}

private:
	Join(const Join &); // no copying allowed

	unsigned int numberOfPorts;
	vector_member_ptrs<ByteQueue> inPorts;
	unsigned int interfacesOpen;
	vector_member_ptrs<JoinInterface> interfaces;
};

NAMESPACE_END

#endif
