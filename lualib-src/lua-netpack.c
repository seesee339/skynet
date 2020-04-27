#define LUA_LIB

#include "skynet_malloc.h"

#include "skynet_socket.h"

#include <lua.h>
#include <lauxlib.h>

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#define QUEUESIZE 1024
#define HASHSIZE 4096
#define SMALLSTRING 2048

#define TYPE_DATA 1
#define TYPE_MORE 2
#define TYPE_ERROR 3
#define TYPE_OPEN 4
#define TYPE_CLOSE 5
#define TYPE_WARNING 6

//LWPADD for ext
#define HEAD_EXT_FLAG 0xFFFF
#define HEAD_FLAG_TOP 0x80
#define HEAD_FLAG_BIG_DATA 0x40
#define HEAD_FLAG_CRC 0x20
#define HEAD_FLAG_ZIP 0x10
//END

/*
	Each package is uint16 + data , uint16 (serialized in big-endian) is the number of bytes comprising the data .
	if headsize == 0xFFFF then use ext format:
	0xFFFF|headSize(8bit)|headdata|data
	headSize:<=8
	headdata:flag(8bit)|datasize(16bit or 32bit)|extFlags
	the flag: 0|isBigData|crccheck|zipflag|unused|unused|unused|unused
	datasize: uint16 or 00000000|uint24(isBigData)
	extFlags: crc8(if crccheck)
 */

struct netpack {
	int id;
	int size;
	void * buffer;
};

struct uncomplete {
	struct netpack pack;
	struct uncomplete * next;
	//LWPADD for ext
	int read;//-1 for nomal head read, -2 for ext head read, >=0 for data read
	//int header;

	//ext heads
	uint8_t flag;
	uint8_t crc8;
	uint8_t readHead;//the readed size
	uint8_t head_size;//the headdata size
	uint8_t head[8];
	//END
};

struct queue {
	int cap;
	int head;
	int tail;
	struct uncomplete * hash[HASHSIZE];
	struct netpack queue[QUEUESIZE];
};

static void
clear_list(struct uncomplete * uc) {
	while (uc) {
		skynet_free(uc->pack.buffer);
		void * tmp = uc;
		uc = uc->next;
		skynet_free(tmp);
	}
}

static int
lclear(lua_State *L) {
	struct queue * q = lua_touserdata(L, 1);
	if (q == NULL) {
		return 0;
	}
	int i;
	for (i=0;i<HASHSIZE;i++) {
		clear_list(q->hash[i]);
		q->hash[i] = NULL;
	}
	if (q->head > q->tail) {
		q->tail += q->cap;
	}
	for (i=q->head;i<q->tail;i++) {
		struct netpack *np = &q->queue[i % q->cap];
		skynet_free(np->buffer);
	}
	q->head = q->tail = 0;

	return 0;
}

static inline int
hash_fd(int fd) {
	int a = fd >> 24;
	int b = fd >> 12;
	int c = fd;
	return (int)(((uint32_t)(a + b + c)) % HASHSIZE);
}

static struct uncomplete *
find_uncomplete(struct queue *q, int fd) {
	if (q == NULL)
		return NULL;
	int h = hash_fd(fd);
	struct uncomplete * uc = q->hash[h];
	if (uc == NULL)
		return NULL;
	if (uc->pack.id == fd) {
		q->hash[h] = uc->next;
		return uc;
	}
	struct uncomplete * last = uc;
	while (last->next) {
		uc = last->next;
		if (uc->pack.id == fd) {
			last->next = uc->next;
			return uc;
		}
		last = uc;
	}
	return NULL;
}

static struct queue *
get_queue(lua_State *L) {
	struct queue *q = lua_touserdata(L,1);
	if (q == NULL) {
		q = lua_newuserdata(L, sizeof(struct queue));
		q->cap = QUEUESIZE;
		q->head = 0;
		q->tail = 0;
		int i;
		for (i=0;i<HASHSIZE;i++) {
			q->hash[i] = NULL;
		}
		lua_replace(L, 1);
	}
	return q;
}

static void
expand_queue(lua_State *L, struct queue *q) {
	struct queue *nq = lua_newuserdata(L, sizeof(struct queue) + q->cap * sizeof(struct netpack));
	nq->cap = q->cap + QUEUESIZE;
	nq->head = 0;
	nq->tail = q->cap;
	memcpy(nq->hash, q->hash, sizeof(nq->hash));
	memset(q->hash, 0, sizeof(q->hash));
	int i;
	for (i=0;i<q->cap;i++) {
		int idx = (q->head + i) % q->cap;
		nq->queue[i] = q->queue[idx];
	}
	q->head = q->tail = 0;
	lua_replace(L,1);
}

static void
push_data(lua_State *L, int fd, void *buffer, int size, int clone) {
	if (clone) {
		void * tmp = skynet_malloc(size);
		memcpy(tmp, buffer, size);
		buffer = tmp;
	}
	struct queue *q = get_queue(L);
	struct netpack *np = &q->queue[q->tail];
	if (++q->tail >= q->cap)
		q->tail -= q->cap;
	np->id = fd;
	np->buffer = buffer;
	np->size = size;
	if (q->head == q->tail) {
		expand_queue(L, q);
	}
}

static struct uncomplete *
save_uncomplete(lua_State *L, int fd) {
	struct queue *q = get_queue(L);
	int h = hash_fd(fd);
	struct uncomplete * uc = skynet_malloc(sizeof(struct uncomplete));
	memset(uc, 0, sizeof(*uc));
	uc->next = q->hash[h];
	uc->pack.id = fd;
	q->hash[h] = uc;

	return uc;
}

static inline int
read_size(uint8_t * buffer) {
	int r = (int)buffer[0] << 8 | (int)buffer[1];
	return r;
}

//LWPADD EXT 
static int get_queue_size(lua_State *L)
{
	struct queue *q = get_queue(L);
	int size = q->tail-q->head;
	if(size<0)
	{
		size += q->cap;
	}
	
	return size;
}

static inline int read_big_size(uint8_t * buffer) 
{
	if(buffer[0] != 0) //the first 8bit must be 0
		return -1;
	int r = (int)buffer[1] << 16 | (int)buffer[2]<<8 | (int)buffer[3];
	return r;
}

static int parse_ext_head(uint8_t *buffer,int headSize,uint8_t* pFlag,int* psize,uint8_t* crc8)
{
	if(headSize<1)
		return -1;

	uint8_t flag = buffer[0];
	*pFlag = flag;
	buffer+=1;
	headSize-=1;
	if((flag&HEAD_FLAG_TOP)>0)
		return -1;

	if((flag&HEAD_FLAG_BIG_DATA)>0)
	{
		if(headSize<4)
			return -1;
		*psize = read_big_size( buffer);
		buffer+=4;
		headSize-=4;
		if(*psize<0)
			return -1;
	}
	else
	{
		if(headSize<2)
			return -1;
		*psize = read_size( buffer);
		buffer+=2;
		headSize-=2;
	}

	if((flag&HEAD_FLAG_CRC)>0)
	{
		if(headSize<1)
			return -1;
		*crc8 = buffer[0];
		buffer+=1;
		headSize-=1;
	}

	return 0;
}

/*
 * static uint8_t sht75_crc_table[];
 *
 * The SHT75 humidity sensor is capable of calculating an 8 bit CRC checksum to
 * ensure data integrity. The lookup table crc_table[] is used to recalculate
 * the CRC. 
 */
#define		CRC_START_8		0x00
static uint8_t sht75_crc_table[] = {

	0,   49,  98,  83,  196, 245, 166, 151, 185, 136, 219, 234, 125, 76,  31,  46,
	67,  114, 33,  16,  135, 182, 229, 212, 250, 203, 152, 169, 62,  15,  92,  109,
	134, 183, 228, 213, 66,  115, 32,  17,  63,  14,  93,  108, 251, 202, 153, 168,
	197, 244, 167, 150, 1,   48,  99,  82,  124, 77,  30,  47,  184, 137, 218, 235,
	61,  12,  95,  110, 249, 200, 155, 170, 132, 181, 230, 215, 64,  113, 34,  19,
	126, 79,  28,  45,  186, 139, 216, 233, 199, 246, 165, 148, 3,   50,  97,  80,
	187, 138, 217, 232, 127, 78,  29,  44,  2,   51,  96,  81,  198, 247, 164, 149,
	248, 201, 154, 171, 60,  13,  94,  111, 65,  112, 35,  18,  133, 180, 231, 214,
	122, 75,  24,  41,  190, 143, 220, 237, 195, 242, 161, 144, 7,   54,  101, 84,
	57,  8,   91,  106, 253, 204, 159, 174, 128, 177, 226, 211, 68,  117, 38,  23,
	252, 205, 158, 175, 56,  9,   90,  107, 69,  116, 39,  22,  129, 176, 227, 210,
	191, 142, 221, 236, 123, 74,  25,  40,  6,   55,  100, 85,  194, 243, 160, 145,
	71,  118, 37,  20,  131, 178, 225, 208, 254, 207, 156, 173, 58,  11,  88,  105,
	4,   53,  102, 87,  192, 241, 162, 147, 189, 140, 223, 238, 121, 72,  27,  42,
	193, 240, 163, 146, 5,   52,  103, 86,  120, 73,  26,  43,  188, 141, 222, 239,
	130, 179, 224, 209, 70,  119, 36,  21,  59,  10,  89,  104, 255, 206, 157, 172
};

/*
 * uint8_t crc_8( const unsigned char *input_str, size_t num_bytes );
 *
 * The function crc_8() calculates the 8 bit wide CRC of an input string of a
 * given length.
 */

static uint8_t crc_8( const uint8_t *input_str, int num_bytes ) {

	int a;
	uint8_t crc;
	const uint8_t *ptr;

	crc = CRC_START_8;
	ptr = input_str;

	if ( ptr != NULL ) for (a=0; a<num_bytes; a++) {

		crc = sht75_crc_table[(*ptr++) ^ crc];
	}

	return crc;

}  /* crc_8 */

static int checkCrc(uint8_t *buffer,int size,uint8_t crc8)
{
	uint8_t crcRes = crc_8( buffer, size);
	return (crc8 == crcRes)?0:-1;
}

static uint8_t* unzipData(uint8_t *buffer,int size,int* pNewSize)
{
	if(size<5)
		return NULL;
	unsigned long newSize = read_big_size(buffer);
	buffer+=4;
	size-=4;
	if(newSize<=0 || newSize>((int)1<<24))
		return NULL;

	uint8_t* newData = skynet_malloc(newSize);
	if(newData==NULL)
	{
		//printf("no enough memory!\n");
		return NULL;
	}

	if(uncompress(newData, &newSize, buffer, size) != Z_OK)
	{
		skynet_free(newData);
		//printf("uncompress failed!\n");
		return NULL;
	}

	*pNewSize = newSize;
	return newData;
}

static uint8_t* zipData(const uint8_t* buffer,int size,int* pNewSize)
{
	if(buffer==NULL || size==0)
		return NULL;

	unsigned long newSize = compressBound(size)+4;
	uint8_t* newData = skynet_malloc(newSize);
	if(newData == NULL)
	{
		//printf("no enough memory!\n");
		return NULL;
	}

	/* 压缩 */
	if(compress(newData+4, &newSize, buffer, size) != Z_OK)
	{
		//printf("compress failed!\n");
		skynet_free(newData);
		return NULL;
	}

	if(newSize+4>=((int)1<<24))
	{
		//printf("newSize failed!\n");
		skynet_free(newData);
		return NULL;
	}

	newData[0] = 0;
	newData[1] = (newSize>>16)& 0xff;
	newData[2] = (newSize>>8)& 0xff;
	newData[3] = newSize&0xff;

	newSize+=4;

	*pNewSize = newSize;
	return newData;
}

static void saveUC(lua_State *L,int fd,struct uncomplete *uc,uint8_t isInStack )
{
	struct queue *q = get_queue(L);
	if(isInStack)
	{
		struct uncomplete * ucNew = save_uncomplete(L, fd);
		uc->next = ucNew->next;
		*ucNew = *uc;
	}
	else
	{
		int h = hash_fd(fd);
		uc->next = q->hash[h];
		q->hash[h] = uc;
	}
}

static void clearUC(struct uncomplete * uc,uint8_t isInStack) 
{
	if (uc) 
	{
		if(uc->pack.buffer)
			skynet_free(uc->pack.buffer);

		if(!isInStack)
		{
			skynet_free(uc);
		}
	}
}


static int
push_more(lua_State *L, int fd, uint8_t *buffer, int size,struct uncomplete *uc,uint8_t isInStack );

static int deal_ext(lua_State *L, int fd, uint8_t *buffer, int size,struct uncomplete *uc,uint8_t isInStack )
{
	if(size <= 0)
	{
		saveUC(L,fd,uc,isInStack);
		return 0;
	}

	if(uc->read == -2 )
	{// fill head
		if(uc->head_size == 0)
		{//read head size
			uint8_t head_size=buffer[0];
			buffer += 1;
			size -= 1;
			if(head_size<3 || head_size>8)
			{
				clearUC(uc,isInStack);
				return -1;//format error
			}
			uc->readHead = 0;
			uc->head_size = head_size;
			if(size <= 0)
			{
				saveUC(L,fd,uc,isInStack);
				return 0;
			}
		}
		
		assert(uc->readHead >= 0 && uc->readHead<uc->head_size);
		int need = uc->head_size - uc->readHead;
		if(need<0)
		{
			clearUC(uc,isInStack);
			return -1;
		}

		if (size < need) 
		{
			memcpy(uc->head + uc->readHead, buffer, size);
			uc->readHead += size;
			saveUC(L,fd,uc,isInStack);
			return 0;
		}

		memcpy(uc->head + uc->readHead, buffer, need);
		buffer += need;
		size -= need;
		
		uint8_t flag = 0;
		int psize = 0;
		uint8_t crc8 = 0;
		int ret = parse_ext_head(uc->head,uc->head_size,&flag,&psize,&crc8);
		if(ret != 0 || psize<=0)
		{
			clearUC(uc,isInStack);
			return -1;//format error
		}

		uc->flag = flag;
		uc->crc8 = crc8;
		uc->pack.size = psize;
		uc->pack.buffer = skynet_malloc(psize);
		uc->read = 0;

		if(size <= 0)
		{
			saveUC(L,fd,uc,isInStack);
			return 0;
		}
	}

	// read size
	assert(uc->read >= 0 && uc->read<uc->pack.size);
	int need = uc->pack.size - uc->read;
	if(need<0)
	{
		clearUC(uc,isInStack);
		return -1;
	}

	if (size < need) 
	{
		memcpy(uc->pack.buffer + uc->read, buffer, size);
		uc->read += size;
		saveUC(L,fd,uc,isInStack);
		return 0;
	}

	memcpy(uc->pack.buffer + uc->read, buffer, need);
	buffer += need;
	size -= need;
	uc->read += need;
	if((uc->flag&HEAD_FLAG_CRC)>0)
	{
		if(checkCrc(uc->pack.buffer, uc->pack.size,uc->crc8)!=0)
		{
			clearUC(uc,isInStack);
			return -1;
		}
	}

	if((uc->flag&HEAD_FLAG_ZIP)>0)
	{
		int newSize = 0;
		uint8_t* pUnzipData = unzipData(uc->pack.buffer, uc->pack.size,&newSize);
		if(pUnzipData == NULL || newSize<=0)
		{
			clearUC(uc,isInStack);
			return -1;
		}
		push_data(L, fd, pUnzipData, newSize, 0);
	}
	else
	{
		push_data(L, fd, uc->pack.buffer, uc->pack.size, 0);
		uc->pack.buffer = NULL;
		uc->pack.size = 0;
	}
	clearUC(uc,isInStack);

	if(size>0)
	{
		struct uncomplete  uc;
		memset(&uc, 0, sizeof(uc));
		uc.read = -1;
		uc.head[0] = buffer[0];
		++buffer;
		--size;
		return push_more(L,fd,buffer,size,&uc,1);
	}
	
	return 0;
}

static int
push_more(lua_State *L, int fd, uint8_t *buffer, int size,struct uncomplete *uc,uint8_t isInStack ) 
{
	if(size <= 0)
	{
		saveUC(L,fd,uc,isInStack);
		return 0;
	}

	if (uc->read ==-1)
	{ //orign head fill
		int pack_size = *buffer;
		pack_size |= uc->head[0] << 8 ;
		++buffer;
		--size;

		if(pack_size == HEAD_EXT_FLAG)
		{
			uc->read = -2;
		}
		else
		{
			uc->pack.size = pack_size;
			uc->pack.buffer = skynet_malloc(pack_size);
			uc->read = 0;
		}

		if(size <= 0)
		{
			saveUC(L,fd,uc,isInStack);
			return 0;
		}
	}

	if(uc->read == -2 || (uc->read==0&&uc->head_size>0))
	{// ext head fill
		return deal_ext(L, fd, buffer,size,uc,isInStack);
	}

	// read size
	assert(uc->read >= 0 && uc->read<uc->pack.size);
	int need = uc->pack.size - uc->read;
	if(need<0)
	{
		clearUC(uc,isInStack);
		return -1;
	}

	if (size < need) 
	{
		memcpy(uc->pack.buffer + uc->read, buffer, size);
		uc->read += size;
		saveUC(L,fd,uc,isInStack);
		return 0;
	}

	memcpy(uc->pack.buffer + uc->read, buffer, need);
	buffer += need;
	size -= need;
	push_data(L, fd, uc->pack.buffer, uc->pack.size, 0);
	uc->pack.buffer = NULL;
	uc->pack.size = 0;
	clearUC(uc,isInStack);

	if(size>0)
	{
		struct uncomplete  uc;
		memset(&uc, 0, sizeof(uc));
		uc.read = -1;
		uc.head[0] = buffer[0];
		++buffer;
		--size;
		return push_more(L,fd,buffer,size,&uc,1);
	}

	return 0;
}

//END

static void
close_uncomplete(lua_State *L, int fd) {
	struct queue *q = lua_touserdata(L,1);
	struct uncomplete * uc = find_uncomplete(q, fd);
	if (uc) {
		skynet_free(uc->pack.buffer);
		skynet_free(uc);
	}
}

static int
filter_data_(lua_State *L, int fd, uint8_t * buffer, int size) 
{
	if(size == 0)
		return 1;

	struct queue *q = lua_touserdata(L,1);
	struct uncomplete * uc = find_uncomplete(q, fd);
	int pushRet = 0;
	if (uc) 
	{
		pushRet = push_more(L,fd,buffer,size,uc,0);
	} 
	else 
	{
		struct uncomplete  uc;
		memset(&uc, 0, sizeof(uc));
		uc.read = -1;
		uc.head[0] = buffer[0];
		++buffer;
		--size;

		pushRet = push_more(L,fd,buffer,size,&uc,1);
	}

	if(pushRet != 0)
	{//parse data error
		close_uncomplete(L, fd);
		lua_pushvalue(L, lua_upvalueindex(TYPE_ERROR));
		lua_pushinteger(L, fd);
		lua_pushliteral(L, "parse data error!");
		return 4;
	}
	else
	{
		//get queue size
		int queueSize = get_queue_size(L);
		if(queueSize==1)
		{
			lua_pushvalue(L, lua_upvalueindex(TYPE_DATA));
			return 2;
		}
		else if(queueSize>=1)
		{
			lua_pushvalue(L, lua_upvalueindex(TYPE_MORE));
			return 2;
		}
		else
		{
			return 1;
		}
	}

}

static inline int
filter_data(lua_State *L, int fd, uint8_t * buffer, int size) {
	int ret = filter_data_(L, fd, buffer, size);
	// buffer is the data of socket message, it malloc at socket_server.c : function forward_message .
	// it should be free before return,
	skynet_free(buffer);
	return ret;
}

static void
pushstring(lua_State *L, const char * msg, int size) {
	if (msg) {
		lua_pushlstring(L, msg, size);
	} else {
		lua_pushliteral(L, "");
	}
}

/*
	userdata queue
	lightuserdata msg
	integer size
	return
		userdata queue
		integer type
		integer fd
		string msg | lightuserdata/integer
 */
static int
lfilter(lua_State *L) {
	struct skynet_socket_message *message = lua_touserdata(L,2);
	int size = luaL_checkinteger(L,3);
	char * buffer = message->buffer;
	if (buffer == NULL) {
		buffer = (char *)(message+1);
		size -= sizeof(*message);
	} else {
		size = -1;
	}

	lua_settop(L, 1);

	switch(message->type) {
	case SKYNET_SOCKET_TYPE_DATA:
		// ignore listen id (message->id)
		assert(size == -1);	// never padding string
		return filter_data(L, message->id, (uint8_t *)buffer, message->ud);
	case SKYNET_SOCKET_TYPE_CONNECT:
		// ignore listen fd connect
		return 1;
	case SKYNET_SOCKET_TYPE_CLOSE:
		// no more data in fd (message->id)
		close_uncomplete(L, message->id);
		lua_pushvalue(L, lua_upvalueindex(TYPE_CLOSE));
		lua_pushinteger(L, message->id);
		return 3;
	case SKYNET_SOCKET_TYPE_ACCEPT:
		lua_pushvalue(L, lua_upvalueindex(TYPE_OPEN));
		// ignore listen id (message->id);
		lua_pushinteger(L, message->ud);
		pushstring(L, buffer, size);
		return 4;
	case SKYNET_SOCKET_TYPE_ERROR:
		// no more data in fd (message->id)
		close_uncomplete(L, message->id);
		lua_pushvalue(L, lua_upvalueindex(TYPE_ERROR));
		lua_pushinteger(L, message->id);
		pushstring(L, buffer, size);
		return 4;
	case SKYNET_SOCKET_TYPE_WARNING:
		lua_pushvalue(L, lua_upvalueindex(TYPE_WARNING));
		lua_pushinteger(L, message->id);
		lua_pushinteger(L, message->ud);
		return 4;
	default:
		// never get here
		return 1;
	}
}

/*
	userdata queue
	return
		integer fd
		lightuserdata msg
		integer size
 */
static int
lpop(lua_State *L) {
	struct queue * q = lua_touserdata(L, 1);
	if (q == NULL || q->head == q->tail)
		return 0;
	struct netpack *np = &q->queue[q->head];
	if (++q->head >= q->cap) {
		q->head = 0;
	}
	lua_pushinteger(L, np->id);
	lua_pushlightuserdata(L, np->buffer);
	lua_pushinteger(L, np->size);

	return 3;
}

/*
	string msg | lightuserdata/integer

	lightuserdata/integer
 */

static const char *
tolstring(lua_State *L, size_t *sz, int index) {
	const char * ptr;
	if (lua_isuserdata(L,index)) {
		ptr = (const char *)lua_touserdata(L,index);
		*sz = (size_t)luaL_checkinteger(L, index+1);
	} else {
		ptr = luaL_checklstring(L, index, sz);
	}
	return ptr;
}

static inline void
write_size(uint8_t * buffer, int len) {
	buffer[0] = (len >> 8) & 0xff;
	buffer[1] = len & 0xff;
}

static inline void
write_big_size(uint8_t * buffer, int len) 
{
	buffer[0] = 0;
	buffer[1] = (len>>16)& 0xff;
	buffer[2] = (len>>8)& 0xff;
	buffer[3] = len&0xff;
}

static int
lpack(lua_State *L) {
	size_t len;
	const char * ptr = tolstring(L, &len, 1);
	if (len >= 0xFFFF) {
		return luaL_error(L, "Invalid size (too long) of data : %d", (int)len);
	}

	uint8_t * buffer = skynet_malloc(len + 2);
	write_size(buffer, len);
	memcpy(buffer+2, ptr, len);

	lua_pushlightuserdata(L, buffer);
	lua_pushinteger(L, len + 2);

	return 2;
}

static int packExt(lua_State *L,const char * ptr,size_t len,int iUseZip,int iUseCRC)
{	
	if (len >= 0xFFFF00) 
	{
		return luaL_error(L, "Invalid size (too long) of data : %d", (int)len);
	}
	//get the buffer size
	int iDataSize = len;
	const uint8_t* pData = (const uint8_t*)ptr;
	int headSize = 1;
	uint8_t flag = HEAD_FLAG_TOP;
	uint8_t crcRes = 0;
	if(iUseZip)
	{
		flag = flag|HEAD_FLAG_ZIP;
		pData = zipData(pData,(int)len,&iDataSize);
		if(pData == NULL || iDataSize<=0)
		{
			return luaL_error(L, "zip data error: len=%d", (int)len);
		}
	}
	uint8_t isBigData = iDataSize>0xFFFF;
	headSize += isBigData?4:2;
	if(isBigData)
	{
		flag = flag|HEAD_FLAG_BIG_DATA;
	}
	
	if(iUseCRC)
	{
		flag = flag|HEAD_FLAG_CRC;
		headSize += 1;
		crcRes = crc_8(pData, iDataSize);
	}

	int iBufferSize = 2+1+headSize+iDataSize;
	uint8_t * buffer = skynet_malloc(iBufferSize);
	buffer[0] = 0xFF;
	buffer[1] = 0xFF;
	buffer[2] = headSize;
	buffer[3] = flag;
	int iWriteSize = 4;
	if(isBigData)
	{
		write_big_size(buffer+iWriteSize,iDataSize);
		iWriteSize+=4;
	}
	else
	{
		write_size(buffer+iWriteSize,iDataSize);
		iWriteSize+=2;
	}
	if(iUseCRC)
	{
		buffer[iWriteSize] = crcRes;
		iWriteSize+=1;
	}
	memcpy(buffer+iWriteSize, pData, iDataSize);

	lua_pushlightuserdata(L, buffer);
	lua_pushinteger(L, iBufferSize);
	return 2;
}


//Args: string(or ptr,size),iUseZip,iUseCRC
static int
lpack_ext(lua_State *L) 
{
	int nArg = lua_gettop(L);
	int iIndex = 1;
	size_t len=0;
	const char * ptr = NULL;
	if (lua_isuserdata(L,iIndex)) 
	{
		ptr = (const char *)lua_touserdata(L,iIndex);
		len = (size_t)luaL_checkinteger(L, iIndex+1);
		iIndex+=2;
	} else {
		ptr = luaL_checklstring(L, iIndex, &len);
		iIndex+=1;
	}

	if(ptr==NULL || len<=0)
	{
		return luaL_error(L, "Invalid  data : len = %d", (int)len);
	}

	int iUseZip = len>=1024;
	int iUseCRC = 1;
	if(nArg>=iIndex)
	{
		iUseZip = (int)luaL_checkinteger(L, iIndex);
		iIndex+=1;
	}

	if(nArg>=iIndex)
	{
		iUseCRC = (int)luaL_checkinteger(L, iIndex);
		iIndex+=1;
	}

	if(iUseZip==0 && iUseCRC==0 && len < 0xFFFF)
	{// use simple head
		uint8_t * buffer = skynet_malloc(len + 2);
		write_size(buffer, len);
		memcpy(buffer+2, ptr, len);

		lua_pushlightuserdata(L, buffer);
		lua_pushinteger(L, len + 2);
		return 2;
	}
	else
	{//use ext head
		return packExt(L,ptr,len,iUseZip,iUseCRC);
	}
}

static int
ltostring(lua_State *L) {
	void * ptr = lua_touserdata(L, 1);
	int size = luaL_checkinteger(L, 2);
	if (ptr == NULL) {
		lua_pushliteral(L, "");
	} else {
		lua_pushlstring(L, (const char *)ptr, size);
		skynet_free(ptr);
	}
	return 1;
}

LUAMOD_API int
luaopen_skynet_netpack(lua_State *L) {
	luaL_checkversion(L);
	luaL_Reg l[] = {
		{ "pop", lpop },
		{ "pack", lpack },
		{ "clear", lclear },
		{ "tostring", ltostring },
		{ "pack_ext", lpack_ext },
		{ NULL, NULL },
	};
	luaL_newlib(L,l);

	// the order is same with macros : TYPE_* (defined top)
	lua_pushliteral(L, "data");
	lua_pushliteral(L, "more");
	lua_pushliteral(L, "error");
	lua_pushliteral(L, "open");
	lua_pushliteral(L, "close");
	lua_pushliteral(L, "warning");

	lua_pushcclosure(L, lfilter, 6);
	lua_setfield(L, -2, "filter");

	return 1;
}
