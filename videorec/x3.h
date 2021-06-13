
// xCBMini_GetInterface
class xCBMini
{
public:
	int (*New)(int *); // New()
	int (*DoUnk1)();
	int (*DoUnk2)(); // 0x80030050
	int (*DoUnk3)(int r3,int r4,int * r5, void * r6);
	int (*DoUnk4)();
	int (*CreateQuery)();
	int (*DoUnk6)();
	int (*DoUnk7)();
	int (*DoUnk8)();
	int (*DoUnk9)();
	int (*DoUnk10)();
	int (*DoUnk11)();
	int (*DoUnk12)();
	int (*DoUnk13)(); // 0x80030050
	int (*CreateResultIterator)();
	int (*DoUnk15)();
	int (*DoUnk16)();
	int (*DoUnk17)();
	int (*DoUnk18)();
	int (*DoUnk19)();
	int (*ResultIteratorLookItemByIndex)(); // ResultIteratorLookItemByIndex
	int (*ResultIteratorGetItemByPosition)(); // ResultIteratorGetItemByPosition 
	int (*ResultIteratorGetCurrentPosition)(); // ResultIteratorGetCurrentPosition
	int (*DoUnk23)();
	int (*ResultIteratorSetCurrentByIDEx)(); // ResultIteratorSetCurrentByIDEx
	int (*ResultIteratorGetTotal)(); // ResultIteratorGetTotal
	int (*DoUnk26)(); // 0x80030050
	int (*DoUnk27)();
	int (*DoUnk28)();
	int (*DoUnk29)();
	int (*DoUnk30)();
	int (*DoUnk31)(); // 0x00000000
	int (*DoUnk32)();
	int (*GetMetadataType)(int r3, unsigned long long r4, int * r5); // GetMetadataType
	int (*DoUnk34)();
	int (*CreateMetaList)(int r3, int* r4); // CreateMetaList
	int (*DoUnk36)(int r3, int r4);
	int (*AppendItemToMetaList)(int r3, int r4, int * r5); // AppendItemToMetaList
	int (*DoUnk38)();
	int (*GetItemFromMetaList)(); // GetItemFromMetaList
	int (*SetItemToMetaList)(); // SetItemToMetaList
	int (*DoUnk41)();
	int (*GetMetaData)(); // GetMetaData
	int (*SetMetaData)(int r3, unsigned long long r4, int r5); // SetMetaData
	int (*DoUnk44)();
	int (*DoUnk45)();
	int (*DoUnk46)();
	int (*DoUnk47)(); // 0x80030050
	int (*DoUnk48)(); // 0x80030050
	int (*DoUnk49)();
	int (*DoUnk50)();
	int (*DoUnk51)(); // 0x80030050
	int (*DoUnk52)();
	int (*DoUnk53)();
	int (*DoUnk54)();
	int (*DoUnk55)();
	int (*DoUnk56)();
	int (*DoUnk57)();
	int (*DoUnk58)(); // 0x80030050
	int (*DoUnk59)(); // 0x80030050
	int (*DoUnk60)(); // Delete_Async
	int (*DoUnk61)(); // 0x80030050
	int (*DoUnk62)(); // 0x80030050
	int (*DoUnk63)();
	int (*DoUnk64)();
	int (*DoUnk65)(); // 0x80030050
	int (*MoveAsyncWithFlag)(int r3, int * r4, int r5, int * r6); // MoveAsyncWithFlag
	int (*DoUnk67)();
	int (*DoUnk68)(); // 0x80030050
	int (*DoUnk69)(); // 0x80030050
	int (*DoUnk70)(); // 0x80030050
	int (*DoUnk71)();
	int (*DoUnk72)();
	int (*DoUnk73)(); // 0x80030050
	int (*DoUnk74)(); // 0x80030050
	int (*DoUnk75)(); // 0x80030050
	int (*DoUnk76)(); // 0x80030050
	int (*DoUnk77)(); // 0x80030050
	int (*DoUnk78)();
	int (*DoUnk79)();
	int (*DoUnk80)(); // 0x80030050
	unsigned long long (*DoUnk81)();
	int (*DoUnk82)();
	int (*DoUnk83)(); // 0x80030050
	int (*GenerateMetadataFromFileWithOption)(int r3, char * r4, int * r5, int r6, int * r7, int * r8); // GenerateMetadataFromFileWithOption
	int (*DoUnk85)();
	int (*DoUnk86)();
	int (*DoUnk87)(); // 0x80030050
	int (*DoUnk88)();
	int (*DoUnk89)();
	int (*DoUnk90)();
	int (*DoUnk91)(); // 0x80030050
	int (*DoUnk92)(); // 0x80030050
	int (*DoUnk93)(int r3, const char * r4, const char * r5);
	int (*DoUnk94)();
	int (*DoUnk95)();
	int (*DoUnk96)(); // 0x80030050
	int (*DoUnk97)(); // 0x80030050
	int (*DoUnk98)(); // 0x80030050
	int (*DoUnk99)(); // 0x80030050
	int (*DoUnk100)(); // 0x80030050
	int (*DoUnk101)(); // 0x80030050
	int (*DoUnk102)(); // 0x80030050
	int (*DoUnk103)(); // 0x80030050
	int (*DoUnk104)(); // 0x80030050
	int (*DoUnk105)(); // 0x80030050
	int (*DoUnk106)(); // 0x80030050
	int (*DoUnk107)(); // 0x80030050
	int (*DoUnk108)(); // 0x80030050
	int (*DoUnk109)(); // 0x80030050
	int (*DoUnk110)(); // 0x80030050
	int (*DoUnk111)(); // 0
	int (*DoUnk112)(); // 0
	int (*DoUnk113)();
	int (*DoUnk114)(); // 0
	int (*DoUnk115)(); // 0
	int (*DoUnk116)(); // 0
	int (*DoUnk117)(); // 0
	int (*DoUnk118)(); // 0
	int (*DoUnk119)(); // 0
	int (*DoUnk120)(); // 0
	int (*DoUnk121)(); // 0
	int (*DoUnk122)(); // 0
	int (*DoUnk123)(); // 0
	int (*DoUnk124)(); // 0
	int (*DoUnk125)(); // 0
	int (*DoUnk126)(); // 0
	int (*DoUnk127)(); // 0
	int (*DoUnk128)(); // 0
	int (*DoUnk129)(); // 0
	int (*DoUnk130)(); // 0
	int (*DoUnk131)(); // 0
	int (*DoUnk132)(); // 0
}; xCBMini * iCBMini;