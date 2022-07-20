from dissect import cstruct


ole_def = """
typedef short   OFFSET;
typedef ULONG   SECT;
typedef ULONG   FSINDEX;
typedef USHORT  FSOFFSET;
typedef ULONG   DFSIGNATURE;
typedef WORD    DFPROPTYPE;
typedef ULONG   SID;

typedef ULONGLONG   TIME_T;     // cheat a bit

#define DIFSECT     0xFFFFFFFC
#define FATSECT     0xFFFFFFFD
#define ENDOFCHAIN  0xFFFFFFFE
#define FREESECT    0xFFFFFFFF

enum STGTY : BYTE {
    STGTY_INVALID   = 0,
    STGTY_STORAGE   = 1,
    STGTY_STREAM    = 2,
    STGTY_LOCKBYTES = 3,
    STGTY_PROPERTY  = 4,
    STGTY_ROOT      = 5,
};

enum DECOLOR : BYTE {
    DE_RED          = 0,
    DE_BLACK        = 1,
};

struct StructuredStorageHeader {    // [offset from start in bytes, length in bytes]
    char    _abSig[8];              // [000H,08] 0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1
                                    //           for current version, was 0x0e, 0x11, 0xfc, 0x0d,
                                    //           0xd0, 0xcf, 0x11, 0xe0 on old, beta 2 files
                                    //           (late ’92) which are also supported by the
                                    //           reference implementation
    char    _clid[16];              // [008H,16] class id (set with WriteClassStg, retrieved with
                                    //           GetClassFile/ReadClassStg)
    USHORT  _uMinorVersion;         // [018H,02] minor version of the format: 33 is written by
                                    //           reference implementation
    USHORT  _uDllVersion;           // [01AH,02] major version of the dll/format: 3 is written
                                    //           by reference implementation
    USHORT  _uByteOrder;            // [01CH,02] 0xFFFE: indicates Intel byte-ordering
    USHORT  _uSectorShift;          // [01EH,02] size of sectors in power-of-two (typically 9,
                                    //           indicating 512-byte sectors)
    USHORT  _uMiniSectorShift;      // [020H,02] size of mini-sectors in power-of-two (typically 6,
                                    //           indicating 64-byte mini-sectors)
    USHORT  _usReserved;            // [022H,02] reserved, must be zero
    ULONG   _ulReserved1;           // [024H,04] reserved, must be zero
    ULONG   _ulReserved2;           // [028H,04] reserved, must be zero
    FSINDEX _csectFat;              // [02CH,04] number of SECTs in the FAT chain
    SECT    _sectDirStart;          // [030H,04] first SECT in the Directory chain
    DFSIGNATURE _signature;         // [034H,04] signature used for transactionin: must be zero.
                                    //           The reference implementation does not support
                                    //           transactioning
    ULONG   _ulMiniSectorCutoff;    // [038H,04] maximum size for mini-streams: typically 4096 bytes
    SECT    _sectMiniFatStart;      // [03CH,04] first SECT in the mini-FAT chain
    FSINDEX _csectMiniFat;          // [040H,04] number of SECTs in the mini-FAT chain
    SECT    _sectDifStart;          // [044H,04] first SECT in the DIF chain
    FSINDEX _csectDif;              // [048H,04] number of SECTs in the DIF chain
    SECT    _sectFat[109];          // [04CH,436] the SECTs of the first 109 FAT sectors
};

struct StructuredStorageDirectoryEntry {    // [offset from start in bytes, length in bytes]
    wchar   _ab[32];                        // [000H,64] 64 bytes. The Element name in Unicode, padded with zeros to
                                            //           fill this byte array
    WORD    _cb;                            // [040H,02] Length of the Element name in characters, not bytes
    STGTY   _mse;                           // [042H,01] Type of object: value taken from the STGTY enumeration
    DECOLOR _bflags;                        // [043H,01] Value taken from DECOLOR enumeration.
    SID     _sidLeftSib;                    // [044H,04] SID of the left-sibling of this entry in the directory tree
    SID     _sidRightSib;                   // [048H,04] SID of the right-sibling of this entry in the directory tree
    SID     _sidChild;                      // [04CH,04] SID of the child acting as the root of all the children of this
                                            //           element (if _mse=STGTY_STORAGE)
    char    _clsId[16];                     // [050H,16] CLSID of this storage (if _mse=STGTY_STORAGE)
    DWORD   _dwUserFlags;                   // [060H,04] User flags of this storage (if _mse=STGTY_STORAGE)
    TIME_T  _time[2];                       // [064H,16] Create/Modify time-stamps (if _mse=STGTY_STORAGE)
    SECT    _sectStart;                     // [074H,04] starting SECT of the stream (if _mse=STGTY_STREAM)
    ULONG   _ulSize;                        // [078H,04] size of stream in bytes (if _mse=STGTY_STREAM)
    DFPROPTYPE  _dptPropType;               // [07CH,02] Reserved for future use. Must be zero.
};
"""
c_ole = cstruct.cstruct()
c_ole.load(ole_def)

SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
SIGNATURE_BETA = b"\x0e\x11\xfc\x0d\xd0\xcf\x11\xe0"

STGTY = c_ole.STGTY
DECOLOR = c_ole.DECOLOR
