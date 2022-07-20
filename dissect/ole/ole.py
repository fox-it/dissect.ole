from dissect.util.ts import wintimestamp
from dissect.util.stream import AlignedStream

from dissect.ole.exceptions import InvalidFileError, NotFoundError, Error
from dissect.ole.c_ole import c_ole, SIGNATURE, SIGNATURE_BETA, DECOLOR, STGTY


class OLE:
    def __init__(self, fh):
        self.fh = fh
        self.header = c_ole.StructuredStorageHeader(fh)

        if self.header._abSig not in (SIGNATURE, SIGNATURE_BETA):
            raise InvalidFileError("invalid OLE signature")

        if self.header._uByteOrder != 0xFFFE:
            raise NotImplementedError("only Intel byte-order implemented")

        self.sector_size = 1 << self.header._uSectorShift
        self.mini_sector_size = 1 << self.header._uMiniSectorShift
        self.mini_cutoff = self.header._ulMiniSectorCutoff

        self.num_fat_entries = self.sector_size // 4
        self.num_difat_entries = self.num_fat_entries - 1

        self._dircache = {}
        self._fatcache = {}
        self._difatcache = {}
        self._chaincache = {}
        self._minichaincache = {}
        self._dirlist = {}

        minifat_buf = self.chain(self.header._sectMiniFatStart).open().read()
        self._minifat = c_ole.uint32[len(minifat_buf) // 4](minifat_buf)

        self._dirstream = self.chain(self.header._sectDirStart).open()

        self.root = self.directory(0)
        self.ministream = self.root.open()

    def get(self, name):
        dirlist = self.listdir()
        try:
            return dirlist[name]
        except KeyError:
            return NotFoundError(name)

    def listdir(self):
        if not self._dirlist:
            for entry in self.root.walk():
                self._dirlist[entry.name] = entry

        return self._dirlist

    dirlist = listdir

    def directory(self, sid):
        try:
            return self._dircache[sid]
        except KeyError:
            entry = DirectoryEntry(self, sid)
            self._dircache[sid] = entry
            return entry

    def fat(self, sect):
        idx, offset = divmod(sect, self.num_fat_entries)

        try:
            table = self._fatcache[idx]
        except KeyError:
            if idx <= 108:
                fatsect = self.header._sectFat[idx]
                if fatsect == c_ole.FREESECT:
                    raise IndexError("sect out of range")
            else:
                # DIFAT
                subtable = idx - 109
                difatidx, difatoffset = divmod(subtable, self.num_difat_entries)

                try:
                    ditable = self._difatcache[difatidx]
                except KeyError:
                    cur = 0
                    cursect = self.header._sectDifStart
                    while cur <= difatidx:
                        if cursect == c_ole.ENDOFCHAIN:
                            raise Error("DIF ENDOFCHAIN reached before table found")

                        try:
                            ditable = self._difatcache[cur]
                        except KeyError:
                            self.fh.seek((cursect + 1) * self.sector_size)
                            ditable = c_ole.uint32[self.num_fat_entries](self.fh.read(self.sector_size))
                            self._difatcache[cur] = ditable

                        cur += 1
                        cursect = ditable[-1]

                fatsect = ditable[difatoffset]

            self.fh.seek((fatsect + 1) * self.sector_size)
            table = c_ole.uint32[self.num_fat_entries](self.fh.read(self.sector_size))

            self._fatcache[idx] = table

        return table[offset]

    def minifat(self, sect):
        return self._minifat[sect]

    def chain(self, sect, size=None):
        try:
            return self._chaincache[sect]
        except KeyError:
            chain = Chain(self, sect, size)
            self._chaincache[sect] = chain
            return chain

    def minichain(self, sect, size=None):
        try:
            return self._minichaincache[sect]
        except KeyError:
            chain = MiniChain(self, sect, size)
            self._minichaincache[sect] = chain
            return chain


class DirectoryEntry:
    def __init__(self, ole, sid):
        self.ole = ole
        self.sid = sid

        ole._dirstream.seek(sid * 128)
        entry = c_ole.StructuredStorageDirectoryEntry(ole._dirstream)
        self.entry = entry

        self.name = entry._ab.rstrip("\x00")
        self.type = entry._mse
        self.flags = entry._bflags
        self.user_flags = entry._dwUserFlags
        self.ctime = wintimestamp(entry._time[0]) if entry._time[0] else None
        self.mtime = wintimestamp(entry._time[1]) if entry._time[1] else None
        self.start = entry._sectStart
        self.size = entry._ulSize

        if self.is_minifat:
            self.chain = ole.minichain(self.start, self.size)
        else:
            self.chain = ole.chain(self.start, self.size)

    def __repr__(self):
        return "<DirectoryEntry sid={} name={} type={} size=0x{:x}>".format(self.sid, self.name, self.type, self.size)

    def open(self):
        return self.chain.open()

    def walk(self):
        if self.has_left_sibling:
            yield self.left_sibling
            for child in self.left_sibling.walk():
                yield child

        if self.has_child:
            yield self.child

        if self.has_right_sibling:
            yield self.right_sibling
            for child in self.right_sibling.walk():
                yield child

        if self.has_child:
            for child in self.child.walk():
                yield child

    @property
    def child(self):
        if not self.has_child:
            return None
        return self.ole.directory(self.entry._sidChild)

    @property
    def left_sibling(self):
        if not self.has_left_sibling:
            return None
        return self.ole.directory(self.entry._sidLeftSib)

    @property
    def right_sibling(self):
        if not self.has_right_sibling:
            return None
        return self.ole.directory(self.entry._sidRightSib)

    @property
    def has_child(self):
        return self.entry._sidChild != 0xFFFFFFFF

    @property
    def has_left_sibling(self):
        return self.entry._sidLeftSib != 0xFFFFFFFF

    @property
    def has_right_sibling(self):
        return self.entry._sidRightSib != 0xFFFFFFFF

    @property
    def is_minifat(self):
        return self.is_stream and self.size < self.ole.mini_cutoff

    @property
    def is_red(self):
        return self.entry._bflags == DECOLOR.DE_RED

    @property
    def is_black(self):
        return self.entry._bflags == DECOLOR.DE_BLACK

    @property
    def is_valid(self):
        return self.entry._mse == STGTY.STGTY_INVALID

    @property
    def is_stream(self):
        return self.entry._mse == STGTY.STGTY_STREAM

    @property
    def is_storage(self):
        return self.entry._mse == STGTY.STGTY_STORAGE


class Chain:
    def __init__(self, ole, sect, size=None):
        self.ole = ole
        self.sect = sect
        self.size = size
        self.chain = [sect]
        self.ended = False

    def __len__(self):
        self.fill()
        return len(self.chain)

    def __iter__(self):
        self.fill()
        return iter(self.chain)

    def __getitem__(self, i):
        cur = len(self.chain)
        tail = self.chain[-1]

        if not self.ended:
            while cur <= i:
                tail = self._lookup(tail)

                if tail == c_ole.ENDOFCHAIN:
                    self.ended = True
                    break

                self.chain.append(tail)
                cur += 1

        if i >= cur:
            raise IndexError("index out of chain range")

        return self.chain[i]

    def open(self):
        return ChainStream(self.ole.fh, self, self.ole.sector_size, offset=self.ole.sector_size)

    def fill(self):
        if self.ended:
            return

        try:
            self[0xFFFFFFFF]
        except IndexError:
            pass

    def _lookup(self, sect):
        return self.ole.fat(sect)


class MiniChain(Chain):
    def open(self):
        return ChainStream(self.ole.ministream, self, self.ole.mini_sector_size)

    def _lookup(self, sect):
        return self.ole.minifat(sect)


class ChainStream(AlignedStream):
    def __init__(self, stream, chain, sector_size, offset=0):
        self._fh = stream
        self.chain = chain
        self.sector_size = sector_size
        self.offset = offset

        super().__init__(chain.size)

    def _read(self, offset, length):
        r = []

        if not self.size and length == -1:
            # make an approximate guess on total file size
            length = self.chain.ole.header._csectFat * 128 * self.chain.ole.sector_size

        sector_size = self.sector_size
        sectidx, sectoffset = divmod(offset, sector_size)
        numsects = length // sector_size

        for _ in range(numsects):
            try:
                sectnum = self.chain[sectidx]
            except IndexError:
                break

            if self.size:
                sectread = min(self.size - offset, sector_size)
            else:
                sectread = sector_size
            fileoffset = self.offset + sectnum * sector_size

            self._fh.seek(fileoffset)
            sectbuf = self._fh.read(sectread)

            if sectoffset:
                sectbuf = sectbuf[sectoffset:]

            r.append(sectbuf)

            sectoffset = 0
            sectidx += 1
            offset += sectread

        return b"".join(r)
