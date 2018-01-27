
# Simple ELF class for parsing headers and symbol tables

from collections import namedtuple
import struct

EI_MAG0 = 0
EI_MAG1 = 1
EI_MAG2 = 2
EI_MAG3 = 3
EI_CLASS = 4
EI_DATA = 5
EI_VERSION = 6
EI_PAD = 7
EI_NIDENT = 16
ELFMAGIC = b'\x7fELF'

ET_NONE = 0
ET_REL = 1
ET_EXEC = 2
ET_DYN = 3
ET_CORE = 4
ET_LOPROC = 0xff00
ET_HIPROC = 0xffff

EM_NONE = 0
EM_M32 = 1
EM_SPARC = 2
EM_386 = 3
EM_68K = 4
EM_88K = 5
EM_860 = 7
EM_MIPS = 8

EV_NONE = 0
EV_CURRENT = 1

ELFCLASSNONE = 0
ELFCLASS32 = 1
ELFCLASS64 = 2

ELFDATANONE = 0
ELFDATA2LSB = 1 # Little endian
ELFDATA2MSB = 2 # Big endian

SHN_UNDEF = 0
SHN_LORESERVE = 0xff00
SHN_LOPROC = 0xff00
SHN_HIPROC = 0xff1f
SHN_ABS = 0xfff1
SHN_COMMON = 0xfff2
SHN_HIRESERVE = 0xffff

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_HASH = 5
SHT_DYNAMIC = 6
SHT_NOTE = 7
SHT_NOBITS = 8
SHT_REL = 9
SHT_SHLIB = 10
SHT_DYNSYM = 11
SHT_LOPROC = 0x70000000
SHT_HIPROC = 0x7fffffff
SHT_LOUSER = 0x80000000
SHT_HIUSER = 0xffffffff

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SHF_MASKPROC=0xf0000000

STN_UNDEF = 0

STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2
STB_LOPROC = 13
STB_HIPROC = 15

STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STT_SECTION = 3
STT_FILE = 4
STT_LOPROC = 13
STT_HIPROC = 15

R_386_NONE = 0
R_386_32 = 1
R_386_PC32 = 2
R_386_GOT32 = 3
R_386_PLT32 = 4
R_386_COPY = 5
R_386_GLOB_DAT = 6
R_386_JMP_SLOT = 7
R_386_RELATIVE = 8
R_386_GOTOFF = 9
R_386_GOTPC = 10

PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_SHLIB = 5
PT_PHDR = 6
PT_LOPROC = 0x70000000
PT_HIPROC = 0x7fffffff

DT_NULL = 0
DT_NEEDED = 1
DT_PLTRELSZ = 2
DT_PLTGOT = 3
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_STRSZ = 10
DT_SYMENT = 11
DT_INIT = 12
DT_FINI = 13
DT_SONAME = 14
DT_RPATH = 15
DT_SYMBOLIC = 16
DT_REL = 17
DT_RELSZ = 18
DT_RELENT = 19
DT_PLTREL = 20
DT_DEBUG = 21
DT_TEXTREL = 22
DT_JMPREL = 23
DT_LOPROC = 0x70000000
DT_HIPROC = 0x7fffffff

# (size, signed)
Elf32_Addr = (4, False)
Elf32_Half = (2, False)
Elf32_Off = (4, False)
Elf32_Sword = (4, True)
Elf32_Word = (4, False)
uint8 = (1, False)

ElfIdentHeader = namedtuple("ElfIdentHeader", "eclass data version pad")
ElfEHeader = namedtuple("ElfELFHeader", "type machine version entry "
	"phoff shoff flags ehsize phentsize phnum shentsize shnum shstrndx")
ElfSHeader = namedtuple("ElfSectionHeader", "name type flags addr "
	"offset size link info addralign entsize")
ElfSym = namedtuple("Elf_Sym", "name value size info other shndx")
ElfPHeader = namedtuple("ElfProgramHeader", "type offset vaddr paddr "
	"filesz memsz flags align")

def header_print(t):
	s = type(t).__name__ + '('
	for name, value in zip(t._fields, t):
		s += name + "=" + hex(value) + ", "
	s = s[:-2] + ')'
	return s

class ElfParsingException(Exception):
	pass

class Elf(object):
	def __init__(self, file, ident):
		self.file = file
		self.ident = ident
		if ident.data == ELFDATA2LSB:
			self.endian = "<"
		else:
			self.endian = ">"
		self.ehdr = self.parse_ehdr()
		self.parse_sections()
		self.parse_pheaders()

	def close(self):
		self.file.close()
		del self.file

	def read(self, nbytes, offset = None):
		if (offset is not None):
			self.file.seek(offset)
		data = self.file.read(nbytes)
		if len(data) != nbytes:
			raise ElfParsingException("Reading %d bytes, %d available"%
				(nbytes, len(data)))
		return data

	def get(self, elftype, offset = None):
		"""Read data from an ELF file according to Elf Data types"""
		size, signed = elftype
		data = self.read(size, offset)
		if(signed):
			packtype = "XbhXlXXXq"[size]
		else:
			packtype = "XBHXLXXXQ"[size]
		return struct.unpack(self.endian + packtype, data)[0]

	def parse_struct(self, struct_type, struct_def, offset = None):
		if offset is not None:
			self.file.seek(offset)
		values = (self.get(t) for t in struct_def)
		return struct_type(*values)

	def parse_ehdr(self):
		return self.parse_struct(ElfEHeader, self.ehdr_struct, offset=EI_NIDENT)
	def parse_sections(self):
		sections = []
		for i in range(self.ehdr.shnum):
			offset = self.ehdr.shoff + i * self.ehdr.shentsize
			sections.append(self.parse_struct(ElfSHeader, self.shdr_struct, offset=offset))
		self.s_headers = sections

	def parse_pheaders(self):
		pheaders = []
		for i in range(self.ehdr.phnum):
			offset = self.ehdr.phoff + i * self.ehdr.phentsize
			pheaders.append(self.parse_struct(ElfPHeader, self.phdr_struct, offset=offset))
		self.p_headers = pheaders

	@classmethod
	def _parse_elfident(cls, file):
		file.seek(0)
		e_ident = file.read(EI_NIDENT)
		if e_ident[:4] != ELFMAGIC:
			raise ElfParsingException("Missing ELF header")
		header = ElfIdentHeader(e_ident[EI_CLASS], e_ident[EI_DATA],
			e_ident[EI_VERSION], e_ident[EI_PAD:])
		return header

def open_elf_file(filename):
	file = open(filename, 'br')
	ident = Elf._parse_elfident(file)
	if ident.eclass == ELFCLASS32:
		return Elf32(file, ident)
	elif ident.eclass == ELFCLASS64:
		return Elf64(file, ident)
	else:
		raise ElfParsingException("Invalid class %d"%(ident.eclass))

class Elf32(Elf):
	ehdr_struct = (
		Elf32_Half, Elf32_Half, Elf32_Word, Elf32_Addr, Elf32_Off, Elf32_Off,
		Elf32_Word, Elf32_Half, Elf32_Half, Elf32_Half, Elf32_Half,
		Elf32_Half, Elf32_Half
		)
	shdr_struct = (
		Elf32_Word, Elf32_Word, Elf32_Word, Elf32_Addr, Elf32_Off, Elf32_Word,
		Elf32_Word, Elf32_Word, Elf32_Word, Elf32_Word
		)
	sym_struct = (
		Elf32_Word, Elf32_Addr, Elf32_Word, uint8, uint8, Elf32_Half
		)
	phdr_struct = (
		Elf32_Word, Elf32_Off, Elf32_Addr, Elf32_Addr,
		Elf32_Word, Elf32_Word, Elf32_Word, Elf32_Word
		)
