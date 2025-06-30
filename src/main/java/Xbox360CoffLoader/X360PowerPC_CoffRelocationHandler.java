package Xbox360CoffLoader;

import ghidra.app.util.bin.format.RelocationException;
import ghidra.app.util.bin.format.coff.*;
import ghidra.app.util.bin.format.coff.relocation.CoffRelocationContext;
import ghidra.app.util.bin.format.coff.relocation.CoffRelocationHandler;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;
import ghidra.program.model.symbol.Symbol;

/**
 * PowerPC COFF relocation handler for Xbox 360 based libs
 * 
 * This implementation handles PowerPC big-endian instruction encoding.
 * PowerPC instructions are 32-bit big-endian with specific field layouts:
 * - Branch instructions (B, BL): Opcode[0:5], LI[6:29], AA[30], LK[31]
 * - Conditional branches (BC): Opcode[0:5], BO[6:10], BI[11:15], BD[16:29], AA[30], LK[31]
 * 
 * TODO(crack): TOC, Segment, Glue, and gplr related relocations
 */
public class X360PowerPC_CoffRelocationHandler implements CoffRelocationHandler {

	// PowerPC relocation types
	public static final short IMAGE_REL_PPC_ABSOLUTE = 0x0000;  // NOP
	public static final short IMAGE_REL_PPC_ADDR64 = 0x0001;    // 64-bit address
	public static final short IMAGE_REL_PPC_ADDR32 = 0x0002;    // 32-bit address
	public static final short IMAGE_REL_PPC_ADDR24 = 0x0003;    // 26-bit address, shifted left 2 (branch absolute)
	public static final short IMAGE_REL_PPC_ADDR16 = 0x0004;    // 16-bit address
	public static final short IMAGE_REL_PPC_ADDR14 = 0x0005;    // 16-bit address, shifted left 2 (load doubleword)
	public static final short IMAGE_REL_PPC_REL24 = 0x0006;     // 26-bit PC-relative offset, shifted left 2 (branch relative)
	public static final short IMAGE_REL_PPC_REL14 = 0x0007;     // 16-bit PC-relative offset, shifted left 2 (br cond relative)
	public static final short IMAGE_REL_PPC_TOCREL16 = 0x0008;  // 16-bit offset from TOC base
	public static final short IMAGE_REL_PPC_TOCREL14 = 0x0009;  // 16-bit offset from TOC base, shifted left 2 (load doubleword)
	public static final short IMAGE_REL_PPC_ADDR32NB = 0x000A;  // 32-bit addr w/o image base
	public static final short IMAGE_REL_PPC_SECREL = 0x000B;    // va of containing section (as in an image sectionhdr)
	public static final short IMAGE_REL_PPC_SECTION = 0x000C;   // sectionheader number
	public static final short IMAGE_REL_PPC_IFGLUE = 0x000D;    // substitute TOC restore instruction iff symbol is glue code
	public static final short IMAGE_REL_PPC_IMGLUE = 0x000E;    // symbol is glue code; virtual address is TOC restore instruction
	public static final short IMAGE_REL_PPC_SECREL16 = 0x000F;  // va of containing section (limited to 16 bits)
	public static final short IMAGE_REL_PPC_REFHI = 0x0010;
	public static final short IMAGE_REL_PPC_REFLO = 0x0011;
	public static final short IMAGE_REL_PPC_PAIR = 0x0012;
	public static final short IMAGE_REL_PPC_SECRELLO = 0x0013;  // Low 16-bit section relative reference (used for >32k TLS)
	public static final short IMAGE_REL_PPC_SECRELHI = 0x0014;  // High 16-bit section relative reference (used for >32k TLS)
	public static final short IMAGE_REL_PPC_GPREL = 0x0015;
	public static final short IMAGE_REL_PPC_TYPEMASK = 0x00FF;  // mask to isolate above values in IMAGE_RELOCATION.Type

	public static final short IMAGE_REL_PPC_NEG = 0x0100;       // subtract reloc value rather than adding it
	public static final short IMAGE_REL_PPC_BRTAKEN = 0x0200;   // fix branch prediction bit to predict branch taken
	public static final short IMAGE_REL_PPC_BRNTAKEN = 0x0400;  // fix branch prediction bit to predict branch not taken
	public static final short IMAGE_REL_PPC_TOCDEFN = 0x0800;   // toc slot defined in file (or, data in toc)
	
	// Symbol section number constants
	public static final short IMAGE_SYM_UNDEFINED = 0;
	public static final short IMAGE_SYM_ABSOLUTE = -1;
	public static final short IMAGE_SYM_DEBUG = -2;
	
	// Split symbol relocations (hi/lo references)
	private long pairValue = 0;
	private boolean hasPair = false;

	@Override
	public boolean canRelocate(CoffFileHeader fileHeader) {
		// 0x01f2 == x360 PPC COFF
		return fileHeader.getMachine() == 0x01f2;
	}

	@Override
	public RelocationResult relocate(Address address, CoffRelocation relocation,
			CoffRelocationContext context) throws MemoryAccessException, RelocationException {
		
		short relocType = (short)(relocation.getType() & IMAGE_REL_PPC_TYPEMASK);
		short flags = (short)(relocation.getType() & ~IMAGE_REL_PPC_TYPEMASK);
		
		// Get symbol from context
		Symbol symbol = context.getSymbol(relocation);
		if (symbol == null && relocType != IMAGE_REL_PPC_ABSOLUTE) {
			throw new RelocationException("Relocation symbol is null");
		}
		
		long symbolValue = 0;
		if (symbol != null) {
			symbolValue = symbol.getAddress().getOffset();
		}
		
		Memory memory = context.getProgram().getMemory();
		
		long value = 0;
		int byteLength = 0;
		Status status = Status.APPLIED;
		
		switch (relocType) {
			case IMAGE_REL_PPC_ABSOLUTE:
				return new RelocationResult(Status.SKIPPED, 0);
				
			case IMAGE_REL_PPC_ADDR64:
				value = symbolValue;
				byteLength = 8;
				break;
				
			case IMAGE_REL_PPC_ADDR32:
				value = symbolValue;
				byteLength = 4;
				break;
				
			case IMAGE_REL_PPC_ADDR24:
				// 26-bit address, shifted left 2 (branch absolute)
				// Bits 0-5: Opcode, Bits 6-29: LI field (24 bits), Bit 30: AA, Bit 31: LK
				value = symbolValue & 0x03fffffc;  // Mask to 26 bits, keep bits 2-25
				byteLength = 4;
				break;
				
			case IMAGE_REL_PPC_ADDR16:
				value = symbolValue & 0xffff;
				byteLength = 2;
				break;
				
			case IMAGE_REL_PPC_ADDR14:
				// 16-bit address, shifted left 2 (load dword)
				// Bits 0-5: Opcode, Bits 6-10: BO, Bits 11-15: BI, Bits 16-29: BD (14 bits)
				value = symbolValue & 0x0000fffc;  // Mask to 16 bits, keep bit alignment
				byteLength = 2;
				break;
				
			case IMAGE_REL_PPC_REL24:
				// 26-bit PC-relative offset, shifted left 2 (branch relative)
				long pcRel24 = symbolValue - address.getOffset();
				value = pcRel24 & 0x03fffffc;
				byteLength = 4;
				break;
				
			case IMAGE_REL_PPC_REL14:
				// 16-bit PC-relative offset, shifted left 2 (br cond relative)
				// PowerPC conditional branch format (big-endian)
				long pcRel14 = symbolValue - address.getOffset();
				value = pcRel14 & 0x0000fffc;  // Mask to 16 bits, keep bit alignment
				byteLength = 2;
				break;
				
			case IMAGE_REL_PPC_TOCREL16:
				// 16-bit offset from TOC base - not implemented
				return new RelocationResult(Status.UNSUPPORTED, 0);
				
			case IMAGE_REL_PPC_TOCREL14:
				// 16-bit offset from TOC base, shifted left 2 (load doubleword)
				// Would need proper TOC handling for PowerPC ABI
				return new RelocationResult(Status.UNSUPPORTED, 0);
				
			case IMAGE_REL_PPC_ADDR32NB:
				// 32-bit addr w/o image base
				value = symbolValue - context.getProgram().getImageBase().getOffset();
				byteLength = 4;
				break;


				
			case IMAGE_REL_PPC_REFHI:
				// High 16 bits of symbol value
				if (hasPair) {
					value = ((symbolValue + pairValue) >> 16) & 0xffff;
					hasPair = false;
				} else {
					value = (symbolValue >> 16) & 0xffff;
				}
				byteLength = 2;
				break;
				
			case IMAGE_REL_PPC_REFLO:
				// Low 16 bits of symbol value
				if (hasPair) {
					value = (symbolValue + pairValue) & 0xffff;
					hasPair = false;
				} else {
					value = symbolValue & 0xffff;
				}
				byteLength = 2;
				break;
			case IMAGE_REL_PPC_PAIR:
			case IMAGE_REL_PPC_SECTION:
			case IMAGE_REL_PPC_SECREL16:
			case IMAGE_REL_PPC_SECRELLO:
			case IMAGE_REL_PPC_SECRELHI:
				return new RelocationResult(Status.UNSUPPORTED, 2);
			case IMAGE_REL_PPC_SECREL:
				return new RelocationResult(Status.UNSUPPORTED, 4);	
			case IMAGE_REL_PPC_IFGLUE:
			case IMAGE_REL_PPC_IMGLUE:
			case IMAGE_REL_PPC_GPREL:	
			default:
				return new RelocationResult(Status.UNSUPPORTED, 0);
		}
		
		// Apply flags
		if ((flags & IMAGE_REL_PPC_NEG) != 0) {
			value = -value;
		}
		
		// Check for TOC definition flag - not implemented
		if ((flags & IMAGE_REL_PPC_TOCDEFN) != 0) {
			return new RelocationResult(Status.UNSUPPORTED, 0);
		}
		
		// Handle branch prediction flags for branch instructions
		if (relocType == IMAGE_REL_PPC_REL24 || relocType == IMAGE_REL_PPC_REL14 ||
		    relocType == IMAGE_REL_PPC_ADDR24) {
			
			if ((flags & IMAGE_REL_PPC_BRTAKEN) != 0 || (flags & IMAGE_REL_PPC_BRNTAKEN) != 0) {
				// Read the current instruction
				int instruction = memory.getInt(address);
				
				// PowerPC branch prediction bit is in the BO field (bits 6-10)
				// For unconditional branches (REL24/ADDR24), this doesn't apply
				// For conditional branches (REL14), bit 9 is the prediction bit
				if (relocType == IMAGE_REL_PPC_REL14) {
					if ((flags & IMAGE_REL_PPC_BRTAKEN) != 0) {
						instruction |= 0x00200000;  // Set bit 9 (predict taken)
					} else if ((flags & IMAGE_REL_PPC_BRNTAKEN) != 0) {
						instruction &= ~0x00200000; // Clear bit 9 (predict not taken)
					}
					memory.setInt(address, instruction);
				}
			}
		}
		
		// Apply the relocation based on byte length
		switch (byteLength) {
			case 2:
				// For 16-bit relocations
				if (relocType == IMAGE_REL_PPC_ADDR14 || relocType == IMAGE_REL_PPC_REL14) {
					// For 14-bit branch displacements, we need to update the BD field
					// Read the full instruction (4 bytes) in big-endian
					int instruction = memory.getInt(address);
					// BD field is bits 16-29 (14 bits) in the instruction
					// Clear the BD field and set new value
					instruction = (instruction & 0xffff0003) | ((int)(value & 0xfffc));
					memory.setInt(address, instruction);
				} else {
					// Standard 16-bit relocation (ADDR16, REFHI, REFLO, etc.)
					short currentShort = memory.getShort(address);
					memory.setShort(address, (short)(currentShort + value));
				}
				break;
				
			case 4:
				if (relocType == IMAGE_REL_PPC_ADDR24 || relocType == IMAGE_REL_PPC_REL24) {
					// For branch instructions, update the LI field
					// Read the instruction in big-endian
					int instruction = memory.getInt(address);
					// LI field is bits 6-29 (24 bits) in the instruction
					// Preserve bits 0-5 (opcode) and bits 30-31 (AA, LK)
					instruction = (instruction & 0xfc000003) | ((int)(value & 0x03fffffc));
					memory.setInt(address, instruction);
				} else {
					// Standard 32-bit relocation
					int currentInt = memory.getInt(address);
					memory.setInt(address, (int)(currentInt + value));
				}
				break;
				
			case 8:
				// 64-bit relocation
				long currentLong = memory.getLong(address);
				memory.setLong(address, currentLong + value);
				break;
				
			default:
				if (byteLength > 0) {
					return new RelocationResult(Status.UNSUPPORTED, byteLength);
				}
		}
		
		return new RelocationResult(status, byteLength);
	}
}