# Ghidra headless script: export analysis results
# Run with: analyzeHeadless ... -postScript ghidra_export.py

import ghidra.program.model.symbol as symbol
import ghidra.program.model.listing as listing
import java.io

TEXT_BASE = 0xffffffffc5400000
TEXT_END  = 0xffffffffc60c0000
DATA_BASE = 0xffffffffc60c0000

outdir = "/Users/macbookairm1/Data/Hypervisor-ps5/analysis"
java.io.File(outdir).mkdirs()

program = currentProgram
mem = program.getMemory()
listing = program.getListing()
refMgr = program.getReferenceManager()

# 1. Export all defined functions
f = open(outdir + "/functions.txt", "w")
f.write("# addr offset name\n")
func = listing.getFunctions(True)
count = 0
while func.hasNext():
    fn = func.next()
    addr = fn.getEntryPoint().getOffset()
    name = fn.getName()
    if addr >= TEXT_BASE and addr < TEXT_END:
        off = addr - TEXT_BASE
        f.write("0x%x text+0x%x %s\n" % (addr, off, name))
    else:
        off = addr - DATA_BASE
        f.write("0x%x data+0x%x %s\n" % (addr, off, name))
    count += 1
f.close()
println("[+] Exported %d functions" % count)

# 2. Export all defined strings
f = open(outdir + "/strings.txt", "w")
f.write("# addr offset string\n")
dataIter = listing.getDefinedData(True)
scount = 0
while dataIter.hasNext():
    d = dataIter.next()
    dt = d.getDataType()
    if dt is not None and "string" in dt.getName().lower():
        addr = d.getAddress().getOffset()
        off = addr - DATA_BASE
        val = d.getValue()
        if val is not None:
            s = str(val).replace("\n", "\\n").replace("\r", "")
            f.write("0x%x data+0x%x %s\n" % (addr, off, s))
            scount += 1
f.close()
println("[+] Exported %d strings" % scount)

# 3. Export pointer table candidates (8+ consecutive kernel pointers)
f = open(outdir + "/pointer_tables.txt", "w")
f.write("# table_addr table_offset count first_target\n")

block = mem.getBlock(program.getMinAddress())
if block is not None:
    start = block.getStart().getOffset()
    end = block.getEnd().getOffset()

    tcount = 0
    off = start
    while off < end - 8:
        try:
            val = mem.getLong(program.getAddressFactory().getDefaultAddressSpace().getAddress(off))
            if val >= TEXT_BASE and val < TEXT_END:
                # Start of potential table
                tstart = off
                entries = 0
                scan = off
                while scan < end - 8:
                    v = mem.getLong(program.getAddressFactory().getDefaultAddressSpace().getAddress(scan))
                    if v >= TEXT_BASE and v < TEXT_END:
                        entries += 1
                        scan += 8
                    else:
                        break
                if entries >= 8:
                    doff = tstart - DATA_BASE
                    f.write("0x%x data+0x%x %d 0x%x\n" % (tstart, doff, entries, val))
                    tcount += 1
                    off = scan
                else:
                    off += 8
            else:
                off += 8
        except:
            off += 8

f.close()
println("[+] Exported %d pointer tables (8+ entries)" % tcount)

# 4. Summary
f = open(outdir + "/summary.txt", "w")
f.write("PS5 Kernel DATA Analysis Summary\n")
f.write("================================\n")
f.write("FW: 13.60\n")
f.write("TEXT: 0x%x - 0x%x\n" % (TEXT_BASE, TEXT_END))
f.write("DATA: 0x%x (64 MB)\n" % DATA_BASE)
f.write("Functions: %d\n" % count)
f.write("Strings: %d\n" % scount)
f.write("Pointer tables: %d\n" % tcount)
f.close()

println("[+] Analysis exported to %s" % outdir)
