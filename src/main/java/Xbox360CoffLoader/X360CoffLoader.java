package Xbox360CoffLoader;


import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.MSCoffLoader;
import ghidra.program.model.lang.LanguageCompilerSpecPair;

import java.io.IOException;
import java.util.*;

public class X360CoffLoader extends MSCoffLoader  {

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		BinaryReader br = new BinaryReader(provider, true);
		if (br.readShort(0) == 0x01f2)
			loadSpecs.add(
					new LoadSpec(this, 0, new LanguageCompilerSpecPair("PowerPC:BE:64:A2ALT-32addr", "default"), true));
		return loadSpecs;
	}

	@Override
	public String getName() {
		return "Xbox 360 Coff Loader";
	}
}
