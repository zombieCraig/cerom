cerom -- Dumps wince rom files from Honda's Navigation DVDs
	 Linux port of DumpNavi/Bysin code

I really only use linux but own one of these Navigation decks so I had
to port the windows code.  Also the original program could not update
'modules'.  Modules are EXEs and DLLs (at least with version 6.x of the SW)

The original tools did not have a license associated with it so I put this
one under the GNU Public License v2.0

Sorry it doesn't have a configure script, etc.  But it's a very simple program.

You should be able to compile just by typing 'make'

Syntax:

./cerom <##AVN2.bin> list -- Lists contents of binary
./cerom <##AVN2.bin> extract <files...> -- Dumps contents
./cecrom <##AVN2.bin> update <file> [<file>] -- Updates file in contents

That's it.  Enjoy!


More info can be found on the Hive13 wiki: http://wiki.hive13.org/Honda_Navigation_Hacking


