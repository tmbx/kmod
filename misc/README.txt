---------------------------------
MERCURIAL INFO:

- The build system builds the objects in the build/ directory. To prevent HG 
  from complaining about these files, create the ".hgignore" file in the KMO 
  directory:
  ^build
  .hgignore
- Use HG only from Cygwin. 
- To be able to commit:
  - # export EDITOR=vim


---------------------------------
WINDOWS COMPILATION:

A prayer to your favorite god is not mandatory but may be useful.

Compiling the sqlite3 library:
  - The README says the configure script is unmaintained, that may explain why
    it must be coerced to work. It is supposed to build both a static and shared
    library, but it actually just build a static library.
  - Use MinGW to compile.
  - Use version 3.3.6. Version 3.3.11 does not compile anymore.
  - # ./configure --disable-tcl
  - # make
  - The library files are in .deps/.  
  - # strip --strip-unneeded --strip-debug libsqlite3.a

Getting a DLL of the sqlite3 library:
  - I could not do it by compilation. The scripts are broken.
  - Download sqlitedll-3_3_11.zip and sqlite-source-3_3_11.zip to get both the
    DLL and the headers.
  - KMOD expects to find the DLL and the sqlite3.h file in the 'sqlite/'
    directory.

Compiling the gpg-error library:
  - Use MinGW to compile. I'm using version 1.5.
  - Don't use --disable-static. Don't use --disable-shared. The script will
    apparently build a static and dynamic library by default and you'll have
    problems if you use one of the options above.
  - # ./configure
  - # make
  - # make install

Compiling the gcrypt library:
  - Use MinGW to compile. I'm using version 1.2.2. It most likely won't work
    with other versions. Download and libgcrypt.def which
    you'll find on the web.
  - # cd libgcrypt-1.2.2
    Manually edit configure.ac and comment out AC_PREREQ(2.59).
    Manually edit acinclude.m4, search for ac_cv_sys, on the line above add
     '| i686-pc-mingw32'.
  - # aclocal -I .
  - # automake --add-missing --copy
  - # autoconf
  - # ./configure --disable-asm
  - # make
  - Build of test programs will fail -- ignore it.
  - # cd ..
  - # cp libgpg-error-1.5/src/.libs/libgpg-error.a libgcrypt-1.2.2/src/.libs/
  - # cp libgcrypt.def libgcrypt-1.2.2/src/.libs/
  - # cd libgcrypt-1.2.2/src/.libs
  - Pray.
  - # gcc -shared -o libgcrypt.dll libgcrypt.def libgcrypt.a libgpg-error.a

Compiling the openssl library:
  - Use MinGW to compile. I'm using version 0.9.8d.
  - Edit Configure
    - Search for MinGW.
    - Replace '-mno-cygwin -shared:.dll.a'
      with -mno-cygwin -Wl,--export-all -shared:.dll.a
  - # ./Configure shared mingw
  - # cp *.h ssl/*.h crypto/*.h include/openssl/
  - Edit Makefile
   - Search for 'test:' and 'tests:', comment everything in these sections.
     Note: still doesn't work correctly. Ignore build failure for that.
 - # make
 - Libraries are called ssleay32-0.9.8.dll and cryptoeay32-0.9.8.dll.
 
Compiling the iconv library:
  - Use MinGW to compile. Use version 1.11, earlier versions likely will not
    work.
  - # ./configure --prefix=/mingw --with-pic --with-gnu-ld --enable-shared
      --enable -static --disable-rpath --enable-nls --disable-debug
  - # make
  - Library is lib/.libs/libiconv-2.dll.

Compiling the pthread-win32 library:
  - Use MinGW to compile. I'm using version 2.8.0.
  - # make clean GC
  - # dlltool -l pthread.lib --input-def pthread.def
  - # cp *.h pthread.lib ../pthread/
  - # cp pthreadGC2.dll ../pthread/pthreadGC2.dll

Compiling the gnutls library:
  - Didn't succeed so far.
  - Download from http://josefsson.org/gnutls4win/.
  - Fix that eventually...there are GPL issues.

Compiling SCons:
  - SCons must be installed from source.
  - You can use bash in Cygwin to compile.
  - # python bootstrap.py
  - # python build/scons/setup.py install

Compiling KMOD:
  - The *Cygwin* absolute paths are broken. Always use Windows absolute paths.
  - Fix SConstruct file:
    - Make sure the library paths are valid.
  - # scons build 
Random notes:
  - If a KMO program does nothing when it is executed, check the return code. I
    got code 53 when Windows was looking for a dynamic library that it couldn't
    find. Executing the program by double-clicking on it will tell you the name
    of the missing file.

