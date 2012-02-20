###########################################################################
### INITIALIZE ############################################################
###########################################################################

### Verify Python version.
EnsurePythonVersion(2,3);

### Import modules.
import commands, sys, os, platform, re;

### No target to build by default.
Default(None);

### Make SCons go faster by telling it not to check for new dependencies.
#SetOption('implicit_cache', 1);

### Check if files changed using MD5 signatures.
SourceSignatures('MD5');

### By default, Scons doesn't check if generated files were manually modified
### when it builds targets. Consequently, the files modified by hand to debug
### are not rebuilded. That silly default should be fixed in future SCons
### versions, according to SK.
TargetSignatures('content');

### Try to detect CPU type, system name, and endianness. This requires Python 2.3.
BUILD_CPU_TYPE = platform.machine();

if BUILD_CPU_TYPE == 'i386' or BUILD_CPU_TYPE == 'i486' or BUILD_CPU_TYPE == 'i586' or BUILD_CPU_TYPE == 'i686' or \
   BUILD_CPU_TYPE == 'x86_64':
	BUILD_CPU_TYPE = 'x86';

elif BUILD_CPU_TYPE == 'Power Macintosh' or BUILD_CPU_TYPE == 'ppc':
	BUILD_CPU_TYPE = 'ppc';

else:
	sys.stderr.write("Cannot determine CPU type (%s) of this machine.\n" % BUILD_CPU_TYPE);
	Exit(1);

BUILD_SYS_NAME = platform.system();

if BUILD_SYS_NAME == 'Linux':
	BUILD_SYS_NAME = 'linux';

elif BUILD_SYS_NAME == 'Darwin':
	BUILD_SYS_NAME = 'mac_os_x';

elif BUILD_SYS_NAME == 'CYGWIN_NT-5.1':
    BUILD_SYS_NAME = 'windows';
    
elif BUILD_SYS_NAME == 'Windows':
    	BUILD_SYS_NAME = 'windows';

else:
	sys.stderr.write("Cannot resolve system name (%s) of this machine.\n" % BUILD_SYS_NAME);
	Exit(1);

if sys.byteorder == 'big':
	BUILD_ENDIAN = 'big';

else:
	BUILD_ENDIAN = 'little';


###########################################################################
### FUNCTIONS #############################################################
###########################################################################

### handle_config_target() helper.
def print_config_summary_item(item, text):
	summary_line = item;
	
	for i in range(1, 40 - len(item)):
		summary_line += '.';
	
	sys.stdout.write("%s%s\n" % (summary_line, text));


### handle_config_target() helper.
def print_config_summary_bool_item(item, enabled_flag):
	if enabled_flag:
		text = "yes";
	else:
		text = "no";
	
	print_config_summary_item(item, text);
	
	
### This function prints the current configuration.
def print_current_config():
	
	sys.stdout.write("\nArgument values (modify using 'scons config arg=value'):\n%s\n" % opts_help);
	sys.stdout.write("---------------------------------------------\n");
	sys.stdout.write("Configuration summary:\n\n");
	
	print_config_summary_bool_item('Enable debugging', DEBUG_FLAG);
	
	if DEBUG_FLAG and DEBUG_KOS_ADDRESS != "":
	    print_config_summary_item('  Debug KOS address: ', DEBUG_KOS_ADDRESS);
	
	if DEBUG_FLAG and DEBUG_KOS_PORT != "":
	    print_config_summary_item('  Debug KOS port: ', DEBUG_KOS_PORT);
	    
	print_config_summary_bool_item('Build kmo program', KMO_FLAG);
	print_config_summary_bool_item('Build test programs', TEST_FLAG);
	
	sys.stdout.write("\n");
	Exit(0);


### This function creates a list of static objects.
### Arguments:
### Build environment.
### Compiled objects destination directory.
### Objects source directory.
### Objects source list.
def get_static_object_list(env, build_dir, src_dir, src_list):

	regex = re.compile('(.+)\.\w+$');
	object_list = [];
	
	for source in src_list:
		object_list.append(env.StaticObject(build_dir + regex.match(source).group(1), src_dir + source));
	
	return object_list;


### This function returns the target to build the base library.
def get_base_lib_target():
    
    	src_list = 	[
			'base64.c',
			'kbuffer.c',
			'kmo_base.c',
			'list.c',
			'utils.c'
			];
	
	env = BUILD_ENV.Copy();
	env.Append	(
			CPPPATH = ['base/'],
			CCFLAGS = [ '-W' ],
			);
	
	return env.StaticLibrary(
		target = 'build/base/kmobase',
		source = get_static_object_list(env, 'build/base/', 'base/', src_list),
		);
    
    
### This function returns the target to build the maildb library.
def get_maildb_lib_target():
    
    	src_list = 	[
			'maildb.c',
			'maildb_sqlite.c',
			];
	
	cpp_path = 	['base/', 'maildb/', 'kmo/'];
	
	if BUILD_SYS_NAME == 'windows':
		cpp_path.append(WIN_SQLITE_CPP_PATH);
    
	env = BUILD_ENV.Copy();
	env.Append	(
			CPPPATH = cpp_path,
			CCFLAGS = [ '-W' ],
			);
	
	return env.StaticLibrary(
		target = 'build/maildb/kmomaildb',
		source = get_static_object_list(env, 'build/maildb/', 'maildb/', src_list),
		);


### This function returns the target to build the maildb test program.
def get_maildb_test_target():

    	src_list = 	[
			'test.c',
			];
	
	cpp_path = 	['base/', 'maildb/'];
	link_flags = 	[''];
	lib_path =	['build/maildb/', 'build/base/'];
	lib_list = 	['kmomaildb', 'kmobase', "sqlite3"];
	
	if BUILD_SYS_NAME == 'windows':
		cpp_path.append(WIN_SQLITE_CPP_PATH);
		lib_path.append(WIN_SQLITE_LIB_PATH);
		lib_list.append('ws2_32');
		

	env = BUILD_ENV.Copy();
	env.Append	(
			CPPPATH = cpp_path,
			CCFLAGS = [ '-W' ],
			LINKFLAGS = link_flags,
			LIBPATH = lib_path,
			LIBS = lib_list,
			);
	
	return env.Program(
		target = 'build/maildb/test',
		source = get_static_object_list(env, 'build/maildb/', 'maildb/', src_list),
		);
		

### This function returns the target to build the crypt library.
def get_crypt_lib_target():
    
    	src_list = 	[
			'kmocrypt.c',
			'kmocryptsignature.c',
			'kmocryptsignature2.c',
			'kmocryptpkey.c',
			'kmocryptsymkey.c',
			];
	
	cpp_path = 	['base/', 'crypt/', 'kmo/'];
	
	if BUILD_SYS_NAME == 'windows':
		cpp_path.append(WIN_GCRYPT_CPP_PATH);
                cpp_path.append(WIN_GPG_ERROR_CPP_PATH);
	
	env = BUILD_ENV.Copy();
	env.Append	(
			CPPPATH = cpp_path,
			);
	
	return env.StaticLibrary(
		target = 'build/crypt/kmocrypt',
		source = get_static_object_list(env, 'build/crypt/', 'crypt/', src_list),
		);


### This function returns the target to build the crypt test program.
def get_crypt_test_target():

    	src_list = 	[
			'test.c',
			];
	
	cpp_path = 	['base/', 'crypt/'];
	link_flags = 	[''];
	lib_path =	['build/crypt/', 'build/base/'];
	lib_list = 	['kmocrypt', 'kmobase', 'gcrypt', 'gpg-error'];
	
	if BUILD_SYS_NAME == 'windows':
		cpp_path.append(WIN_GCRYPT_CPP_PATH);
                cpp_path.append(WIN_GPG_ERROR_CPP_PATH);
		lib_path.append(WIN_GCRYPT_LIB_PATH);
                lib_path.append(WIN_GPG_ERROR_LIB_PATH);
		lib_list.append('ws2_32');
	
	env = BUILD_ENV.Copy();
	env.Append	(
			CPPPATH = cpp_path,
			CCFLAGS = [ '-W' ],
			LINKFLAGS = link_flags,
			LIBPATH = lib_path,
			LIBS = lib_list,
			);
	
	return env.Program(
		target = 'build/crypt/test',
		source = get_static_object_list(env, 'build/crypt/', 'crypt/', src_list),
		);


### This function returns the target to build the kmo program.
def get_kmo_target():

    	src_list = 	[
			'k3p.c',
			'k3p_comm.c',
			'kmo.c',
			];
	
	if BUILD_SYS_NAME == "windows":
		src_list.append('k3p_comm_win32_pipe.c');
		src_list.append('k3p_comm_win32_socket.c');
	else:
		src_list.append('k3p_comm_pipe.c');
		src_list.append('k3p_comm_socket.c');
	
	link_flags = 	[''];
        lib_list = 	['kmobase'];
	
	if BUILD_SYS_NAME == 'windows':
		lib_list.append('ws2_32');

	env = BUILD_ENV.Copy();
	env.Append	(
			CPPPATH = ['base/', 'kmo/'],
			CCFLAGS = [ '-W' ],
			LINKFLAGS = link_flags,
			LIBPATH = ['build/base/'],
			LIBS = lib_list,
			);
	
	return env.Program(
		target = 'build/kmo/kmo',
		source = get_static_object_list(env, 'build/kmo/', 'kmo/', src_list),
		);


### This function returns the target to build the kmod program.
def get_kmod_target():

    	src_list = 	[
			'k3p.c',
			'kmod.c',
			'kmo_comm.c',
			'kmod_link.c',
			'kmo_sock.c',
			'knp.c',
			'mail.c',
			];
	
	cpp_path = 	['base/', 'maildb/', 'crypt/', 'kmo/'];
	cpp_defines =	[];
	link_flags = 	['-Wl,-rpath=\'$$ORIGIN\''];
	lib_path =	['build/maildb/', 'build/crypt/', 'build/base/'];
	lib_list = 	['kmomaildb', 'kmocrypt', 'kmobase', 'sqlite3', 'gcrypt', 'gpg-error', 'ssl', 'crypto'];
	
	if BUILD_SYS_NAME == 'windows':
		cpp_path.append(WIN_SQLITE_CPP_PATH);
		lib_path.append(WIN_SQLITE_LIB_PATH);
		cpp_path.append(WIN_OPENSSL_CPP_PATH);
		lib_path.append(WIN_OPENSSL_LIB_PATH);
		cpp_path.append(WIN_GCRYPT_CPP_PATH);
		lib_path.append(WIN_GCRYPT_LIB_PATH);
                cpp_path.append(WIN_GPG_ERROR_CPP_PATH);
                lib_path.append(WIN_GPG_ERROR_LIB_PATH);
		lib_list.append('gdi32');
		lib_list.append('ws2_32');
		lib_list.append('dnsapi');
	else:
		lib_list.append('adns');
	
	if DEBUG_FLAG:
	    if DEBUG_KOS_ADDRESS != "":
	    	cpp_defines.append("__DEBUG_KOS_ADDRESS__='" + '"' + DEBUG_KOS_ADDRESS + '"' + "'");
	    if DEBUG_KOS_PORT != "":
	    	cpp_defines.append("__DEBUG_KOS_PORT__=" + DEBUG_KOS_PORT);
	
	hg_rev = commands.getoutput('hg tip | head -n 1 | cut -d \' \' -f 4').rstrip();
	cpp_defines.append("-DBUILD_ID='\"%s\"'" % hg_rev);
	cpp_defines.append("-D__KMOD__");
	
	env = BUILD_ENV.Copy();
	env.Append	(
			CPPPATH = cpp_path,
			CPPDEFINES = cpp_defines,
			CCFLAGS = [ '-W' ],
			LINKFLAGS = link_flags,
			LIBPATH = lib_path,
			LIBS = lib_list,
			);
	
	kmod_target = 'build/kmod/kmod';
	
	if DEBUG_FLAG and BUILD_SYS_NAME == 'windows':
	    kmod_target = 'build/kmod/kmod_debug';
	
	return env.Program(
		target = kmod_target,
		source = get_static_object_list(env, 'build/kmod/', 'kmo/', src_list),
		);


### This function returns the target to build the kmod test program.
def get_kmod_test_target():

    	src_list = 	[
			'k3p.c',
			'kmod.c',
			'kmod_test.c',
			'kmo_comm.c',
			'kmo_sock.c',
			'knp.c',
			'mail.c',
			];
	
	cpp_path = 	['base/', 'maildb/', 'crypt/', 'kmo/'];
	cpp_defines =	['__TEST__'];
	link_flags = 	[''];
	lib_path =	['build/maildb/', 'build/crypt/', 'build/base/'];
	lib_list = 	['kmomaildb', 'kmocrypt', 'kmobase', 'sqlite3', 'gcrypt', 'gpg-error', 'ssl', 'crypto'];
	
	if BUILD_SYS_NAME == 'windows':
		cpp_path.append(WIN_SQLITE_CPP_PATH);
		lib_path.append(WIN_SQLITE_LIB_PATH);
		cpp_path.append(WIN_OPENSSL_CPP_PATH);
		lib_path.append(WIN_OPENSSL_LIB_PATH);
		cpp_path.append(WIN_GCRYPT_CPP_PATH);
		lib_path.append(WIN_GCRYPT_LIB_PATH);
                cpp_path.append(WIN_GPG_ERROR_CPP_PATH);
                lib_path.append(WIN_GPG_ERROR_LIB_PATH);
		lib_list.append('ws2_32');
		lib_list.append('gdi32');
		lib_list.append('dnsapi');
	else:
		lib_list.append('adns');
		
	hg_rev = commands.getoutput('hg tip | head -n 1 | cut -d \' \' -f 4');
	cpp_defines.append("-DBUILD_ID='\"%s\"'" % hg_rev);
	
	env = BUILD_ENV.Copy();
	env.Append	(
			CPPPATH = cpp_path,
			CPPDEFINES = cpp_defines,
			CCFLAGS = [ '-W' ],
			LINKFLAGS = link_flags,
			LIBPATH = lib_path,
			LIBS = lib_list,
			);
	
	return env.Program(
		target = 'build/kmod_test/test',
		source = get_static_object_list(env, 'build/kmod_test/', 'kmo/', src_list),
		);
		
		
### This function populates the build list and returns it. It's OK to call this function 
### many times, it will only populate the list once.
def get_build_list():
	
	global build_list;
	global build_list_init;
	
	if build_list_init:
		return build_list;
	
	build_list_init = 1;
	
	build_list.append(get_base_lib_target());
	build_list.append(get_maildb_lib_target());
	build_list.append(get_crypt_lib_target());
	build_list.append(get_kmod_target());
	
	if KMO_FLAG:
	    build_list.append(get_kmo_target());
	
	if TEST_FLAG:
	    build_list.append(get_crypt_test_target());
	    build_list.append(get_maildb_test_target());
	    build_list.append(get_kmod_test_target());
		
	return build_list;


###########################################################################
### OPTIONS ###############################################################
###########################################################################

### Create options environment.
opts_env = Environment();

### Load the options values.
opts = Options('build/kmo.conf');
opts.AddOptions	(
		(BoolOption('debug', 'enable debugging', 1)),
		('debug_kos_address', 'KMOD KOS address override', ''),
		('debug_kos_port', 'KMOD KOS port override', ''),
		(BoolOption('kmo', 'build kmo program', 0)),
		(BoolOption('test', 'build test programs', 0)),
		);
		
opts.Update(opts_env);
opts_dict = opts_env.Dictionary();

### Get the configuration values.
DEBUG_FLAG = opts_dict['debug'];
KMO_FLAG = opts_dict['kmo'];
TEST_FLAG = opts_dict['test'];
DEBUG_KOS_ADDRESS = opts_dict['debug_kos_address'];
DEBUG_KOS_PORT = opts_dict['debug_kos_port'];

### Update the options values and save.
if not os.path.isdir('build/'):
    os.mkdir('build/');
    
opts.Save('build/kmo.conf', opts_env);

### Setup help text.
help_text = "Type: 'scons config [-Q]' to show current configuration.\n"\
	    "      'scons build' to build the targets.\n"\
	    "      'scons clean' to clean built targets.\n";
opts_help = opts.GenerateHelpText(opts_env);
Help(help_text);


###########################################################################
### BUILD TARGET HANDLING #################################################
###########################################################################

### Create build environment.
BUILD_ENV = Environment(ENV = os.environ);

### Set compilation flags.
BUILD_ENV.Append(CCFLAGS = [ '-Wall', '-fno-strict-aliasing']);

### Get GCC version.
gcc_version_match = re.compile('^(\d)\.').match(BUILD_ENV["CXXVERSION"]);

if not gcc_version_match:
	sys.stderr.write("Cannot determine GCC version.\n");
	Exit(1);

gcc_version = int(gcc_version_match.group(1));

if gcc_version >= 4:
	BUILD_ENV.Append(CCFLAGS = [ '-Wno-pointer-sign' ]);

if DEBUG_FLAG:
	BUILD_ENV.Append(CCFLAGS = [ '-g' ]);
else:
	BUILD_ENV.Append(CCFLAGS = [ '-O2' ]);
	BUILD_ENV.Append(CPPDEFINES = ['NDEBUG']);

if BUILD_SYS_NAME == 'windows':
    	BUILD_ENV.Append(CPPDEFINES = ['__WINDOWS__']);
else:
    	BUILD_ENV.Append(CPPDEFINES = ['__UNIX__']);
	
if BUILD_ENDIAN == 'big':
    	BUILD_ENV.Append(CPPDEFINES = ['__BIG_ENDIAN__']);
else:
    	BUILD_ENV.Append(CPPDEFINES = ['__LITTLE_ENDIAN__']);

### The list of targets to build/clean.
build_list = [];

### True if the build_list has been initiailized.
build_list_init = 0;

### Handle windows build.
###
### Note: if we specify a relative path that is below the directory that
### contains the SConstruct file, 'scons' will convert the path to an absolute
### path. Due to bugs in Cygwin, gcc will fail to find those paths (absolute 
### paths are broken in Cygwin). So we need to use *Windows* absolute paths.
###
### The libraries are expected to be in the 'lib' directory, itself located
### in the directory containing the root 'kmo' repository. Adjust the paths
### below if necessary.

win_lib_path = os.path.abspath(os.getcwd() + '/../lib/');
win_lib_path = re.compile("^/cygdrive/c/").sub("C:/", win_lib_path);
win_lib_path += "/";

WIN_SQLITE_CPP_PATH = win_lib_path + "sqlite";
WIN_SQLITE_LIB_PATH = win_lib_path + "sqlite";
WIN_OPENSSL_CPP_PATH = win_lib_path + "openssl-0.9.8d/include";
WIN_OPENSSL_LIB_PATH = win_lib_path + "openssl-0.9.8d";
WIN_GCRYPT_CPP_PATH = win_lib_path + "libgcrypt-1.2.2/src";

### It looks like gcc is linking gcrypt statically if we offer it the choice.
### If only the DLL is present, we get dynamic linking.
WIN_GCRYPT_LIB_PATH = win_lib_path + "gcrypt";
WIN_GPG_ERROR_CPP_PATH = win_lib_path + "libgpg-error-1.5/src";
WIN_GPG_ERROR_LIB_PATH = win_lib_path + "libgpg-error-1.5/src/.libs";


###########################################################################
### PHONY TARGETS #########################################################
###########################################################################

### Config: allow user to review current configuration. Include instructions
### on how to change it.
if 'config' in COMMAND_LINE_TARGETS:
	Alias("config", None);
	print_current_config();
	
### Build: build targets according to configuration.
elif 'build' in COMMAND_LINE_TARGETS:
	Alias("build", get_build_list());

### Clean: clean built targets.
elif 'clean' in COMMAND_LINE_TARGETS:
	SetOption("clean", 1);
	Alias("clean", get_build_list());

### No targets specified.
elif len(COMMAND_LINE_TARGETS) == 0:
		
	### Just print help.
	sys.stdout.write("\n%s\n" % help_text);
	Exit(0);
	
