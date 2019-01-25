project('OTAESGCM', 'cpp',
    default_options : [
        'c_std=c11', 'cpp_std=c++11']
)

cpp_args = [
        '-O0',
        '-Wall', '-Werror',
        '-Wno-non-virtual-dtor',
        '-DEXT_AVAILABLE_ARDUINO_LIB_OTAESGCM'
]
cpp_args_clang_compat = ['-fstack-check', '-fstack-protector-strong']


compiler = meson.get_compiler('cpp')
if (compiler.get_id() == 'gcc') # and (compiler.version().version_compare('<8'))
    cpp_args += cpp_args_clang_compat
else
    warning('Skipping -fstack-check and -fstack-protector-strong due to old compiler version.')
endif

# Setup and compile gtest.
# Tries to find gtest via normal dependency manager (e.g. pkgconf) and falls 
# back to downloading and compiling using a wrap file.
gtest_dep = dependency('gtest_main', required : false)
if not gtest_dep.found()
    thread_dep = dependency('threads')
    gtest_proj = subproject('gtest')
    gtest_inc = gtest_proj.get_variable('gtest_incdir')
    gtest_src = [
        gtest_proj.get_variable('gtest_libsources'), 
        gtest_proj.get_variable('gtest_mainsources')
    ]
    gtest_lib = static_library('gtest', gtest_src,
        include_directories : gtest_inc,
        dependencies : thread_dep) # + all your args here
    gtest_dep = declare_dependency(
        include_directories : gtest_inc, 
        link_with : gtest_lib)
endif

# Compile OTAESGCM library for other tests.
inc = include_directories(
    'content/OTAESGCM',
    'content/OTAESGCM/utility',
    'portableUnitTests'
)

src = [
    'content/OTAESGCM/utility/OTAESGCM_OTAES128AVR.cpp',
    'content/OTAESGCM/utility/OTAESGCM_OTAESGCM.cpp',
]

libOTAESGCM = static_library('OTAESGCM', src,
    include_directories : inc,
    cpp_args : cpp_args,
    install : true
)

libOTAESGCM_dep = declare_dependency(
    include_directories : inc, 
    link_with : libOTAESGCM
)

if not meson.is_subproject()
    # Compile test executable.
    # This is broken out to avoid compile errors due to lack of gtest.
    test_src = 'portableUnitTests/main.cpp'

    test_app = executable('OTAESGCMTests', [src, test_src],
        include_directories : inc,
        dependencies : gtest_dep,
        cpp_args : cpp_args,
        install : false
    )

    test('unit_tests', test_app)
endif
