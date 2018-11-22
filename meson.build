project('OTAESGCM', 'cpp',
    default_options : [
        'c_std=c11', 'cpp_std=c++11']
)

gtest_dep = dependency('gtest_main')

inc = include_directories(
    'content/OTAESGCM',
    'content/OTAESGCM/utility',
    'portableUnitTests'
)

src = [
    'content/OTAESGCM/utility/OTAESGCM_OTAES128AVR.cpp',
    'content/OTAESGCM/utility/OTAESGCM_OTAESGCM.cpp',
    'portableUnitTests/main.cpp'
]

libOTAESGCM = static_library('OTAESGCM', src,
    include_directories : inc,
    cpp_args : [
        '-O0',
        '-Wall', '-Werror',
        '-Wno-non-virtual-dtor',
        '-fstack-check', '-fstack-protector-strong'
    ],
    install : true
)


libOTAESGCM_dep = declare_dependency(
    include_directories : inc, 
    link_with : libOTAESGCM
)

test_app = executable('OTAESGCMTests', src,
    include_directories : inc,
    dependencies : gtest_dep,
    cpp_args : [
        '-O0',
        '-Wall', '-Werror',
        '-Wno-non-virtual-dtor',
        '-fstack-check', '-fstack-protector-strong'
    ],
    install : false
)

test('unit_tests', test_app)
