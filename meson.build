project('libsuci', 'c',
    version : '1.1.0',
    license : 'GNU  AGPL v3.0',
    meson_version : '>= 0.43.0',
    default_options : [
        'warning_level=1',
        'c_std=gnu11',
        'prefix=/usr',
    ],
)

libsuci_version = meson.project_version()
libsuci_soversion = '1.1.0'

prefix = get_option('prefix')
bindir = join_paths(prefix, get_option('bindir'))
libdir = join_paths(prefix, get_option('libdir'))
sysconfdir = join_paths(prefix, get_option('sysconfdir'))
localstatedir = join_paths(prefix, get_option('localstatedir'))

cc = meson.get_compiler('c')
host_system = host_machine.system()

flex = find_program('flex')
bison = find_program('bison')

# Compiler flags
if cc.get_id() == 'gcc' or cc.get_id() == 'clang'
    possible_cc_flags = [
        '-Werror',

        '-Wno-unused-variable',
        '-Wno-unused-but-set-variable',
        '-Wno-maybe-uninitialized',
        '-Wno-format-truncation',
        '-Wno-stringop-truncation',
    ]
else
    possible_cc_flags = []
endif

add_project_arguments(
    cc.get_supported_arguments(possible_cc_flags),
    language : 'c')

libsuci_sources = files('''
    inc/suci_calcs.h
    inc/suci_utils.h

    src/suci_calcs.c
    src/suci_utils.c
'''.split())

libsuci_includes = include_directories('''
    inc
    .
'''.split())

libsuci = library('suci',
    sources : libsuci_sources,
    version : libsuci_soversion,
    include_directories : [libsuci_includes],
    install : true)

libsuci_dep = declare_dependency(
    link_with : libsuci,
    include_directories : [libsuci_includes]
)
