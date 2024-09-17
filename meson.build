project(
    'noise',
    'c',
    'cpp',
    version: '0.1',
    default_options: ['warning_level=3', 'c_std=c18', 'cpp_std=c++20'],
)

magic_enum = dependency('magic_enum', static: true)
fmt = dependency('fmt', static: true)
noise_sources = [
    'monocypher.c',
    'monocypher-ed25519.c',
    'rng_get_bytes.c',
    'noise.cpp',
]
cpp_args = []
extra_deps = []
if host_machine.system() == 'windows'
    cpp_args += ['-D_WIN32_WINNT=0x0A00']
    cpp = meson.get_compiler('cpp')
    ws2_32 = cpp.find_library('ws2_32', required: true)
    extra_deps += ws2_32
endif

executable(
    'cpp-client',
    noise_sources,
    'easywsclient.cpp',
    'cpp-client.cpp',
    dependencies: [magic_enum, fmt, extra_deps],
    cpp_args: cpp_args,
)
