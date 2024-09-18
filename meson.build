project(
    'noise',
    'c',
    'cpp',
    version: '0.1',
    default_options: ['warning_level=3', 'c_std=c18', 'cpp_std=c++20'],
)
fs = import('fs')

magic_enum = dependency('magic_enum', static: true)
noise_sources = [
    'monocypher.c',
    'monocypher-ed25519.c',
    'rng_get_bytes.c',
    'noise.cpp',
]

if get_option('build_test_clients')
    enet = dependency('enet', static: true)
    fmt = dependency('fmt', static: true)
    cpp_args = []
    extra_deps = []
    if host_machine.system() == 'windows'
        cpp_args += ['-D_WIN32_WINNT=0x0A00']
        cpp = meson.get_compiler('cpp')
        ws2_32 = cpp.find_library('ws2_32', required: true)
        extra_deps += ws2_32
    endif

    if get_option('build_ws_test_client')
        executable(
            'ws-client',
            noise_sources,
            'test-clients/cpp/websockets/easywsclient.cpp',
            'test-clients/cpp/websockets/ws-client.cpp',
            dependencies: [magic_enum, fmt, extra_deps],
            cpp_args: cpp_args,
        )
    endif

    if get_option('build_enet_test_client')
        executable(
            'enet-client',
            noise_sources,
            'test-clients/cpp/enet/enet-client.cpp',
            dependencies: [magic_enum, fmt, extra_deps, enet],
            cpp_args: cpp_args,
        )
    endif
endif

if get_option('build_examples')
    examples = files(
        'examples/Noise_NN_25519_ChaChaPoly_Blake2b.cpp',
        'examples/Noise_XX_25519_ChaChaPoly_Blake2b.cpp',
    )
    foreach example : examples
        executable(
            fs.stem(example),
            noise_sources,
            example,
            dependencies: [magic_enum, fmt],
        )
    endforeach
endif
