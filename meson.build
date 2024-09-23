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

if get_option('build_examples')
    fmt = dependency('fmt', static: true)
    examples = files(
        'examples/Noise_NN_25519_ChaChaPoly_Blake2b.cpp',
        'examples/Noise_XX_25519_ChaChaPoly_Blake2b.cpp',
        'examples/enet-client.cpp',
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

cpp_args = []
cpp = meson.get_compiler('cpp')
if cpp.get_argument_syntax() == 'msvc' and cpp.has_argument('/Zc:preprocessor') and cpp.has_argument('/permissive-') and cpp.has_argument('/Zc:lambda')
cpp_args += ['/Zc:preprocessor', '/permissive-', '/Zc:lambda']
endif

test_runner = executable(
    'test_runner',
    noise_sources,
    'tests/runner/test_runner.cpp',
    dependencies: [magic_enum, fmt],
    cpp_args: cpp_args,
    override_options : ['cpp_std=c++latest,c++23'],
    include_directories: include_directories('tests/runner'),
)

subdir('tests/vectors')
subdir_done()
