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
