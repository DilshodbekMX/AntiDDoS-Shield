# Fuzz Tests Build Configuration
#
# Fuzz tests require clang with libFuzzer support.
# Build with: CC=clang meson setup builddir -Dbuild_fuzz=true
# Run with:   ./builddir/tests/fuzz/fuzz_packet_parser corpus/ -jobs=4
#
# For standalone testing (without libFuzzer):
#   meson compile -C builddir fuzz_packet_parser_standalone

if get_option('build_fuzz')
    # Check for clang (libFuzzer requires clang)
    cc = meson.get_compiler('c')

    if cc.get_id() == 'clang'
        # libFuzzer-enabled fuzz targets
        fuzz_packet_parser = executable(
            'fuzz_packet_parser',
            files('fuzz_packet_parser.c'),
            c_args: ['-fsanitize=fuzzer,address', '-g', '-DFUZZ_WITH_LIBFUZZER'],
            link_args: ['-fsanitize=fuzzer,address'],
            include_directories: [include_directories('../../')],
            install: false,
        )

        fuzz_json_config = executable(
            'fuzz_json_config',
            files('fuzz_json_config.c'),
            c_args: ['-fsanitize=fuzzer,address', '-g', '-DFUZZ_WITH_LIBFUZZER'],
            link_args: ['-fsanitize=fuzzer,address'],
            include_directories: [include_directories('../../')],
            install: false,
        )

        message('Fuzz targets built with libFuzzer support')
    else
        warning('libFuzzer requires clang - building standalone fuzz tests only')
    endif

    # Standalone versions (for testing without libFuzzer)
    fuzz_packet_parser_standalone = executable(
        'fuzz_packet_parser_standalone',
        files('fuzz_packet_parser.c'),
        c_args: ['-g', '-DFUZZ_STANDALONE'],
        include_directories: [include_directories('../../')],
        install: false,
    )

    fuzz_json_config_standalone = executable(
        'fuzz_json_config_standalone',
        files('fuzz_json_config.c'),
        c_args: ['-g', '-DFUZZ_STANDALONE'],
        include_directories: [include_directories('../../')],
        install: false,
    )

    # Register as tests (standalone versions)
    test('fuzz_packet_parser_standalone', fuzz_packet_parser_standalone, suite: 'fuzz')
    test('fuzz_json_config_standalone', fuzz_json_config_standalone, suite: 'fuzz')
endif
