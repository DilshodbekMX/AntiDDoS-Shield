# Integration Tests Build Configuration
#
# Build with: meson compile -C builddir
# Run with:   meson test -C builddir --suite integration
#
# Note: Integration tests require libpcap-dev

if get_option('build_tests')
    pcap_dep = dependency('libpcap', required: false)

    if pcap_dep.found()
        test_env = environment()
        test_env.set('XDG_RUNTIME_DIR', '/tmp')

        # PCAP Replay Library
        pcap_replay_lib = static_library('pcap_replay',
            files('pcap_replay.c'),
            dependencies: [dpdk_dep, pcap_dep],
            link_with: [layer1_lib],
            include_directories: [include_directories('../../')],
        )

        # Integration Test: PCAP Replay
        test_pcap_integration = executable(
            'test_pcap_integration',
            files('test_pcap_integration.c'),
            dependencies: [dpdk_dep, pcap_dep],
            link_with: [pcap_replay_lib, layer1_lib],
            include_directories: [include_directories('../../')],
            install: false,
        )
        test('pcap_integration_tests', test_pcap_integration, suite: 'integration', env: test_env)

        # Integration Test: Carpet-bomb across a protected /24 aggregates to one slot
        test_carpet_bomb_subnet = executable(
            'test_carpet_bomb_subnet',
            files('test_carpet_bomb_subnet.c'),
            dependencies: [dpdk_dep, pcap_dep],
            link_with: [pcap_replay_lib, layer1_lib],
            include_directories: [include_directories('../../')],
            install: false,
        )
        test('carpet_bomb_subnet_tests', test_carpet_bomb_subnet, suite: 'integration', env: test_env)

    else
        message('libpcap not found - skipping PCAP integration tests')
    endif
endif
