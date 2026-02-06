# CMake generated Testfile for 
# Source directory: /home/shura/projects/elefp
# Build directory: /home/shura/projects/elefp/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(TestKem "/home/shura/projects/elefp/build/test_kem")
set_tests_properties(TestKem PROPERTIES  _BACKTRACE_TRIPLES "/home/shura/projects/elefp/CMakeLists.txt;136;add_test;/home/shura/projects/elefp/CMakeLists.txt;0;")
add_test(CryptoUnit "/home/shura/projects/elefp/build/crypto_test")
set_tests_properties(CryptoUnit PROPERTIES  _BACKTRACE_TRIPLES "/home/shura/projects/elefp/CMakeLists.txt;137;add_test;/home/shura/projects/elefp/CMakeLists.txt;0;")
add_test(VpnComponents "/home/shura/projects/elefp/build/vpn_component_test")
set_tests_properties(VpnComponents PROPERTIES  _BACKTRACE_TRIPLES "/home/shura/projects/elefp/CMakeLists.txt;138;add_test;/home/shura/projects/elefp/CMakeLists.txt;0;")
add_test(VpnIntegration "/home/shura/projects/elefp/build/vpn_integration_test")
set_tests_properties(VpnIntegration PROPERTIES  _BACKTRACE_TRIPLES "/home/shura/projects/elefp/CMakeLists.txt;139;add_test;/home/shura/projects/elefp/CMakeLists.txt;0;")
