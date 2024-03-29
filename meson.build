project('vccrypt', 'c', 'cpp',
  version : '0.4.2-snapshot',
  default_options : ['c_std=c11', 'cpp_std=c++14', 'buildtype=release'],
  meson_version : '>=0.49.0'
)

message('Using build type: ' + get_option('buildtype'))

force_velo_toolchain = get_option('force_velo_toolchain')

if force_velo_toolchain
  cc = meson.get_compiler('c')
  cc_version = run_command(cc.cmd_array() + ['--version'], check : true).stdout()
  if not cc_version.contains('(velo)')
    error('force_velo_toolchain is set and you arn\'t using the velo toolchain.')
  endif
  cpp = meson.get_compiler('cpp')
  cpp_version = run_command(cpp.cmd_array() + ['--version'], check : true).stdout()
  if not cpp_version.contains('(velo)')
    error('force_velo_toolchain is set and you arn\'t using the velo toolchain.')
  endif
else
  warning('Not using the blessed velo gcc toolchain. Here be dragons.')
endif

add_project_arguments('-Wall', '-Werror', '-Wextra', language : 'c')
add_project_arguments('-Wall', '-Werror', '-Wextra', language : 'cpp')

#non-mock source files
src = run_command(
  'find', './src', '-name', '*.c', '-and', '(', '!', '-path',
  '"*/src/mock/*"', ')',
  check : true).stdout().strip().split('\n')
#mock source files
src_mock = run_command(
  'find', './src/mock', '-name', '*.c', '-or', '-name', '*.cpp',
  check : true).stdout().strip().split('\n')
#test source files
test_src = run_command('find', './test', '-name', '*.cpp', check : true).stdout().strip().split('\n')

# GTest is currently only used on native x86 builds. Creating a disabler will disable the test exe and test target.
if meson.is_cross_build()
  minunit = disabler()
else
  minunit = dependency('minunit', main : true, required : true, fallback : ['minunit', 'minunit_dep'])
endif

vcmodel = dependency(
  'vcmodel',
  required : true,
  fallback : ['vcmodel', 'vcmodel_dep']
)

vpr = dependency(
  'vpr',
  required : true,
  fallback : ['vpr', 'vpr_dep']
)

vccrypt_include = include_directories('include')
config_include = include_directories('.')

vccrypt_lib = static_library(
  'vccrypt',
  src,
  dependencies : [vcmodel, vpr],
  include_directories : [vccrypt_include, config_include]
)

vccrypt_mock_lib = static_library(
  'vccrypt_mock',
  src_mock,
  dependencies : [vcmodel, vpr],
  include_directories : [vccrypt_include, config_include]
)

vccrypt_dep = declare_dependency(
  link_with : vccrypt_lib,
  include_directories : vccrypt_include
)

vccrypt_test = executable(
  'testvccrypt',
  test_src,
  include_directories : [vccrypt_include, config_include],
  dependencies : [vpr, minunit],
  link_with : [vccrypt_lib, vccrypt_mock_lib]
)

test_env = environment()
test_env.set(
  'TEST_SIGNATURE_PATH',
  meson.current_source_dir() / 'test/digital_signature/sign.input'
)

test(
  'libvccrypt-test',
  vccrypt_test,
  env : test_env
)

conf_data = configuration_data()
conf_data.set('VERSION', meson.project_version())
configure_file(
  input : 'config.h.in',
  output : 'config.h',
  configuration : conf_data
)

# vim: ts=2 sw=2 et colorcolumn=120
