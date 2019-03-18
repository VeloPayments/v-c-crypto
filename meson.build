project('vccrypt', 'c', 'cpp',
  default_options : ['c_std=gnu11', 'cpp_std=c++14'],
  meson_version : '>=0.49.0'
)

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

src = run_command('find', './src', '-name', '*.c', check : true).stdout().strip().split('\n')
test_src = run_command('find', './test', '-name', '*.cpp', check : true).stdout().strip().split('\n')

# GTest is currently only used on native x86 builds. Creating a disabler will disable the test exe and test target.
if meson.is_cross_build()
  gtest = disabler()
else
  gtest = dependency('gtest', main : true, required : true, fallback : ['gtest','gtest_dep'])
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

vccrypt_lib = static_library(
  'vccrypt',
  src,
  dependencies : [vcmodel, vpr],
  include_directories : vccrypt_include
)

vccrypt_dep = declare_dependency(
  link_with : vccrypt_lib,
  include_directories : vccrypt_include
)

vccrypt_test = executable(
  'testvccrypt',
  test_src,
  include_directories : vccrypt_include,
  dependencies : [vpr, gtest],
  link_with : vccrypt_lib
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
