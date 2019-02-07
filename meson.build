project(
  'vccrypt', 
  'c', 
  'cpp',
  default_options : ['c_std=gnu11', 'cpp_std=c++14']
)

add_project_arguments('-Wall', '-Werror', '-Wextra', language : 'c')
add_project_arguments('-Wall', '-Werror', '-Wextra', language : 'cpp')

src = run_command('find', './src', '-name', '*.c', check : true).stdout().strip().split('\n')
test_src = run_command('find', './test', '-name', '*.cpp', check : true).stdout().strip().split('\n')

gtest = dependency('gtest', main : true, required : false)

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

vccrypt_test = executable(
  'testvccrypt',
  test_src,
  include_directories : vccrypt_include,
  dependencies : [vpr, gtest],
  link_with : vccrypt_lib
)

test(
  'libvccrypt-test', 
  vccrypt_test,
  workdir : meson.source_root()
)

vccrypt_dep = declare_dependency(
  link_with : vccrypt_lib,
  include_directories : vccrypt_include
)
