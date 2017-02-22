Velo C Crypto Library
=====================

The Velo C Crypto Library is a low-level C library that provides interfaces and
implementations for cryptographic primitives and operations necessary to
interface with the Velo ledger.

Building
========

The [`vc-toolchain`][vc-toolchain-url] project needs to be installed in the
`/opt/vctoolchain` subdirectory.  If a different installation directory is used,
then the `TOOLCHAIN_DIR` environment variable should be set to that directory
instead.  The [Velo Portable Runtime][vpr-url] library is required to link
against this library and to run the test cases.

[vc-toolchain-url]: https://github.com/VeloPayments/vc-toolchain
[vpr-url]: https://github.com/VeloPayments/vpr

The default build target will just build the vccrypt release library for each
supported platform.  To run unit tests, use the `test` build target.  This will
build both the release and the checked libraries for the current host.  The
`test` build target depends on Google Test.  The location of the Google Test
source distribution must be included in the `GTEST_DIR` environment variable.
For instance:

    #build just the release libraries
    make
    
    #build with unit tests - also builds checked libraries
    GTEST_DIR="path/to/google/test" make test

The resulting library will be available under the `build` subdirectory, which
will be created as part of the build process.

This library also supports model checking via [CBMC][cbmc-url].  To run the
model checks, use the following build target.  Note that the `cbmc` executable
must be in the current `PATH`.

    #run model checks
    make model-check

[cbmc-url]: http://www.cprover.org/cbmc/

Continuous Integration Recommendations
--------------------------------------

It is recommended that this project be run downstream of the `vpr` library and
upstream of any libraries that depend on it in the build pipeline.
Additionally, all three of the supported build targets, `make`, `make
model-check`, and `make test` should be run as described in the previous
section.  If any of these build targets fail, then the build should be
considered a failure.
