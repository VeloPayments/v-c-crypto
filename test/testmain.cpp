/**
 * \file testmain.cpp
 *
 * This is the command-line test runner for vccrypt unit tests.
 *
 * \copyright 2017 Velo-Payments, Inc.  All rights reserved.
 */

#include <gtest/gtest.h>
#include <iostream>

using namespace std;

GTEST_API_ int main(int argc, char* argv[])
{
    cout << "Running main() from " << __FILE__ << endl;

    testing::InitGoogleTest(&argc, argv);

    return RUN_ALL_TESTS();
}
