//----------------------------------------------------------------------------
//
// TSDuck - The MPEG Transport Stream Toolkit
// Copyright (c) 2005-2017, Thierry Lelegard
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//
//----------------------------------------------------------------------------
//
//  CppUnit test suite for tsUserInterrupt.h
//
//  Since the purpose of this test is to interrupt the application, we don't do
//  it blindly! The interrupt is effective only if the environment variable
//  UTEST_INTERRUPT_ALLOWED is defined.
//
//----------------------------------------------------------------------------

#include "tsUserInterrupt.h"
#include "tsSysUtils.h"
#include "utestCppUnitTest.h"
TSDUCK_SOURCE;


//----------------------------------------------------------------------------
// The test fixture
//----------------------------------------------------------------------------

class InterruptTest: public CppUnit::TestFixture
{
public:
    virtual void setUp() override;
    virtual void tearDown() override;

    void testInterrupt();

    CPPUNIT_TEST_SUITE(InterruptTest);
    CPPUNIT_TEST(testInterrupt);
    CPPUNIT_TEST_SUITE_END();
};

CPPUNIT_TEST_SUITE_REGISTRATION(InterruptTest);


//----------------------------------------------------------------------------
// Initialization.
//----------------------------------------------------------------------------

// Test suite initialization method.
void InterruptTest::setUp()
{
}

// Test suite cleanup method.
void InterruptTest::tearDown()
{
}


//----------------------------------------------------------------------------
// Unitary tests.
//----------------------------------------------------------------------------

namespace {
    class TestHandler: public ts::InterruptHandler
    {
    public:
        virtual void handleInterrupt() override
        {
            std::cout << "* Got user-interrupt, next time should kill the process" << std::endl;
        }
    };
}

void InterruptTest::testInterrupt()
{
    if (ts::EnvironmentExists(u"UTEST_INTERRUPT_ALLOWED")) {
        std::cerr << "InterruptTest: Unset UTEST_INTERRUPT_ALLOWED to skip the interrupt test" << std::endl;

        TestHandler handler;
        ts::UserInterrupt ui(&handler, true, true);

        CPPUNIT_ASSERT(ui.isActive());
        std::cerr << "* Established one-shot handler" << std::endl;
        for (;;) {
            std::cerr << "* Press Ctrl+C..." << std::endl;
            ts::SleepThread(5000);
        }
    }
    else {
        utest::Out() << "InterruptTest: interrupt test skipped, define UTEST_INTERRUPT_ALLOWED to force it" << std::endl;
    }
}
