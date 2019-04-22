//----------------------------------------------------------------------------
//
// TSDuck - The MPEG Transport Stream Toolkit
// Copyright (c) 2005-2019, Thierry Lelegard
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

#include "tsMultilingualNetworkNameDescriptor.h"
#include "tsDescriptor.h"
#include "tsTablesFactory.h"
TSDUCK_SOURCE;

#define MY_XML_NAME u"multilingual_network_name_descriptor"
#define MY_XML_ATTR u"network_name"
#define MY_DID ts::DID_MLINGUAL_NETWORK

TS_XML_DESCRIPTOR_FACTORY(ts::MultilingualNetworkNameDescriptor, MY_XML_NAME);
TS_ID_DESCRIPTOR_FACTORY(ts::MultilingualNetworkNameDescriptor, ts::EDID::Standard(MY_DID));
TS_ID_DESCRIPTOR_DISPLAY(ts::MultilingualNetworkNameDescriptor::DisplayDescriptor, ts::EDID::Standard(MY_DID));


//----------------------------------------------------------------------------
// Constructors and destructors.
//----------------------------------------------------------------------------

ts::MultilingualNetworkNameDescriptor::MultilingualNetworkNameDescriptor() :
    AbstractMultilingualDescriptor(MY_DID, MY_XML_NAME, MY_XML_ATTR)
{
    _is_valid = true;
}

ts::MultilingualNetworkNameDescriptor::MultilingualNetworkNameDescriptor(DuckContext& duck, const Descriptor& desc) :
    MultilingualNetworkNameDescriptor()
{
    deserialize(duck, desc);
}

ts::MultilingualNetworkNameDescriptor::~MultilingualNetworkNameDescriptor()
{
}
