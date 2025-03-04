//----------------------------------------------------------------------------
//
// TSDuck - The MPEG Transport Stream Toolkit
// Copyright (c) 2005-2025, Thierry Lelegard
// BSD-2-Clause license, see LICENSE.txt file or https://tsduck.io/license
//
//----------------------------------------------------------------------------
//!
//!  @file
//!  Full identification of a DVB service (aka "DVB triplet")
//!
//----------------------------------------------------------------------------

#pragma once
#include "tsTransportStreamId.h"

namespace ts {
    //!
    //! Full identification of a DVB service (aka "DVB triplet").
    //! @ingroup libtsduck mpeg
    //!
    class TSDUCKDLL ServiceIdTriplet: public TransportStreamId
    {
    public:
        // Public members:
        uint16_t service_id = 0;  //!< Service id.
        uint8_t  version = 0;     //!< General-purpose version (typically a table version), not part of the DVB triplet.

        //!
        //! Default constructor.
        //!
        ServiceIdTriplet() = default;

        //!
        //! Constructor.
        //! @param [in] svid Service id.
        //! @param [in] tsid Transport stream id.
        //! @param [in] onid Original network id.
        //! @param [in] vers Optional version.
        //!
        ServiceIdTriplet(uint16_t svid, uint16_t tsid, uint16_t onid, uint8_t vers = 0) :
            TransportStreamId(tsid, onid),
            service_id(svid),
            version(vers)
        {
        }

        //!
        //! Constructor.
        //! @param [in] svid Service id.
        //! @param [in] tsid Full transport stream id.
        //! @param [in] vers Optional version.
        //!
        ServiceIdTriplet(uint16_t svid, const TransportStreamId& tsid, uint8_t vers = 0) :
            TransportStreamId(tsid),
            service_id(svid),
            version(vers)
        {
        }

        //! @cond nodoxygen
        auto operator<=>(const ServiceIdTriplet&) const = default;
        //! @endcond

        //!
        //! Get a "normalized" 64-bit identifier.
        //! This is a value containing the original network id, TS id, service id and version.
        //! @return The "normalized" 64-bit identifier of the TS.
        //!
        uint64_t normalized() const
        {
            return (uint64_t(original_network_id) << 40) | (uint64_t(transport_stream_id) << 24) | (uint64_t(service_id) << 8) | uint64_t(version);
        }

        // Inherited methods.
        virtual void clear() override;

        // Implementation of StringifyInterface.
        virtual UString toString() const override;
    };

    // Containers:
    using ServiceIdTripletSet = std::set<ServiceIdTriplet>;        //!< Set of ServiceIdTriplet.
    using ServiceIdTripletVector = std::vector<ServiceIdTriplet>;  //!< Vector of ServiceIdTriplet.
}
