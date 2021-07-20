/* C:B**************************************************************************
This software is Copyright 2014-2017 Bright Plaza Inc. <drivetrust@drivetrust.com>

This file is part of sedutil.

sedutil is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

sedutil is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with sedutil.  If not, see <http://www.gnu.org/licenses/>.

 * C:E********************************************************************** */
#pragma once

#include <vector>
#include "DtaLexicon.h"
class DtaDevOpal;
class DtaDevEnterprise;

using namespace std;

/** A class to build & send Opal Command streams to a TPer.
* This class attempts to closely mimic the command
* pseudo code used in the TCG documents, the syntactic
* sugar is not represented.  See TCG document Storage Architecture
* Core Specification R2.00 V2.00 Section 3.2.1.2 for all
* the gory details.
*
* @see DtaLexicon.h for structs, typedefs and enums used to encode
* the bytestream.
*/
class DtaCommand {
	friend class DtaDevOpal;
	friend class DtaDevEnterprise;
public:
    /** Default constructor, allocates the command and resonse buffers. */
    DtaCommand();
    /** Constructor that initializes the incokingUid and method fields.
     *   @param InvokingUid  The UID used to call the SSC method
     *   @param method The SSC method to be called
     */
    DtaCommand(const OPAL_UID InvokingUid, const OPAL_METHOD method);
    /** destructor  frees the command and response buffers */
    ~DtaCommand();
    /** Add a Token to the bytstream of type OPAL_TOKEN. */
    void addToken(const OPAL_TOKEN token);
    /** Add a Token to the bytstream of type OPL_SHORT ATOM. */
    void addToken(const OPAL_SHORT_ATOM token);
    /** Add a Token to the bytstream of type OPL_TINY ATOM. */
    void addToken(const OPAL_TINY_ATOM token);
    /** Add a Token to the bytstream of from the OPALUID array. */
    void addToken(const OPAL_UID token);
    /** Add a Token to the bytstream of type c-string */
    void addToken(const char * bytestring);
    /** Add a Token to the bytstream of type vector<uint8_t>.
     * This token must be a complete token properly encoded
     * with the proper TCG bytestream header information  */
    void addToken(const std::vector<uint8_t> token);
    /** Add a Token to the bytstream of type uint64. */
    void addToken(const uint64_t number);
    /** Set the commid to be used in the command. */
    void setcomID(const uint16_t comID) const;
    /** set the Host session number to be used in the command. */
    void setHSN(const uint32_t HSN) const;
    /** Set the TPer session number to be used for the command. */
    void setTSN(const uint32_t TSN) const;
    /** Add the required fields to the end of the bytestream. If EOD is true (default) the
     * EOD token and the method status list will be added to the end of the bytestream.
     * Then the bytstram is padded to a 4-byte boundary if required and the length fields
     * are populated in packet, subpacket and command packet.
     *
     *  @param EOD a bool to signal that command requires the EOD and method status fields
     */
    void complete(const uint8_t EOD = 1);
    /** Clears the command buffer and resets the the end of buffer pointer
     * @see bufferpos
     */
    void reset();
    /** Clears the command buffer and resets the the end of buffer pointer
     * also initializes the invoker and method fields.
     *
     *   @param InvokingUid  The UID used to call the SSC method
     *   @param method The SSC method to be called
     */
    void reset(const OPAL_UID InvokingUid, const OPAL_METHOD method);
    /** Clears the command buffer and resets the the end of buffer pointer
     * also initializes the invoker and method fields.
     * The invoker is passed as a vector<uint8_t> this is used for the case
     * where the invoker is not an OPAL user, typically a table.
     *
     *   @param InvokingUid  The UID used to call the SSC method
     *   @param method The SSC method to be called
     */
    void reset(const OPAL_UID InvokingUid, const std::vector<uint8_t>& method);
    /** Clears the command buffer and resets the the end of buffer pointer
     * also initializes the invoker and method fields.
     * Both the invoker and method are passed as a vector<uint8_t>
     *
     *   @param InvokingUid  The UID used to call the SSC method
     *   @param method The SSC method to be called
     */
    void reset(const std::vector<uint8_t>& InvokingUid, const std::vector<uint8_t>& method);
	/** Clears the command buffer and resets the the end of buffer pointer
     * also initializes the invoker and method fields.
     * The invoker and method are passed as a vector<uint8_t>.
	 * The method is from the enumeration
     *
     *   @param InvokingUid  The UID used to call the SSC method
     *   @param method The SSC method to be called
     */
	void reset(const std::vector<uint8_t>& InvokingUid, const OPAL_METHOD method);
	/** Changes the invoker field.
     * The invoker is passed as a vector<uint8_t> this is used for the case
     * where the invoker is not an OPAL user, typically a table.
     *
     *   @param Invoker  The UID used to call the SSC method
     */
    void changeInvokingUid(const vector<uint8_t>& Invoker);
    /** Produce a hexdump of the response.  Typically used in debugging and tracing */
	void dumpResponse() const;
    /** Produce a hexdump of the command.  Typically used in debugging and tracing */
	void dumpCommand() const;
	/** Return the space used in the command buffer (rounded to 512 bytes) */
	uint16_t outputBufferSize() const;
private:
    /** return a pointer to the command buffer */
	void * getCmdBuffer() const;
    /** return a pointer to the response buffer. */
	void * getRespBuffer() const;
	uint8_t commandbuffer[MAX_BUFFER_LENGTH + IO_BUFFER_ALIGNMENT]; /**< buffer allocation allow for 1k alignment */
	uint8_t responsebuffer[PROP_BUFFER_LENGTH + IO_BUFFER_ALIGNMENT]; /**< buffer allocation allow for 1k alignment */
	uint8_t *cmdbuf;  /**< Pointer to the command buffer */
    uint8_t *respbuf;  /**< pointer to the response buffer */
    uint32_t bufferpos = 0;  /**< position of the next byte in the command buffer */
};
