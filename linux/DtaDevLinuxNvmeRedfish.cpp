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
#include "os.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <cstdlib>
#include <string.h>
#include <unistd.h>
#include <linux/hdreg.h>
#include <errno.h>
#include "DtaDevLinuxNvmeRedfish.h"
#include "DtaHexDump.h"
#include <cppcodec/base64_rfc4648.hpp>
#include <nlohmann/json.hpp>

using base64 = cppcodec::base64_rfc4648;

std::string getBMCRedfishUri()
{
    const char *val = std::getenv("BMC_REDFISH_URI");
   	if (val == NULL)
		return std::string("http://localbmc:80");
	else
		return std::string(val);
}

/** The Device class represents a single disk device.
 *  Linux specific implementation using the NVMe interface
 */
DtaDevLinuxNvmeRedfish::DtaDevLinuxNvmeRedfish() : client(getBMCRedfishUri()) {
    client.set_connection_timeout(5, 0);  // 5 seconds
    client.set_read_timeout(20, 0);       // 20 seconds
    client.set_write_timeout(20, 0);      // 20 seconds
}

bool DtaDevLinuxNvmeRedfish::init(const char *devref)
{
	LOG(D1) << "Creating DtaDevLinuxNvmeRedfish::DtaDev() ";
	idfy_path = std::string("/google/v1/NVMe/") + devref + "/Controllers/0/Actions/NVMeController.Identify";
	if_send_path = std::string("/redfish/v1/Systems/system/Storage/") + devref + "/Controllers/0/Actions/StorageController.SecuritySend";
	if_recv_path = std::string("/redfish/v1/Systems/system/Storage/") + devref + "/Controllers/0/Actions/StorageController.SecurityReceive";
	LOG(D1) << idfy_path;
	LOG(D1) << if_send_path;
	LOG(D1) << if_recv_path;
	return TRUE;
}

/** Send an ioctl to the device using nvme admin commands. */
uint8_t DtaDevLinuxNvmeRedfish::sendCmd(ATACOMMAND cmd, uint8_t protocol, uint16_t comID,
					void *buffer, uint32_t bufferlen)
{
	if (IF_SEND == cmd)
	{
		LOG(D1) << "\nEntering DtaDevLinuxNvmeRedfish::IF_SEND";
		std::string encoded_data = base64::encode((char*)buffer, bufferlen);
		nlohmann::json body = {
			{"SecurityProtocol", protocol},
			{"SecurityProtocolSpecific", comID},
			{"Data", encoded_data}};
		LOG(D2) << body.dump() ;
		auto res = client.Post(if_send_path, body.dump(), "application/json");
		if (res.error() != httplib::Error::Success)
		{
			LOG(E) << "IF_SEND HTTP error: " << httplib::to_string(res.error()) ;
			return -1;
		}
	}
	else
	{
		LOG(D1) << "\nEntering DtaDevLinuxNvmeRedfish::IF_RECV";
		nlohmann::json body = {
			{"SecurityProtocol", protocol},
			{"SecurityProtocolSpecific", comID},
			{"AllocationLength", std::min((int)bufferlen, 4096)}};

		LOG(D2) << body.dump();

		auto res = client.Post(if_recv_path, body.dump(), "application/json");
		if (res.error() != httplib::Error::Success)
		{
			LOG(E) << "IF_RECV HTTP error: " << httplib::to_string(res.error()) ;
			return -1;
		}
		
		nlohmann::json response = nlohmann::json::parse(res->body);
		auto data = response["Data"].get<std::string>();
		std::vector<uint8_t> decoded = base64::decode(data);
		LOG(D3) << "bufferlen:" << bufferlen << ", return size:" << decoded.size() ;
		
		assert(decoded.size() <= bufferlen);
		std::copy(decoded.begin(), decoded.end(), (char*)buffer);
	}
	return 0;
}

void DtaDevLinuxNvmeRedfish::identify(OPAL_DiskInfo &disk_info)
{
	LOG(D1) << "Entering DtaDevLinuxNvmeRedfish::identify()" ;
	nlohmann::json body = {
		{"CNS", 1},
		{"NSID", 0},
		{"CNTID", 0}};
	auto res = client.Post(idfy_path, body.dump(), "application/json");
	if (res.error() != httplib::Error::Success)
	{
		LOG(E) << "identify HTTP error: " << httplib::to_string(res.error()) ;
		return;
	}

	disk_info.devType = DEVICE_TYPE_NVME;
	const char *results = (res->body).c_str();
	results += 4;
	memcpy(disk_info.serialNum, results, sizeof(disk_info.serialNum));
	results += sizeof(disk_info.serialNum);
	memcpy(disk_info.modelNum, results, sizeof(disk_info.modelNum));
	results += sizeof(disk_info.modelNum);
	memcpy(disk_info.firmwareRev, results, sizeof(disk_info.firmwareRev));
	return;
}

/** Close the device reference so this object can be delete. */
DtaDevLinuxNvmeRedfish::~DtaDevLinuxNvmeRedfish()
{
	LOG(D1) << "Destroying DtaDevLinuxNvmeRedfish";
}
