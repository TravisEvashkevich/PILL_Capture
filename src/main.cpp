#include <Arduino.h> 

#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>

#include <cstdint>
#include <iostream>
#include <cmath>
#include <vector>
#include <string>
// #include <FS.h> // Include the file system library

std::vector<BLEAddress> targetAddresses;

// From https://gitlab.com/rapt.io/public/-/wikis/Pill%20Hydrometer%20Bluetooth%20Transmissions

// #include <cstdint>
#include <cstring>
#include <assert.h>

enum class PacketFieldType : uint8_t
{
	//! @brief The packet is a 
	Flags = 0x01u,
	Data = 0xFFu,
};

//! @brief The header sent before every packet
struct PacketField_Header
{
	//! @brief The type of packet that is in the payload
	PacketFieldType m_type;

	//! @brief The size in bytes of the payload packet
	uint8_t m_sizeInBytes;
};

struct PacketField_Flags
{
	//! @brief Always 0x06
	uint8_t m_flags;
};

enum class PacketField_Data_Type
{
	V1,
	V2,
	FirmwareVersion,
	DeviceType
};

struct PacketField_Data_V1
{
	//! @brief The MAC address used for registration
	//! @details Only lower 6 bytes are used, upper 2 bytes are always 0x0000
	uint64_t m_macAddress;

	//! @brief The temperature in Kelvin, multiplied by 128
	uint16_t m_temperature;

	//! @brief The specific gravity
	float m_specificGravity;

	//! @{
	//! @brief Raw acceleromater data multiplied by 16
	int16_t m_acceleromaterX;
	int16_t m_acceleromaterY;
	int16_t m_acceleromaterZ;
	//! @}

	//! @brief The charge of the battery as a percentage multiplied by 256
	uint16_t m_batteryCharge;
};

struct PacketField_Data_V2
{
	//! @brief Does this packet have valid gravity data?
	bool m_hasValidGravityData;

	//! @brief Gravity velocity, in points per day
	//! @details This field only has valid data if m_hasValidGravityData is true
	float m_gravityVelocity;

	//! @brief The temperature in Kelvin, multiplied by 128
	uint16_t m_temperature;

	//! @brief The specific gravity
	float m_specificGravity;

	//! @{
	//! @brief Raw acceleromater data multiplied by 16
	int16_t m_acceleromaterX;
	int16_t m_acceleromaterY;
	int16_t m_acceleromaterZ;
	//! @}

	//! @brief The charge of the battery as a percentage multiplied by 256
	uint16_t m_batteryCharge;
};

struct PacketField_Data_FirmwareVersion
{
	//! @brief The length of the amount of characters in the m_firmwareVersion string, not including null-terminating character
	uint8_t m_firmareVersionLength;

	//! @brief A null-terminated string of the firmware version
	char m_firmwareVersion[ 23u ];
};

struct PacketField_Data_DeviceType
{
	//! @brief The length of the amount of characters in the m_deviceType string, not including null-terminating character
	uint8_t m_deviceTypeLength;

	//! @brief A null-terminated string of the device type
	char m_deviceType[ 21u ];
};

struct PacketField_Data
{
	PacketField_Data_Type m_type;
	union 
	{
		PacketField_Data_V1 m_v1;
		PacketField_Data_V2 m_v2;
		PacketField_Data_FirmwareVersion m_firmwareVersion;
		PacketField_Data_DeviceType m_deviceType;
	} m_data;
};

struct PacketField
{
	PacketField_Header m_header;
	union 
	{
		PacketField_Flags m_flags;
		PacketField_Data m_data;
	} m_data;
};

//! @brief Decode bytes as a uint16_t using big endian
uint16_t DecodeUInt16_BigEndian
(
 	uint8_t const*& io_bytes
)
{
	uint16_t const value = ( (uint16_t) io_bytes[0u] << 8u )
		| ( (uint16_t) io_bytes[1u] );
	io_bytes += 2u;
	return value;
}

//! @brief Decode bytes as a uint32_t using big endian
uint32_t DecodeUInt32_BigEndian
(
 	uint8_t const*& io_bytes
)
{
	uint32_t const value = ( (uint32_t) io_bytes[0u] << 24u )
		| ( (uint32_t) io_bytes[1u] << 16u )
		| ( (uint32_t) io_bytes[2u] << 8u )
		| ( (uint32_t) io_bytes[3u] );
	io_bytes += 4u;
	return value;
}

//! @brief Decode 6 bytes as a uint64_t using big endian skipping the first two bytes
uint32_t DecodeX16UInt48_BigEndian
(
 	uint8_t const*& io_bytes
)
{
	uint64_t const value = ( (uint64_t) io_bytes[0u] << 40u )
		| ( (uint64_t) io_bytes[1u] << 32u )
		| ( (uint64_t) io_bytes[2u] << 24u )
		| ( (uint64_t) io_bytes[3u] << 16u )
		| ( (uint64_t) io_bytes[4u] << 8u )
		| ( (uint64_t) io_bytes[5u] );
	io_bytes += 6u;
	return value;
}

//! @brief Decode bytes as a float using big endian
float DecodeFloat_BigEndian
(
 	uint8_t const*& io_bytes
)
{
	uint32_t const data = DecodeUInt32_BigEndian( io_bytes );
	return *reinterpret_cast< float const* >( &data );
}

//! @brief Decode bytes as a int16_t using big endian
int16_t DecodeInt16_BigEndian
(
 	uint8_t const*& io_bytes
)
{
	uint16_t const data = DecodeUInt16_BigEndian( io_bytes );
	return *reinterpret_cast< uint16_t const* >( &data );
}

//! @brief Decode a set of bytes as a packet field structure
//! @param i_bytes The bytes to decode the packet field from
//! @param i_byteCount The amount of bytes to decode
size_t DecodePacketField
( 
 	uint8_t const* const i_bytes,
 	PacketField* io_field
)
{
	uint8_t const* curByte = i_bytes;

	PacketField field = {};
	field.m_header.m_sizeInBytes = *( curByte++ );

	// NOTE: The byte bit is included in the size of the payload
	field.m_header.m_type = (PacketFieldType) *( curByte++ );

	if( field.m_header.m_type == PacketFieldType::Flags )
	{
		assert( field.m_header.m_sizeInBytes == 0x02u );
		field.m_data.m_flags.m_flags = *( curByte++ );
		assert( field.m_data.m_flags.m_flags == 0x06u );
	}
	else if( field.m_header.m_type == PacketFieldType::Data )
	{
		if( *curByte == 0x4Bu )
		{
			assert( *( curByte++ ) == 0x4Bu );
			assert( *( curByte++ ) == 0x45u );
			assert( *( curByte++ ) == 0x47u );

			field.m_data.m_data.m_type = PacketField_Data_Type::FirmwareVersion;
			field.m_data.m_data.m_data.m_firmwareVersion.m_firmareVersionLength = field.m_header.m_sizeInBytes - 3u;

			assert( field.m_data.m_data.m_data.m_firmwareVersion.m_firmareVersionLength < 23u );
			memcpy( field.m_data.m_data.m_data.m_firmwareVersion.m_firmwareVersion, curByte, field.m_data.m_data.m_data.m_firmwareVersion.m_firmareVersionLength );

			curByte += field.m_data.m_data.m_data.m_firmwareVersion.m_firmareVersionLength;
		}
		else if( *curByte == 0x52u )
		{
			assert( *( curByte++ ) == 0x52u );
			assert( *( curByte++ ) == 0x41u );
			assert( *( curByte++ ) == 0x50u );
			assert( *( curByte++ ) == 0x54u );

			uint8_t const nextByte = *( curByte++ );
			if( nextByte == 0x64u )
			{
				field.m_data.m_data.m_type = PacketField_Data_Type::DeviceType;
				field.m_data.m_data.m_data.m_deviceType.m_deviceTypeLength = field.m_header.m_sizeInBytes - 3u;

				assert( field.m_data.m_data.m_data.m_deviceType.m_deviceTypeLength < 21u );
				memcpy( field.m_data.m_data.m_data.m_deviceType.m_deviceType, curByte, field.m_data.m_data.m_data.m_deviceType.m_deviceTypeLength );

				curByte += field.m_data.m_data.m_data.m_deviceType.m_deviceTypeLength;
			}
			else if( nextByte == 0x01u )
			{
				field.m_data.m_data.m_type = PacketField_Data_Type::V1;
				field.m_data.m_data.m_data.m_v1.m_macAddress = DecodeX16UInt48_BigEndian( curByte );
				field.m_data.m_data.m_data.m_v1.m_temperature = (DecodeUInt16_BigEndian( curByte )/ 128) - 273.15; 
				field.m_data.m_data.m_data.m_v1.m_specificGravity = DecodeFloat_BigEndian( curByte ); 
				field.m_data.m_data.m_data.m_v1.m_acceleromaterX = DecodeInt16_BigEndian( curByte ) / 16; 
				field.m_data.m_data.m_data.m_v1.m_acceleromaterY = DecodeInt16_BigEndian( curByte ) / 16; 
				field.m_data.m_data.m_data.m_v1.m_acceleromaterZ = DecodeInt16_BigEndian( curByte ) / 16; 
				field.m_data.m_data.m_data.m_v1.m_batteryCharge = DecodeUInt16_BigEndian( curByte ) / 256; 
			}
			else if( nextByte == 0x02u )
			{
				// Dummy byte that is part of the marker
				assert( *( curByte++ ) == 0x00 );

				field.m_data.m_data.m_type = PacketField_Data_Type::V2;
				field.m_data.m_data.m_data.m_v2.m_hasValidGravityData = *( curByte++ ) == 0x01u;
				field.m_data.m_data.m_data.m_v2.m_gravityVelocity = DecodeFloat_BigEndian( curByte ); 
                // Temp is kelvin * 128 so to get C we need to / 128 and subtract 273.15
				field.m_data.m_data.m_data.m_v2.m_temperature = (DecodeUInt16_BigEndian( curByte ) / 128) - 273.15; 
				field.m_data.m_data.m_data.m_v2.m_specificGravity = DecodeFloat_BigEndian( curByte ); 
				field.m_data.m_data.m_data.m_v2.m_acceleromaterX = DecodeInt16_BigEndian( curByte ) / 16; 
				field.m_data.m_data.m_data.m_v2.m_acceleromaterY = DecodeInt16_BigEndian( curByte ) / 16; 
				field.m_data.m_data.m_data.m_v2.m_acceleromaterZ = DecodeInt16_BigEndian( curByte ) / 16; 
				field.m_data.m_data.m_data.m_v2.m_batteryCharge = DecodeUInt16_BigEndian( curByte ) / 256; 
			}
		}
	}

	if( io_field )
	{
		(*io_field) = field;
	}
	return curByte - i_bytes; 
}

void PrintData(PacketField &data)
{
    if (data.m_data.m_data.m_type == PacketField_Data_Type::V1)
    {
        Serial.print("Version 1"); 
    }
    else{
        Serial.println("");
        Serial.println("Version 2"); 
        Serial.print("Temperature (c): ");
        Serial.println(data.m_data.m_data.m_data.m_v2.m_temperature);
        
        Serial.print("Battery Charge %: ");
        Serial.print(data.m_data.m_data.m_data.m_v2.m_batteryCharge);
        Serial.println("%");
        
        Serial.print("Acceleromater X: ");
        Serial.println(data.m_data.m_data.m_data.m_v2.m_acceleromaterX);
        Serial.print("Acceleromater Y: ");
        Serial.println(data.m_data.m_data.m_data.m_v2.m_acceleromaterY);
        Serial.print("Acceleromater Z: ");
        Serial.println(data.m_data.m_data.m_data.m_v2.m_acceleromaterZ);

        Serial.print("Specific Gravity: ");
        Serial.println(data.m_data.m_data.m_data.m_v2.m_specificGravity);

        Serial.print("Has Gravity Velocity:");
        Serial.println(data.m_data.m_data.m_data.m_v2.m_hasValidGravityData);
        Serial.print("Gravity Velocity:");
        Serial.println(data.m_data.m_data.m_data.m_v2.m_gravityVelocity);
    }

}


class MyAdvertisedDeviceCallbacks : public BLEAdvertisedDeviceCallbacks {
    void onResult(BLEAdvertisedDevice advertisedDevice) {
        // Serial.println(advertisedDevice.getAddress().toString().c_str());
        BLEAddress advertisedAddress = advertisedDevice.getAddress();
        bool found = false;
        for (const auto& targetAddress : targetAddresses) {
            if (advertisedAddress == targetAddress) {
                found = true;
                break;
            }
        }
        if (advertisedAddress == BLEAddress("78:e3:6d:29:19:16")) {
            // Get the payload
            const uint8_t* payload = advertisedDevice.getPayload();
            // Print the advertisement data (in hexadecimal format)
            uint8_t payloadLength = advertisedDevice.getPayloadLength();
            Serial.print("RSSI: ");
            Serial.print(advertisedDevice.getRSSI());
            Serial.println("");
            Serial.print("Payload Length: ");
            Serial.print(payloadLength);
            Serial.println();
            Serial.print("Raw Advertisement Data: ");
            for (int i = 0; i < payloadLength; i++) {
                Serial.print(payload[i], HEX);
                Serial.print(" ");
            }
            // Decode cc, gravity velocity, temperature, specific gravity, accelerometer data, and battery SOC
            // 0x52 0x41 0x50 0x54 0x02 0x00 cc vv vv vv vv tt tt gg gg gg gg xx xx yy yy zz zz bb bb
            //   0   1    2    3     4   5   6  7  8  9  10 11 12 13 14 15 16 17 18 19 20 21 22 23 24
            Serial.println();
            PacketField field = {};
            uint8_t const* bytes = payload;
            size_t bytesRemaining = payloadLength;
            while( bytesRemaining > 0u )
            {
                size_t const decodedByteCount = DecodePacketField( bytes, &field );
                // Serial.print("Decoded Byte Count: ");
                // Serial.println(decodedByteCount);
                // if( decodedByteCount > 0u )
                // {
                //     //Do something with decoded field
                //     PrintData(field);
                // }
                assert( decodedByteCount <= bytesRemaining );
                bytesRemaining -= decodedByteCount;
                bytes += decodedByteCount;
            }
            // Print the decoded data
            PrintData(field);
 

        }
        else {
            // Print that the device name doesn't match the target name or name is not available
            // Serial.print("Advertisement from a different device or name is not available: ");
            // Serial.println(advertisedDevice.getName().c_str());
        }
    }
};

void setup() {
    targetAddresses.push_back(BLEAddress("78:e3:6d:29:19:16"));

    Serial.begin(115200);
    Serial.println("Scanning...");

    BLEDevice::init("");

    BLEScan* pBLEScan = BLEDevice::getScan();
    
    pBLEScan->setAdvertisedDeviceCallbacks(new MyAdvertisedDeviceCallbacks());
    pBLEScan->setActiveScan(true);

    // BLEScanResults foundDevices = pBLEScan->start(0, false);

}

void loop() {
  Serial.println("Start of Loop");
  BLEDevice::getScan()->clearResults();
  // Continue scanning in the loop
  BLEScan* pBLEScan = BLEDevice::getScan();
  pBLEScan->setAdvertisedDeviceCallbacks(new MyAdvertisedDeviceCallbacks());
  pBLEScan->setActiveScan(true);
  pBLEScan->start(35, false);
  Serial.println("End of Loop");
  // delay(5000);

}
