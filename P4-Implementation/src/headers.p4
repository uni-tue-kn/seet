/* Copyright 2024-present University of Tuebingen, Chair of Communication Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Steffen Lindner (steffen.lindner@uni-tuebingen.de)
 * Maximilian Bertsch (max.bertsch@gmx.de)
 */
#ifndef _HEADERS_
#define _HEADERS_

/***
     Constants 
***/

/***
Activate Global address modus
***/
//#define GLOBAL_ADDRESSES


const PortId_t CPU_PORT = 192;

const PortId_t RECIRCULATION_PORT = 4;
const PortId_t RECIRCULATION_OUT_PORT = 12;


//Ether types
const bit<16> ETHER_TYPE_SEET = 0x900;


//Type Definitions
typedef bit<48> MACAddr_t;
typedef bit<16> EtherType_t;

typedef bit<14> SEETAddr_t;


/***
    Headers
***/

header ethernet_h {
    MACAddr_t dst_addr;
    MACAddr_t src_addr;
    EtherType_t ether_type;
}

header bytes_100_h {
    bit<(100*8)> data;
}

header bytes_50_h {
    bit<(50*8)> data;
}

header bytes_20_h {
    bit<(20*8)> data;
}

header bytes_10_h {
    bit<(10*8)> data;
}

header bytes_5_h {
    bit<(5*8)> data;
}

header bytes_2_h {
    bit<(2*8)> data;
}

header bytes_h {
    bit<8> data;
}

header seet_protocol_h {
    EtherType_t next_protocol;
}

header top_header_h {
    SEETAddr_t  identifier;
    bit<1> deliver_bit;
    bit<1> bitstring_indicator;
    bit<8> length;
}

header bitstring_h {
    bit<8> bs;
}

header bridge_header_h {
    bit<4> keep_tens;
    bit<4> keep_units;
    bit<8> drop_bytes;
    PortId_t out_port;
    bit<7> padding;
}

header mirror_header_h {
    bit<8> remove_byte;
}

/***
    Metadata structs
***/

struct ingress_metadata_t {
    bool checksum_err;
    bit<10> mirror_session;
    bit<8> active_segment_length;
}

struct egress_metadata_t {
    bit<8> active_segment_length;
}

/***
    Header struct
***/

struct header_t {
    ethernet_h ethernet;
    seet_protocol_h seet_protocol;
    top_header_h top_header;
    top_header_h active_segment;
    bitstring_h bitstring;
    bridge_header_h bridge_header;
    bytes_100_h data_100;
    bytes_50_h data_50;
    bytes_20_h[2] data_20;
    bytes_10_h data_10;
    bytes_5_h data_5;
    bytes_2_h[2] data_2;
    bytes_h data;

}

#endif