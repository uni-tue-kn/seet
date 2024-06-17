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

#include "parser/tofino_parser.p4"

/***
    Ingress
***/
parser SwitchIngressParser(
    packet_in pkt,
    out header_t hdr,
    out ingress_metadata_t ig_md,
    out ingress_intrinsic_metadata_t ig_intr_md
) {
    TofinoIngressParser() tofino_parser;
    ParserCounter() drop_counter;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition select(ig_intr_md.ingress_port) {
            RECIRCULATION_PORT: parse_bridge_header_drop_front;
            RECIRCULATION_OUT_PORT: parse_bridge_header;
            default: parse_ethernet;
        }
    }

    state parse_bridge_header_drop_front {
        pkt.extract(hdr.bridge_header);
        transition parse_ethernet_and_slice_drop_front;
    }

    state parse_bridge_header {
        pkt.extract(hdr.bridge_header);
        transition parse_ethernet_and_slice;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHER_TYPE_SEET: parse_top_header;
            default: accept;
        }
    }

    state parse_top_header {
        pkt.extract(hdr.seet_protocol);
        pkt.extract(hdr.top_header);
        transition select(hdr.top_header.bitstring_indicator) {
            1: parse_bitstring;
            0: parse_active_segment;
        }
    }

    state parse_active_segment {
        pkt.extract(hdr.active_segment);
        transition accept;
    }

    state parse_bitstring {
        pkt.extract(hdr.bitstring);
        transition accept;
    }

    state parse_ethernet_and_slice {
        pkt.extract(hdr.ethernet);
        pkt.extract(hdr.seet_protocol);
        pkt.extract(hdr.top_header);

        transition select(hdr.bridge_header.keep_tens) {
	    14: parse_140;
	    13: parse_130;
            12: parse_120;
            11: parse_110;
            10: parse_100;
            9: parse_90;
            8: parse_80;
            7: parse_70;
            6: parse_60;
            5: parse_50;
            4: parse_40;
            3: parse_30;
            2: parse_20;
            1: parse_10;
            default: parse_units;
        }
    }

    state parse_140 {
	pkt.extract(hdr.data_100);
	pkt.extract(hdr.data_20.next);
	pkt.extract(hdr.data_20.next);
	transition parse_units;
    }
 
    state parse_130 {
	pkt.extract(hdr.data_100);
	pkt.extract(hdr.data_20.next);
	pkt.extract(hdr.data_10);
	transition parse_units;
    }

    state parse_120 {
        pkt.extract(hdr.data_100);
	pkt.extract(hdr.data_20.next);
        transition parse_units;
    }

    state parse_110 {
        pkt.extract(hdr.data_100);
	pkt.extract(hdr.data_10);
        transition parse_units;
    }

    state parse_100 {
        pkt.extract(hdr.data_100);
        transition parse_units;
    }

    state parse_90 {
        pkt.extract(hdr.data_50);
        pkt.extract(hdr.data_20.next);
        pkt.extract(hdr.data_20.next);
        transition parse_units;
    }
    state parse_80 {
        pkt.extract(hdr.data_50);
        pkt.extract(hdr.data_20.next);
        pkt.extract(hdr.data_10);
        transition parse_units;
    }
    state parse_70 {
        pkt.extract(hdr.data_50);
        pkt.extract(hdr.data_20.next);
        transition parse_units;
    }
    state parse_60 {
        pkt.extract(hdr.data_50);
        pkt.extract(hdr.data_10);
        transition parse_units;
    }
    state parse_50 {
        pkt.extract(hdr.data_50);
        transition parse_units;
    }
    state parse_40 {
        pkt.extract(hdr.data_20.next);
        pkt.extract(hdr.data_20.next);
        transition parse_units;
    }
    state parse_30 {
        pkt.extract(hdr.data_20.next);
        pkt.extract(hdr.data_10);
        transition parse_units;
    }
    state parse_20 {
        pkt.extract(hdr.data_20.next);
        transition parse_units;
    }
    state parse_10 {
        pkt.extract(hdr.data_10);
        transition parse_units;
    }

    state parse_units {
        transition select(hdr.bridge_header.keep_units) {
            9: parse_9;
            8: parse_8;
            7: parse_7;
            6: parse_6;
            5: parse_5;
            4: parse_4;
            3: parse_3;
            2: parse_2;
            1: parse_1;
            default: advance_bytes;
        }
    }

    state parse_9 {
        pkt.extract(hdr.data_5);
        pkt.extract(hdr.data_2.next);
        pkt.extract(hdr.data_2.next);
        transition advance_bytes;
    }
    state parse_8 {
        pkt.extract(hdr.data_5);
        pkt.extract(hdr.data_2.next);
        pkt.extract(hdr.data);
        transition advance_bytes;
    }
    state parse_7 {
        pkt.extract(hdr.data_5);
        pkt.extract(hdr.data_2.next);
        transition advance_bytes;
    }
    state parse_6 {
        pkt.extract(hdr.data_5);
        pkt.extract(hdr.data);
        transition advance_bytes;
    }
    state parse_5 {
        pkt.extract(hdr.data_5);
        transition advance_bytes;
    }
    state parse_4 {
        pkt.extract(hdr.data_2.next);
        pkt.extract(hdr.data_2.next);
        transition advance_bytes;
    }
    state parse_3 {
        pkt.extract(hdr.data_2.next);
        pkt.extract(hdr.data);
        transition advance_bytes;
    }
    state parse_2 {
        pkt.extract(hdr.data_2.next);
        transition advance_bytes;
    }
    state parse_1 {
        pkt.extract(hdr.data);
        transition advance_bytes;
    }

    state advance_bytes {
        drop_counter.set(hdr.bridge_header.drop_bytes);
        transition select(drop_counter.is_zero()) {
            true: accept;
            false: advance_byte;
        }
    }

    state advance_byte {
        pkt.advance(8);
        drop_counter.decrement(1);
        transition select(drop_counter.is_zero()) {
            true: accept;
            false: advance_byte;
        }
    }

    state parse_ethernet_and_slice_drop_front {
        pkt.extract(hdr.ethernet);
        pkt.extract(hdr.seet_protocol);
        pkt.extract(hdr.top_header);

        transition advance_bytes_drop_front;
    }

    state advance_bytes_drop_front {
        drop_counter.set(hdr.bridge_header.drop_bytes);
        transition select(drop_counter.is_zero()) {
            true: parse_active_segment;
            false: advance_byte_drop_front;
        }
    }

    state advance_byte_drop_front {
        pkt.advance(8);
        drop_counter.decrement(1);
        transition select(drop_counter.is_zero()) {
            true: parse_active_segment;
            false: advance_byte_drop_front;
        }
    }

}

control SwitchIngressDeparser(
    packet_out pkt,
    inout header_t hdr,
    in ingress_metadata_t ig_md,
    in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md
) {

    apply {
        pkt.emit(hdr.bridge_header);
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.seet_protocol);
        pkt.emit(hdr.top_header);
        pkt.emit(hdr.active_segment);
        pkt.emit(hdr.bitstring);
        pkt.emit(hdr.data_100);
        pkt.emit(hdr.data_50);
        pkt.emit(hdr.data_20);
        pkt.emit(hdr.data_10);
        pkt.emit(hdr.data_5);
        pkt.emit(hdr.data_2);
        pkt.emit(hdr.data);
    }
}

/***
    Egress
***/
parser SwitchEgressParser(
    packet_in pkt,
    out header_t hdr,
    out egress_metadata_t eg_md,
    out egress_intrinsic_metadata_t eg_intr_md
) {
    TofinoEgressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, eg_intr_md);
        transition parse_bridge_header;
    }

    state parse_bridge_header {
        pkt.extract(hdr.bridge_header);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHER_TYPE_SEET: parse_top_header;
            default: accept;
        }
    }

    state parse_top_header {
        pkt.extract(hdr.seet_protocol);
        pkt.extract(hdr.top_header);
        pkt.extract(hdr.active_segment);
        transition accept;
    }

}

control SwitchEgressDeparser(
    packet_out pkt,
    inout header_t hdr,
    in egress_metadata_t eg_md,
    in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md
) {
    apply {
        pkt.emit(hdr.bridge_header);
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.seet_protocol);
        pkt.emit(hdr.top_header);
        pkt.emit(hdr.active_segment);
    }
}
