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
control ingress(
    /*user*/
    inout header_t hdr,
    inout ingress_metadata_t ig_md,
    /*intrinsic*/
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md
) {

    action forward(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    table seet_global {
        key = {
            hdr.top_header.identifier: exact;
        }
        actions = {
            forward;
        }
        size = 128;
    }

    action seet_forward(PortId_t port) {
        hdr.bridge_header.setValid();
        hdr.bridge_header.out_port = port;
        ig_tm_md.ucast_egress_port = RECIRCULATION_OUT_PORT;
        ig_tm_md.mcast_grp_a = 1024; // special multicast group that clones the packet to RECIRCULATION_PORT
    }

    table seet_logic {
        key = {
            hdr.active_segment.identifier: exact;
        }
        actions = {
            seet_forward;
        }
        size = 128;
    }

    action set_bridge_header(bit < 4 > tens, bit < 4 > units) {
        hdr.bridge_header.setValid();
        hdr.bridge_header.keep_tens = tens;
        hdr.bridge_header.keep_units = units;
        hdr.bridge_header.drop_bytes = hdr.top_header.length;
    }

    table length_to_bridge_header {
        key = {
            ig_md.active_segment_length: exact;
        }
        actions = {
            set_bridge_header;
        }
        size = 256;
    }

    action do_bier_multicast(bit < 16 > mcid) {
        ig_tm_md.mcast_grp_a = mcid;
    }

    table bier_multicast {
        key = {
            hdr.bitstring.bs: exact;
            hdr.top_header.length: exact;
        }
        actions = {
            do_bier_multicast;
        }
        size = 256;
    }

    apply {
        // we processed all segments or have a BIER-like bitstring
        if (hdr.top_header.length == 0 || hdr.bitstring.isValid()) {
            // check for deliver bit
            if (hdr.top_header.deliver_bit == 1) {
                hdr.ethernet.ether_type = hdr.seet_protocol.next_protocol;
                hdr.top_header.setInvalid();
                ig_tm_md.ucast_egress_port = CPU_PORT; // pass packet to CPU for further processing
                hdr.bridge_header.setInvalid();
            }

            // bitstring indicator has been set
            // we are at the penultimate hop
            // do BIER-like forwarding with bitstring
            if (bier_multicast.apply().hit) { // we apply a "cheap" BIER using an exact match on the bitstring
                hdr.ethernet.ether_type = hdr.seet_protocol.next_protocol;
                hdr.seet_protocol.setInvalid();
                hdr.top_header.setInvalid();
                hdr.bridge_header.setInvalid();
                hdr.active_segment.setInvalid();
                hdr.bitstring.setInvalid();
            }

            if(hdr.top_header.deliver_bit == 1) {
                hdr.seet_protocol.setInvalid(); // deactivate protocol header here, so that it can still be used in the BIER case
            }
        } else if (seet_global.apply().miss) { // check if we do global SEET forwarding
            if (ig_intr_md.ingress_port == RECIRCULATION_OUT_PORT) { // we are on the recirculation port that is used to send the packet to the next neighbor
                ig_tm_md.ucast_egress_port = hdr.bridge_header.out_port;
                hdr.bridge_header.setInvalid();
                hdr.top_header.setInvalid();
            } else {
                if (seet_logic.apply().hit) { // check what to do for next segment
                    if (hdr.active_segment.bitstring_indicator == 1) {  // if it has an bitstring indicator, the length is encoded in the first leftmost 4 bit
                        ig_md.active_segment_length = (bit<8>) hdr.active_segment.length[7:4];
                    }
                    else {
                        ig_md.active_segment_length = hdr.active_segment.length;
                    }

                    if(length_to_bridge_header.apply().hit) {
                        hdr.bridge_header.drop_bytes = hdr.bridge_header.drop_bytes - ig_md.active_segment_length;
                        hdr.bridge_header.drop_bytes = hdr.bridge_header.drop_bytes - 3;
                    }
                }
            }
        }
    }
}