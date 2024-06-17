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
control egress (
    /*user*/
    inout header_t hdr,
    inout egress_metadata_t eg_md,
    /*intrinsic*/
    in egress_intrinsic_metadata_t eg_intr_md, 
    in egress_intrinsic_metadata_from_parser_t eg_intr_from_prsr,
    inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
    inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport
) {

    apply {
        if(eg_intr_md.egress_port == RECIRCULATION_PORT) { // adjust bridge header and top header for packet that keeps recirculating to process all segments

            if(hdr.active_segment.bitstring_indicator == 1) {
                eg_md.active_segment_length = (bit<8>) hdr.active_segment.length[7:4];
            }
            else {
                eg_md.active_segment_length = hdr.active_segment.length;
            }

            hdr.top_header.length = hdr.top_header.length - eg_md.active_segment_length;

            hdr.top_header.length = hdr.top_header.length - 3;
            hdr.bridge_header.keep_tens = 0;
            hdr.bridge_header.keep_units = 0;
            hdr.bridge_header.drop_bytes = eg_md.active_segment_length;
            hdr.bridge_header.drop_bytes = hdr.bridge_header.drop_bytes + 3;
        }
    }
}