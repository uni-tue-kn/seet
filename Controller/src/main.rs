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
 */

use log::{info, warn};
use rbfrt::{SwitchConnection, table};
use rbfrt::table::{MatchValue, Request};
use rbfrt::util::port_manager::{AutoNegotiation, FEC, Loopback, Port, Speed};
use rbfrt::util::PortManager;
use rbfrt::error::RBFRTError;

const CPU_PORT: u16 = 192;

const SEET_GLOBAL_TABLE: &str = "ingress.seet_global";
const SEET_EXACT_TABLE: &str = "ingress.seet_logic";

const SEET_LENGTH_TABLE: &str = "ingress.length_to_bridge_header";

const BIER_MULTICAST_TABLE: &str = "ingress.bier_multicast";

/// Table for multicast groups
const MULTICAST_TABLE: &str = "$pre.mgid";

/// Table for multicast nodes
const MULTICAST_NODE_TABLE: &str = "$pre.node";

/// Creates a simple multicast group.
///
/// # Arguments
///
/// * `switch`: Switch connection.
/// * `mid`: Multicast group identifier.
/// This is used as identifier in the data plane.
/// * `ports`: List of dev ports for the multicast group
pub async fn create_simple_multicast_group(switch: &SwitchConnection,
                                           mid: u16,
                                           ports: &Vec<u32>) -> Result<(), RBFRTError> {
    // create node id
    let req = table::Request::new("$pre.node")
        .match_key("$MULTICAST_NODE_ID", MatchValue::exact(mid))
        .action_data("$MULTICAST_RID", 1)
        .action_data_repeated("$MULTICAST_LAG_ID", vec![0])
        .action_data_repeated("$DEV_PORT", ports.to_vec());

    switch.write_table_entry(req).await?;

    let req = table::Request::new("$pre.mgid")
        .match_key("$MGID", MatchValue::exact(mid))
        .action_data_repeated("$MULTICAST_NODE_ID", vec![mid])
        .action_data_repeated("$MULTICAST_NODE_L1_XID_VALID", vec![false])
        .action_data_repeated("$MULTICAST_NODE_L1_XID", vec![0]);

    switch.write_table_entry(req).await?;

    Ok(())
}

/// Deletes a simple multicast group.
///
/// # Arguments
///
/// * `switch`: Switch connection.
/// * `mid`: Multicast group identifier.
/// This is used as identifier in the data plane.
pub async fn delete_simple_multicast_group(switch: &SwitchConnection,
                                           mid: u16) -> Result<(), RBFRTError> {
    let req = table::Request::new(MULTICAST_TABLE)
        .match_key("$MGID", MatchValue::exact(mid));

    let _ = switch.delete_table_entry(req).await;

    let req = table::Request::new(MULTICAST_NODE_TABLE)
        .match_key("$MULTICAST_NODE_ID", MatchValue::exact(mid));

    let _ = switch.delete_table_entry(req).await;

    Ok(())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting controller...");

    let mut switch = SwitchConnection::new("localhost", 50052)
        .device_id(0)
        .client_id(1)
        .p4_name("seet")
        .connect()
        .await?;

    let pm = PortManager::new(&mut switch).await;

    let port_requests = vec![
        Port::new(7, 0)
            .speed(Speed::BF_SPEED_100G)
            .fec(FEC::BF_FEC_TYP_NONE)
            .auto_negotiation(AutoNegotiation::PM_AN_DEFAULT),
        Port::new(15, 0)
            .speed(Speed::BF_SPEED_100G)
            .fec(FEC::BF_FEC_TYP_NONE)
            .auto_negotiation(AutoNegotiation::PM_AN_DEFAULT)
            .loopback(Loopback::BF_LPBK_MAC_NEAR),
        Port::new(16, 0)
            .speed(Speed::BF_SPEED_100G)
            .fec(FEC::BF_FEC_TYP_NONE)
            .auto_negotiation(AutoNegotiation::PM_AN_DEFAULT)
            .loopback(Loopback::BF_LPBK_MAC_NEAR),
        Port::new(17, 0)
            .speed(Speed::BF_SPEED_100G)
            .fec(FEC::BF_FEC_TYP_NONE)
            .auto_negotiation(AutoNegotiation::PM_AN_DEFAULT)
            .loopback(Loopback::BF_LPBK_MAC_NEAR),
    ];

    pm.add_ports(&mut switch, &port_requests).await?;

    info!("Ports configured.");

    let _ = switch.clear_tables(vec![SEET_GLOBAL_TABLE, SEET_EXACT_TABLE, SEET_LENGTH_TABLE, BIER_MULTICAST_TABLE]).await?;

    let _ = delete_simple_multicast_group(&switch, 1024).await;
    let _ = delete_simple_multicast_group(&switch, 1).await;

    // create multicast group
    create_simple_multicast_group(&switch, 1024, &vec![pm.dev_port(16, 0)?]).await?;
    create_simple_multicast_group(&switch, 1, &vec![CPU_PORT as u32]).await?;

    //
    let entry = Request::new(SEET_EXACT_TABLE)
        .match_key("hdr.active_segment.identifier", MatchValue::exact(2))
        .action("ingress.seet_forward")
        .action_data("port", CPU_PORT);

    switch.write_table_entry(entry).await?;

    let entry = Request::new(SEET_EXACT_TABLE)
        .match_key("hdr.active_segment.identifier", MatchValue::exact(10))
        .action("ingress.seet_forward")
        .action_data("port", pm.dev_port(17, 0)?);

    switch.write_table_entry(entry).await?;

    let mut entries = vec![];

    for i in 1u8..150 {
        let tens = (i+3) / 10;
        let units = (i+3) % 10;

        entries.push(Request::new(SEET_LENGTH_TABLE)
            .match_key("ig_md.active_segment_length", MatchValue::exact(i))
            .action("ingress.set_bridge_header")
            .action_data("tens", tens)
            .action_data("units", units));
    }

    switch.write_table_entries(entries).await?;

    let entry = Request::new(BIER_MULTICAST_TABLE)
        .match_key("hdr.bitstring.bs", MatchValue::exact(1))
        .match_key("hdr.top_header.length", MatchValue::exact(17))
        .action("ingress.do_bier_multicast")
        .action_data("mcid", 1);

    switch.write_table_entry(entry).await?;


    Ok(())
}

#[tokio::main]
async fn main() -> () {
    env_logger::init();

    match run().await {
        Ok(_) => {}
        Err(e) => {
            warn!("Error: {}", e);
        }
    }
}