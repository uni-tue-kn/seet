use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::{fs, vec};
use std::time::{Duration, Instant, SystemTime};
use petgraph::{Graph, Undirected};
use petgraph::algo::{bellman_ford};
use petgraph::graph::{NodeIndex, UnGraph};
use petgraph::visit::{Bfs, Dfs, IntoEdges, IntoNeighbors, NodeCount};
use rand::prelude::{IteratorRandom, StdRng};
use rand::{RngCore, SeedableRng};
use rand::distributions::{Distribution, WeightedIndex};
use serde_json::Value;
use rayon::prelude::*;
use rand::prelude::SliceRandom;

//Represents the semantics of recursive headers, not the bit layout.
#[derive(Clone, Debug)]
struct Header {
    destination: NodeIndex, //next destination of a header
    next_header: Vec<Header>, //sub headers in SEET style
    rbs_record: HashSet<NodeIndex>, //nodes that are reached through an RBS header starting from destination
    leaves: Vec<NodeIndex>, //all destinations addressed by the header including subheaders
    header_size: u64, //current header size in bytes (only SEET+RBS fields)
    hops: u64, //hops in the forwarding tree including forwarding of subheaders
    broadcast: bool,
    rbs_length: u8,
    pre_index: usize,
}

impl Display for Header {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} B:{:?} [{}]",
               self.destination,
               self.rbs_record,
               self.next_header.iter().fold(
                   "".to_string(),
                   |mut res, s| {
                       res.push_str(&s.to_string());
                       res.push(',');
                       res
                   }
               )
        )
    }
}


struct BitstringConfiguration {
    leave_subsets: Vec<Vec<HashSet<NodeIndex>>>,
}

type BitstringConfigurations = HashMap<NodeIndex, BitstringConfiguration>;

impl BitstringConfiguration {
    fn new(neighbors: Vec<NodeIndex>, max_length: u8) -> BitstringConfiguration {
        let mut leave_subsets = Vec::with_capacity(max_length as usize);
        leave_subsets.push(vec![HashSet::new()]);

        for l in 1 ..= max_length as u32 {
            let mut subsets = Vec::with_capacity(16);
            let mut start_index = 0usize;
            let size = (l*8) as usize;
            for _i in 0 .. 16 {
                let mut receivers = HashSet::with_capacity(8*l as usize);
                for j in start_index .. (start_index + size).min(neighbors.len()) {
                    receivers.insert(neighbors[j]);
                }
                start_index += size;
                subsets.push(receivers);
                if start_index >= neighbors.len() {
                    break;
                }

            }
            leave_subsets.push(subsets);

            if l*8 > neighbors.len() as u32 {
                break;
            }
        }



        BitstringConfiguration {
            leave_subsets
        }
    }

    fn find_optimal_length(&self, destinations: &HashSet<NodeIndex>, min_length: u8, new_dest: NodeIndex, pre_index: usize) -> Option<(u8, usize)> {
        //if self.leave_subsets[min_length as usize][pre_index].contains(&new_dest) {
        //    return Some((min_length, pre_index))
        //}

        for l in min_length .. self.leave_subsets.len() as u8 {
            for i in 0 .. self.leave_subsets[l as usize].len() {
                let subset = &self.leave_subsets[l as usize][i];
                if destinations.is_subset(subset) {
                    return Some((l, i))
                }
            }
        }


        None
    }
}




//Represents the packet layout, i.e., the length of the SEET and RBS fields.
struct PacketFormat {
    bitstring_length_field: u32, //number of bits used to indicate the length of the bitstring in RBS
    additional_seet_bits: u32, //deliver bit, broadcast bit, whatever Chef comes up with next
    seet_length_field: u32, //seet length field in bits
    identifier_bits: u32, //number of bits used for identifier in SEET
    padding_bits: u32, //padding bits in SEET header
    payload: u64, //bytes
    additional_header: u64 //IP header, Ethernet header, whatever in bytes
}

impl PacketFormat {
    //Constructs a packet format struct by computing the padding bits and the length of the SEET identifier.
    fn new(num_nodes: usize, additional_seet_bits: u32, bitstring_length_field: u32, payload: u64, additional_header: u64) -> PacketFormat {
        let identifier_bits = if num_nodes.is_power_of_two() {
            (num_nodes as f64).log2() as u32
        } else {
            (num_nodes as f64).log2() as u32 + 1
        };

        let padding_bits = if (additional_seet_bits + identifier_bits) % 8 == 0 {
            0
        } else {
            8 - ((additional_seet_bits + identifier_bits) % 8)
        };

        PacketFormat {
            bitstring_length_field,
            additional_seet_bits,
            seet_length_field: 8,
            identifier_bits,
            padding_bits,
            payload,
            additional_header,
        }
    }
}


impl Header {

    //Recursively computes the overall traffic of a message, including payload and other headers.
    fn eval_header_traffic(&self, pf: &PacketFormat, paths: &mut GraphPaths) -> u64 {
        let path = paths.path(self.destination);
        let hops = path.len()-1;
        let mut header_bytes = (pf.additional_seet_bits + pf.identifier_bits + pf.padding_bits + pf.seet_length_field) / 8;
        if self.rbs_length > 0 {
            header_bytes += self.rbs_length as u32 +1;
        }
        let recursive_header_bytes = self.next_header.iter().fold(0, |sum, s| sum + s.eval_header_traffic(pf, paths));

        (hops * header_bytes as usize) as u64 + recursive_header_bytes
    }


    //Base case header, i.e., one SEET header to the destination.
    fn new_base_case(destination: NodeIndex, pf: &PacketFormat, paths: &mut GraphPaths, bitstring_configurations: &BitstringConfigurations) -> Header {
        let header_bytes = ((pf.additional_seet_bits + pf.identifier_bits + pf.identifier_bits + pf.padding_bits) / 8) as u64;

        let penultimate = paths.penultimate_hop(destination).unwrap();
        let mut rbs = HashSet::with_capacity(paths.num_neighbors(penultimate) as usize);
        rbs.insert(destination);


        let (size, index) = bitstring_configurations[&penultimate].find_optimal_length(&rbs, 0, destination, 0).unwrap();


        Header {
            destination: penultimate,
            next_header: vec![],
            rbs_record: rbs,
            leaves: vec![destination],
            header_size: header_bytes + size as u64,
            hops: (paths.path(destination).len() - 1) as u64,
            broadcast: false,
            rbs_length: size,
            pre_index: index,
        }
    }



    //Adds a destination recursively to a header.
    //Returns the additional header size and the additional hops that result from the new destination.
    fn add_destination(&mut self, destination: NodeIndex, paths: &mut GraphPaths, pf: &PacketFormat, bitstring_configurations: &BitstringConfigurations) -> (u64, i64) {
        self.leaves.push(destination);
        if destination == self.destination {
            return (0,0)
        }

        let replication_node = paths.replication_node(destination, self.destination);
        if replication_node == self.destination {
            for child in &mut self.next_header {
                let rn = paths.replication_node(destination, child.destination);

                if rn != self.destination {
                    let growth = child.add_destination(destination, paths, pf, bitstring_configurations);
                    self.header_size = (self.header_size as i64 + growth.1) as u64;
                    self.hops += growth.0;
                    return growth;
                }
            }

            match paths.penultimate_hop(destination) {
                None => {return (0, 0)}
                Some(penultimate_hop) => {
                    if self.destination == penultimate_hop {
                        self.rbs_record.insert(destination);
                        self.hops += 1;

                        let config = &bitstring_configurations[&self.destination];
                        return match config.find_optimal_length(&self.rbs_record, self.rbs_length, destination, self.pre_index) {
                            None => {

                                self.header_size += 10000000;
                                (1, 10000000)
                            }
                            Some((size, index)) => {
                                let mut additional_header = if self.rbs_record.len() == 1 {
                                    1
                                } else {
                                    0
                                };

                                additional_header += size - self.rbs_length;
                                self.rbs_length = size;
                                self.pre_index = index;
                                self.header_size += additional_header as u64;
                                (1, additional_header as i64)

                            }
                        }


                    } else {
                        let new_header = Header {
                            destination,
                            next_header: vec![],
                            rbs_record: HashSet::with_capacity(paths.num_neighbors(destination) as usize),
                            leaves: vec![],
                            header_size: 0,
                            hops: 0,
                            broadcast: false,
                            rbs_length: 0,
                            pre_index: 0,
                        };
                        self.next_header.push(new_header);
                        self.header_size += ((pf.padding_bits + pf.additional_seet_bits + pf.seet_length_field + pf.identifier_bits) / 8) as u64;
                        self.hops += (paths.distances[destination.index()] - paths.distances[replication_node.index()]) as u64;

                        return ((paths.distances[destination.index()] - paths.distances[replication_node.index()]) as u64, ((pf.padding_bits + pf.additional_seet_bits + pf.seet_length_field + pf.identifier_bits) / 8) as i64);
                    }

                }
            }

        } else {
            let penultimate1 = paths.penultimate_hop(self.destination).unwrap();
            let penultimate2 = paths.penultimate_hop(destination).unwrap();

            if penultimate1 == penultimate2 && self.next_header.is_empty() {
                self.rbs_record.insert(destination);
                self.rbs_record.insert(self.destination);
                self.destination = penultimate1;
                self.hops += 1;

                let config = &bitstring_configurations[&self.destination];
                return match config.find_optimal_length(&self.rbs_record, self.rbs_length, destination, self.pre_index) {
                    None => {

                        self.header_size += 10000000;
                        (1, 10000000)
                    }
                    Some((size, index)) => {
                        let mut additional_header = if self.rbs_record.len() == 1 {
                            1
                        } else {
                            0
                        };

                        additional_header += size - self.rbs_length;
                        self.pre_index = index;
                        self.rbs_length = size;
                        self.header_size += additional_header as u64;
                        (1, additional_header as i64)

                    }
                }

            } else {
                self.split_at_replication_node(replication_node, destination);
                self.header_size += 2*((pf.padding_bits + pf.additional_seet_bits + pf.seet_length_field + pf.identifier_bits) / 8) as u64;
                self.hops += (paths.distances[destination.index()] - paths.distances[replication_node.index()]) as u64;
                return ((paths.distances[destination.index()] - paths.distances[replication_node.index()]) as u64, 2*((pf.padding_bits + pf.additional_seet_bits + pf.seet_length_field + pf.identifier_bits) / 8) as i64);

            }




        }

    }

    fn split_at_replication_node(&mut self, replication_node: NodeIndex, destination: NodeIndex) {
        let mut new_header = Header {
            destination: self.destination,
            next_header: vec![],
            rbs_record: HashSet::with_capacity(16),
            leaves: vec![],
            header_size: 0,
            hops: 0,
            broadcast: false,
            rbs_length: 0,
            pre_index: 0,
        };
        new_header.next_header.append(&mut self.next_header);
        new_header.rbs_record.extend(self.rbs_record.iter());
        self.rbs_record.clear();
        let new_header_dest = Header {
            destination,
            next_header: vec![],
            rbs_record: HashSet::with_capacity(16),
            leaves: vec![],
            header_size: 0,
            hops: 0,
            broadcast: false,
            rbs_length: 0,
            pre_index: 0,
        };

        self.next_header.push(new_header);
        self.next_header.push(new_header_dest);
        self.destination = replication_node;
    }
}

//Returns bitstring length for a given Bitstring ID. Length is byte aligned.
fn bid_to_bitstring_length(num_neighbors: u32, bid: u8) -> u32 {
    let quarter_len = if num_neighbors % 4 == 0 {
        num_neighbors / 4
    } else {
        num_neighbors / 4 + 1
    };
    let len = bid.count_ones() * quarter_len;
    if len % 8 == 0 {
        len / 8
    } else {
        len / 8 + 1
    }
}


fn bitstring_configs(graph: &Graph<(), f64, Undirected>) -> BitstringConfigurations {
    let mut bitstring_configs = HashMap::with_capacity(graph.node_count());
    for node in graph.node_indices() {
        let mut neighbors = graph.neighbors(node).collect::<Vec<_>>();
        neighbors.sort_by(|n1, n2| n1.index().cmp(&n2.index()));
        let bitstring_config = BitstringConfiguration::new(neighbors, 16);
        bitstring_configs.insert(node, bitstring_config);
    }

    bitstring_configs
}


//Abstracts away shortest path algorithm.
//Paths are computed lazily, i.e., only when a path is requested for the first time and paths are cached for future requests.
//Some topologies such as Torus may benefit from Floyd-Warshall instead of Bellman-Ford.
struct GraphPaths<'a> {
    source: NodeIndex,
    graph: &'a Graph<(), f64, Undirected>,
    paths: HashMap<NodeIndex, Vec<NodeIndex>>,
    predecessors: Vec<Option<NodeIndex>>,
    distances: Vec<f64>,
}

impl<'a> GraphPaths<'a> {
    fn new(source: NodeIndex, graph: &Graph<(), f64, Undirected>) -> GraphPaths {
        let shortest_paths = bellman_ford(&graph, source).unwrap();
        let predecessors = shortest_paths.predecessors;
        let distances = shortest_paths.distances;
        let mut paths = HashMap::with_capacity(graph.node_count());



        GraphPaths {
            source,
            graph,
            paths,
            predecessors,
            distances,
        }
    }

    //Computes path as node.
    fn compute_path(graph: &Graph<(), f64, Undirected>, predecessors: &Vec<Option<NodeIndex>>, source: NodeIndex, destination: NodeIndex) -> Vec<NodeIndex> {
        let mut current = destination;
        let mut path = Vec::with_capacity(10);
        while current != source {
            path.push(current);
            current = predecessors[current.index()].unwrap();
        }
        path.push(source);

        path.reverse();
        path
    }

    //Returns path as node list.
    fn path(&mut self, destination: NodeIndex) -> &Vec<NodeIndex> {
        if !self.paths.contains_key(&destination) {
            self.paths.insert(destination, GraphPaths::compute_path(self.graph, &self.predecessors, self.source, destination));
        }
        &self.paths[&destination]
    }

    //Returns the node where paths to d1 and d2 diverge.
    fn replication_node(&mut self, d1: NodeIndex, d2: NodeIndex) -> NodeIndex {
        if !self.paths.contains_key(&d1) {
            self.paths.insert(d1, GraphPaths::compute_path(self.graph, &self.predecessors, self.source, d1));
        }
        if !self.paths.contains_key(&d2) {
            self.paths.insert(d2, GraphPaths::compute_path(self.graph, &self.predecessors, self.source, d2));
        }
        let p1 = &self.paths[&d1];
        let p2 = &self.paths[&d2];

        let shorter_path = if p1.len() < p2.len() {
            &p1
        } else {
            &p2
        };
        let longer_path = if p1.len() < p2.len() {
            &p2
        } else {
            &p1
        };
        for (index, node) in shorter_path.iter().enumerate() {
            if longer_path[index] != *node {
                return longer_path[index-1]
            }
        }

        *shorter_path.last().unwrap()
    }

    //Returns the penultimate hop of some node relative to the shortest path from self.source.
    fn penultimate_hop(&mut self, destination: NodeIndex) -> Option<NodeIndex> {
        if self.source == destination {
            None
        } else {
            let path = self.path(destination);
            Some(path[path.len()-2])
        }
    }

    //Returns the number of neighbors of some node. Used for RBS bitstring length.
    fn num_neighbors(&self, node: NodeIndex) -> u32 {
        self.graph.neighbors(node).count() as u32
    }

    fn neighbor_bid(&self, node: NodeIndex, neighbor: NodeIndex) -> u8 {
        let mut neighbors = self.graph.neighbors(node).collect::<Vec<_>>();
        neighbors.sort_by(|n1, n2| n1.index().cmp(&n2.index()));
        let pos = neighbors.iter().position(|n| *n == neighbor).unwrap();
        if pos < neighbors.len()/2 {
            if pos < neighbors.len()/4 {
                1
            } else {
                2
            }
        } else {
            if pos < 3*neighbors.len()/4 {
                4
            } else {
                8
            }
        }
    }


    //Returns the number of neighbors of some node that are leaves, i.e, have node degree 1.
    fn num_leave_neighbors(&self, node: NodeIndex) -> u32 {
        let mut num = 0;
        self.graph.neighbors(node).for_each(|n| if self.graph.edges(n).count() == 1 {num += 1;} else {});
        num
    }

    fn neighbors(&self, node: NodeIndex) -> Vec<NodeIndex> {
        self.graph.neighbors(node).collect::<Vec<_>>()
    }
}


//Computes the traffic including header and payload to reach all destinations with IP unicast.
fn traffic_unicast(destinations: &Vec<NodeIndex>, pf: &PacketFormat, paths: &mut GraphPaths) -> EvalResult {
    let mut traffic = 0;
    let mut hops = 0;
    for d in destinations.iter().copied() {
        let path = paths.path(d);
        traffic += (path.len()-1) as u64 * (pf.payload+pf.additional_header);
        hops += (path.len()-1) as u64;
    }
    let num_destinations = if destinations.contains(&paths.source) {
        destinations.len()-1
    } else {
        destinations.len()
    } as f64;

    let mc_traffic = traffic_multicast(destinations, pf, paths);

    EvalResult {
        overall_traffic: traffic as f64,
        pkts: hops as f64,
        source_traffic: (pf.payload+pf.additional_header) as f64 * destinations.len() as f64,
        pkts_from_source: num_destinations,
        additional_packets: hops as f64 - mc_traffic.pkts,
        denseness: 0.0,
    }
}

//Computes the traffic including header and payload to reach all destinations with IPMC.
fn traffic_multicast(destinations: &Vec<NodeIndex>, pf: &PacketFormat, paths: &mut GraphPaths) -> EvalResult {
    let mut edges = HashSet::with_capacity(destinations.len());

    let mut source_pkts = 0;
    for d in destinations.iter().copied() {
        let path = paths.path(d);
        for i in 1 .. path.len() {
            if i == 1 && !edges.contains(&(path[i-1], path[i])) {
                source_pkts += 1;
            }
            edges.insert((path[i-1], path[i]));
        }
    }
    let overall_traffic = edges.len() as u64 * (pf.payload+pf.additional_header);

    EvalResult {
        overall_traffic: overall_traffic as f64,
        pkts: edges.len() as f64,
        source_traffic: ((pf.payload+pf.additional_header) * source_pkts) as f64,
        pkts_from_source: source_pkts as f64,
        additional_packets: 0.0,
        denseness: 0.0,
    }
}

//Reads graph files used for BIER scalability paper and constructs petgraph instance.
fn read_brite(filename: &String) -> (Graph<(), f64, Undirected>, HashMap<u32, NodeIndex>) {
    let input = fs::read_to_string(filename).unwrap();
    let lines = input.lines();
    let mut result: Graph<(), f64, Undirected> = Graph::new_undirected();
    let mut read_nodes = false;
    let mut read_edges = false;
    let mut map: HashMap<u32, NodeIndex> = HashMap::new();

    for line in lines {
        if line.starts_with("Nodes") {
            read_nodes = true;
        } else if line.starts_with("Edges") {
            read_edges = true;
        } else if line.eq("") {
            read_edges = false;
            read_nodes = false;
        } else {
            let cols = line.split("\t").collect::<Vec<_>>();
            if read_nodes {
                let next_node_id: u32 = cols[0].parse().unwrap();
                let next_node = result.add_node(());
                map.insert(next_node_id, next_node);
            } else if read_edges {
                let first_node_id: u32 = cols[1].parse().unwrap();
                let second_node_id: u32 = cols[2].parse().unwrap();
                result.add_edge(map[&first_node_id], map[&second_node_id], 1.0);
            }
        }
    }
    (result, map)
}

//Reads SDs for graphs from BIER scalability.
fn parse_bier_sds(filename: String, map: HashMap<u32, NodeIndex>, bitstring_length: u32) -> Vec<Vec<NodeIndex>> {
    let input: Value = serde_json::from_str(&*fs::read_to_string(filename).unwrap()).unwrap();
    let bitstring_sol = input.get(bitstring_length.to_string()).unwrap().as_array().unwrap();
    let mut sol = Vec::with_capacity(bitstring_sol.len());
    for sd in bitstring_sol {
        sol.push(sd.as_array().unwrap().iter().map(|i| map[&(i.as_u64().unwrap() as u32)]).collect());
    }
    sol
}


struct Mesh {
    name: String,
    graph: Graph<(), f64, Undirected>,
    hosts: Vec<NodeIndex>,
    map: HashMap<u32, NodeIndex>
}

fn construct_mesh(name: &str) -> Mesh {
    let (graph, map) = read_brite(&(name.to_string() + ".brite"));
    let mut hosts = Vec::with_capacity(graph.node_count());
    hosts.extend(graph.node_indices());
    Mesh {
        name: name.to_string(),
        graph,
        hosts,
        map,
    }
}

impl Topology for Mesh {
    fn graph(&self) -> &Graph<(), f64, Undirected> {
        &self.graph
    }

    fn hosts(&self) -> &Vec<NodeIndex> {
        &self.hosts
    }

    fn bier_sds(&self, bitstring_length: u32) -> Vec<Vec<NodeIndex>> {
        let input: Value = serde_json::from_str(&*fs::read_to_string(self.name.clone() + ".brite.sol").unwrap()).unwrap();
        let bitstring_sol = input.get(bitstring_length.to_string()).unwrap().as_array().unwrap();
        let mut sol = Vec::with_capacity(bitstring_sol.len());
        for sd in bitstring_sol {
            sol.push(sd.as_array().unwrap().iter().map(|i| self.map[&(i.as_u64().unwrap() as u32)]).collect());
        }
        sol
    }

    fn sample(&self, num: u32, s: f64, rng: &mut StdRng) -> Vec<NodeIndex> {
        let mut destinations = self.hosts.iter().copied().choose_multiple(rng, num as usize);
        destinations.sort_by(|n1, n2| n1.index().cmp(&n2.index()));
        destinations
    }
}



struct Mesh2 {
    name: String,
    graph: Graph<(), f64, Undirected>,
    hosts: Vec<NodeIndex>,
    map: HashMap<u32, NodeIndex>,
    seed: u64,
    random_sds: bool,
}

fn construct_mesh2(name: &str, leaves: u32, seed: u64, random_sds: bool) -> Mesh2 {
    let (mut graph, map) = read_brite(&(name.to_string() + ".brite"));
    let mut hosts = Vec::with_capacity(graph.node_count());

    for node in graph.node_indices().collect::<Vec<_>>() {
        for _l in 0 .. leaves {
            let n = graph.add_node(());
            graph.add_edge(node , n, 1.0);
            hosts.push(n);
        }
    }
    //hosts.append(&mut graph.node_indices().collect::<Vec<_>>());

    Mesh2 {
        name: name.to_string(),
        graph,
        hosts,
        map,
        seed,
        random_sds,
    }
}

impl Topology for Mesh2 {
    fn graph(&self) -> &Graph<(), f64, Undirected> {
        &self.graph
    }

    fn hosts(&self) -> &Vec<NodeIndex> {
        &self.hosts
    }

    fn bier_sds(&self, bitstring_length: u32) -> Vec<Vec<NodeIndex>> {
        if self.random_sds {
            let mut rng = StdRng::seed_from_u64(self.seed);
            let num_sds = (self.graph.node_count() as f64 / bitstring_length as f64).ceil() as usize;

            let mut sds: Vec<Vec<NodeIndex>> = vec![Vec::with_capacity(bitstring_length as usize); num_sds];
            for v in self.graph.node_indices() {
                let mut sd: &mut Vec<NodeIndex> = sds.choose_mut(&mut rng).unwrap();
                while sd.len() >= bitstring_length as usize {
                    sd = sds.choose_mut(&mut rng).unwrap();
                }
                sd.push(v);
            }
            sds
        } else {
            self.compute_bier_sds(bitstring_length, self.seed)
        }
    }

    fn sample(&self, num: u32, s: f64, rng: &mut StdRng) -> Vec<NodeIndex> {
        let mut destinations = self.hosts.iter().copied().choose_multiple(rng, num as usize);
        destinations.sort_by(|n1, n2| n1.index().cmp(&n2.index()));
        destinations
    }
}


impl Mesh2 {
    fn compute_bier_sds(&self, bitstring_length: u32, seed: u64) -> Vec<Vec<NodeIndex>> {
        let mut rng = StdRng::seed_from_u64(seed);
        let num_sds = (self.graph.node_count() as f64 / bitstring_length as f64).ceil() as usize;
        let mut best_sds = vec![Vec::with_capacity(self.graph.node_count()); num_sds];
        for iteration in 0 .. 1 {
            let mut seeds = self.hosts.choose_multiple(&mut rng, num_sds).copied().collect::<Vec<_>>();
            let mut visited: HashSet<NodeIndex> = HashSet::with_capacity(self.graph.node_count());
            let mut bfs_searches = seeds.iter().map(|s| Bfs::new(&self.graph, *s)).collect::<Vec<_>>();
            let mut current = 0;
            let mut sds = vec![Vec::with_capacity(self.graph.node_count()); num_sds];

            while (self.graph.node_count() > visited.len()) {
                let mut next = bfs_searches[current % num_sds].next(&self.graph).unwrap();
                while (visited.contains(&next)) {
                    next = bfs_searches[current % num_sds].next(&self.graph).unwrap();
                }
                visited.insert(next);
                sds[current % num_sds].push(next);
                current += 1;
            }

            best_sds = sds;
        }

        best_sds
    }
}



//Computes the traffic including header and payload to reach all destinations with BIER.
fn traffic_bier(destinations: &Vec<NodeIndex>, sds: &Vec<Vec<NodeIndex>>, bitstring_length: u32, pf: &PacketFormat, paths: &mut GraphPaths) -> EvalResult {
    let mut traffic = 0;
    let mut hops = 0;
    let mut source_pkts = 0;
    let mut source_traffic = 0;
    let mut denseness = 0.0;
    let mut covered_sds = 0;
    for sd in sds {
        let mut edges = HashSet::with_capacity(destinations.len());
        let mut set_bits = 0;
        let mut sd_size = 0;
        for d in destinations.iter().copied() {
            if !sd.contains(&d) {
                continue;
            }
            sd_size += 1;
            let path = paths.path(d);
            set_bits += path.len()-1;
            for i in 1 .. path.len() {
                if i == 1 && !edges.contains(&(path[i-1], path[i])) {
                    source_pkts += 1;
                    source_traffic += pf.payload+pf.additional_header+(bitstring_length as u64/8);
                }
                edges.insert((path[i-1], path[i]));
            }

        }
        if sd_size > 0 && edges.len() > 0 {
            denseness += (set_bits as f64) / (edges.len() as f64);
            covered_sds += 1;
        }

        hops += edges.len() as u64;
        traffic += edges.len() as u64 * (pf.payload+pf.additional_header+(bitstring_length as u64/8));
    }

    let mc_traffic = traffic_multicast(destinations, pf, paths);



    EvalResult {
        overall_traffic: traffic as f64,
        pkts: hops as f64,
        source_traffic: source_traffic as f64,
        pkts_from_source: source_pkts as f64,
        additional_packets: hops as f64 - mc_traffic.pkts,
        denseness: denseness / (covered_sds as f64),
    }
}

fn combined_traffic(destinations: &Vec<NodeIndex>, headers: &Vec<Header>, pf: &PacketFormat, paths: &mut GraphPaths) -> EvalResult {
    let mut overall_traffic = 0.0;
    let mut hops = 0.0;
    let mut source_traffic = 0.0;
    for header in headers {
        overall_traffic += (header.eval_header_traffic(pf, paths) + header.hops*(pf.payload+pf.additional_header)) as f64;
        source_traffic += (header.header_size + pf.payload + pf.additional_header) as f64;
        hops += header.hops as f64;
    }

    let mc_traffic = traffic_multicast(destinations, pf, paths);

    EvalResult {
        overall_traffic,
        pkts: hops,
        source_traffic,
        pkts_from_source: headers.len() as f64,
        additional_packets: hops-mc_traffic.pkts,
        denseness: 0.0,
    }
}


//Computes partitioning of destinations such that the overall traffic is small when one message is used for every partition.
fn optimize_second_approach(source: NodeIndex, destinations: &Vec<NodeIndex>, max_header_size: u64, pf: &PacketFormat, graph: &Graph<(), f64, Undirected>, mut paths: &mut GraphPaths, bitstring_configurations: &BitstringConfigurations) -> Vec<Header> {
    let mut result = Vec::with_capacity(destinations.len());
    let mut current_nodes = Vec::with_capacity(destinations.len());
    let mut header = None;
    let mut destination_set: HashSet<NodeIndex> = HashSet::with_capacity(destinations.len());
    destination_set.extend(destinations.iter());

    let mut path_links = HashSet::with_capacity(graph.node_count());
    for n in destinations {
        let path_nodes = paths.path(*n);
        for i in 1 .. path_nodes.len() {
            path_links.insert((path_nodes[i-1], path_nodes[i]));
        }
    }

    let mut stack = Vec::with_capacity(graph.node_count());
    stack.push(source);
    let mut visited = HashSet::with_capacity(graph.node_count());

    while let Some(node) = stack.pop() {
        visited.insert(node);
        let mut neighbors = graph.neighbors(node).collect::<Vec<_>>();
        neighbors.retain(|n| !visited.contains(n) && path_links.contains(&(node, *n)));
        neighbors.sort_by(|n1, n2| n1.index().cmp(&n2.index())); //allows optimization with Bitstring IDs

        for n in &neighbors {
            stack.insert(0, *n);
        }

        if !destination_set.contains(&node) || source == node {
            continue;
        }

        if current_nodes.len() == 0 {
            header = Some(Header::new_base_case(node, pf, paths, bitstring_configurations));
            current_nodes.push(node);
        } else {
            let n1 = paths.path(current_nodes[0])[1];
            let n2 = paths.path(node)[1];

            if n1 != n2 {
                let mut new_header = Header::new_base_case(current_nodes[0], pf, paths, bitstring_configurations);
                for i in 1 .. current_nodes.len() {
                    new_header.add_destination(current_nodes[i], paths, pf, bitstring_configurations);
                }

                result.push(new_header.clone());
                header = None;
                current_nodes.clear();
                header = Some(Header::new_base_case(node, pf, paths, bitstring_configurations));
                current_nodes.push(node);
            } else {
                let s = header.as_mut().unwrap();
                s.add_destination(node, paths, pf, bitstring_configurations);
                if s.header_size > max_header_size {
                    let mut new_header = Header::new_base_case(current_nodes[0], pf, paths, bitstring_configurations);
                    for i in 1 .. current_nodes.len() {
                        new_header.add_destination(current_nodes[i], paths, pf, bitstring_configurations);
                    }

                    result.push(new_header.clone());
                    header = None;
                    current_nodes.clear();
                    header = Some(Header::new_base_case(node, pf, paths, bitstring_configurations));
                    current_nodes.push(node);
                } else {
                    current_nodes.push(node);
                }
            }


        }


    }

    if current_nodes.len() > 0 {
        let mut new_header = Header::new_base_case(current_nodes[0], pf, paths, bitstring_configurations);
        for i in 1 .. current_nodes.len() {
            new_header.add_destination(current_nodes[i], paths, pf, bitstring_configurations);
        }
        let traffic = new_header.eval_header_traffic(pf, paths) + new_header.hops*(pf.payload+pf.additional_header);
        result.push(new_header.clone());
    }

    result
}

//Trait for network topologies.
//Allows to implement specific algorithms for BIER SDs and node sampling for special cases like Fat Tree and Torus.
trait Topology {
    fn graph(&self) -> &Graph<(), f64, Undirected>;
    fn hosts(&self) -> &Vec<NodeIndex>;
    fn bier_sds(&self, bitstring_length: u32) -> Vec<Vec<NodeIndex>>;
    fn sample(&self, num: u32, s: f64, rng: &mut StdRng) -> Vec<NodeIndex>;
}


//Prof. Menth's preferred topology for highly meshed networks.
//Basically, Grid network where nodes are connected to exactly 4 neighbors, wrap around for first/last line/column.
struct Torus {
    graph: Graph<(), f64, Undirected>,
    k: u32,
    nodes: HashMap<(u32, u32), NodeIndex>,
    hosts: Vec<NodeIndex>,
}

fn generate_torus(k: u32) -> Torus {
    let mut graph: Graph<(), f64, Undirected> = Graph::with_capacity(k.pow(2) as usize, (4*k.pow(2) as usize));
    let mut nodes = HashMap::with_capacity(k.pow(2) as usize);
    let mut hosts = Vec::with_capacity(k.pow(2) as usize);

    //nodes
    for i in 0 .. k { //line
        for j in 0 .. k { //column
            let node = graph.add_node(());
            nodes.insert((i, j), node);
            hosts.push(node);
        }
    }

    //edges
    for i in 0 .. k { //line
        for j in 0 .. k { //column
            let node = nodes[&(i, j)];
            let right = nodes[&(i, (j+1) % k)];
            let bottom = nodes[&((i+1) % k, j)];
            graph.add_edge(node, right, 1.0);
            graph.add_edge(node, bottom, 1.0);
        }
    }

    Torus {
        graph,
        k,
        nodes,
        hosts,
    }
}


impl Topology for Torus {
    fn graph(&self) -> &Graph<(), f64, Undirected> {
        &self.graph
    }

    fn hosts(&self) -> &Vec<NodeIndex> {
        &self.hosts
    }

    //Torus is symmetric, so it does not matter how SDs are computed as long as they are compact.
    fn bier_sds(&self, bitstring_length: u32) -> Vec<Vec<NodeIndex>> {
        let mut sds = Vec::with_capacity((self.k / bitstring_length) as usize + 1);
        let mut current_sd = Vec::with_capacity(bitstring_length as usize);
        for line in 0 .. self.k {
            for column in 0 .. self.k {
                current_sd.push(self.nodes[&(line, column)]);
                if current_sd.len() == bitstring_length as usize {
                    sds.push(current_sd);
                    current_sd = Vec::with_capacity((bitstring_length) as usize);
                }
            }
        }
        if current_sd.len() > 0 {
            sds.push(current_sd);
        }

        sds
    }

    //Uniform sampling
    fn sample(&self, num: u32, s: f64, rng: &mut StdRng) -> Vec<NodeIndex> {
        let mut destinations = self.graph.node_indices().choose_multiple(rng, num as usize);
        destinations.sort_by(|n1, n2| n1.index().cmp(&n2.index()));
        destinations
    }
}

//Toerless desired topology from China.
//See bier-rbs-draft for details.
struct ChinaTree {
    graph: Graph<(), f64, Undirected>,
    hosts: Vec<NodeIndex>,
}

fn generate_china_tree() -> ChinaTree {
    let mut graph: Graph<(), f64, Undirected> = UnGraph::with_capacity(30000, 60000);
    let mut hosts = Vec::with_capacity(8*8*15*18);

    //backbone
    let mut backbone_switches = Vec::with_capacity(8);
    for _i in 0 .. 8 {
        backbone_switches.push(graph.add_node(()));
    }
    for i in 0 .. 8 {
        for j in i+1 .. 8 {
            graph.add_edge(backbone_switches[i], backbone_switches[j], 1.0);
        }
    }

    //core layers
    for b in 0 .. 8 {
        //upper layer
        let c1 = graph.add_node(());
        graph.add_edge(c1, backbone_switches[b], 1.0);
        graph.add_edge(c1, backbone_switches[(b+1) % 8], 1.0);

        let c2 = graph.add_node(());
        graph.add_edge(c2, backbone_switches[b], 1.0);
        graph.add_edge(c2, backbone_switches[(b+1) % 8], 1.0);
        graph.add_edge(c1, c2, 1.0);

        //lower layer
        let c3 = graph.add_node(());
        graph.add_edge(c3, c1, 1.0);
        graph.add_edge(c3, c2, 1.0);
        let c4 = graph.add_node(());
        graph.add_edge(c4, c1, 1.0);
        graph.add_edge(c4, c2, 1.0);
        graph.add_edge(c3, c4, 1.0);

        //aggregation layer
        let upper_agg = [graph.add_node(()), graph.add_node(()), graph.add_node(()), graph.add_node(())];
        for upper in upper_agg {
            graph.add_edge(upper, c3, 1.0);
            graph.add_edge(upper, c4, 1.0);
        }

        let lower_agg = [graph.add_node(()), graph.add_node(()), graph.add_node(()), graph.add_node(())];
        for upper in upper_agg {
            for lower in lower_agg {
                graph.add_edge(upper, lower, 1.0);
            }
        }

        //aggregation rings
        for ar in 0 .. 8 {
            let aggregation_ring = [graph.add_node(()), graph.add_node(()), graph.add_node(()), graph.add_node(()), graph.add_node(()), graph.add_node(())];
            for i in 0 .. 5 {
                graph.add_edge(aggregation_ring[i], aggregation_ring[i+1], 1.0);
            }
            graph.add_edge(aggregation_ring[0], lower_agg[1], 1.0);
            graph.add_edge(aggregation_ring[0], lower_agg[2], 1.0);
            graph.add_edge(aggregation_ring[1], lower_agg[1], 1.0);
            graph.add_edge(aggregation_ring[1], lower_agg[2], 1.0);

            //access rings
            for i in 0 .. 6 {
                for j in i+1 .. 6 {
                    let mut access_ring = Vec::with_capacity(18);
                    for _k in 0 .. 18 {
                        access_ring.push(graph.add_node(()));
                    }
                    for k in 0 .. 17 {
                        graph.add_edge(access_ring[k], access_ring[k+1], 1.0);
                    }
                    graph.add_edge(access_ring[0], aggregation_ring[i],1.0);
                    graph.add_edge(access_ring[17], aggregation_ring[i],1.0);
                    graph.add_edge(access_ring[0], aggregation_ring[j],1.0);
                    graph.add_edge(access_ring[17], aggregation_ring[j],1.0);
                    hosts.extend(access_ring);
                }
            }
        }
    }

    ChinaTree {
        graph,
        hosts,
    }
}


impl Topology for ChinaTree {
    fn graph(&self) -> &Graph<(), f64, Undirected> {
        &self.graph
    }

    fn hosts(&self) -> &Vec<NodeIndex> {
        &self.hosts
    }

    fn bier_sds(&self, bitstring_length: u32) -> Vec<Vec<NodeIndex>> {
        let mut sds = Vec::with_capacity(self.hosts.len() / bitstring_length as usize + 1);
        let mut sd = Vec::with_capacity(bitstring_length as usize);
        for node in &self.hosts {
            sd.push(*node);
            if sd.len() == bitstring_length as usize {
                sds.push(sd);
                sd = Vec::with_capacity(bitstring_length as usize);
            }
        }
        if sd.len() > 0 {
            sds.push(sd);
        }
        sds
    }

    fn sample(&self, num: u32, s: f64, rng: &mut StdRng) -> Vec<NodeIndex> {
        let mut destinations = self.hosts.iter().copied().choose_multiple(rng, num as usize);
        destinations.sort_by(|n1, n2| n1.index().cmp(&n2.index()));
        destinations
    }
}



//Prof. Menth's' desired topology for structured networks from real-world use cases.
//See SIGCOMM paper for details.
struct FatTree {
    graph: Graph<(), f64, Undirected>,
    k: u32,
    core_switches: Vec<NodeIndex>,
    agg_switches: HashMap<(u32, u32), NodeIndex>,
    edge_switches: HashMap<(u32, u32), NodeIndex>,
    servers: HashMap<(u32, u32, u32), NodeIndex>,
    pods: Vec<Vec<NodeIndex>>,
    hosts: Vec<NodeIndex>,
}

impl Topology for FatTree {
    fn graph(&self) -> &Graph<(), f64, Undirected> {
        &self.graph
    }

    fn hosts(&self) -> &Vec<NodeIndex> {
        &self.hosts
    }

    //Fill SDs with nodes from the same pod and same edge router if possible.
    fn bier_sds(&self, bitstring_length: u32) -> Vec<Vec<NodeIndex>> {
        let mut result = Vec::with_capacity(self.k as usize);
        let mut sd = Vec::with_capacity((self.k/2).pow(2) as usize);
        for pod in 0 .. self.k {
            for i in 0 .. self.k/2 {
                for j in 0 .. self.k/2 {
                    sd.push(self.servers[&(pod, i, j)]);
                    if sd.len() == bitstring_length as usize {
                        result.push(sd);
                        sd = Vec::with_capacity((self.k/2).pow(2) as usize);
                    }
                }
            }


        }
        if sd.len() > 0 {
            result.push(sd);
        }
        result
    }

    //Correlated sampling by Prof. Menth.
    //s is a parameter that controls how likely it is that nodes from the same edge router are selected if other nodes are already selected.
    //s=0 is uniform sampling.
    fn sample(&self, num: u32, s: f64, rng: &mut StdRng) -> Vec<NodeIndex> {
        let mut sample: HashSet<NodeIndex> = HashSet::with_capacity(num as usize);
        let mut r_edge = vec![vec![0; (self.k/2) as usize]; self.k as usize];
        let mut r = vec![0; self.k as usize];

        while sample.len() < num as usize {

            //choose pod
            let pod= {
                let mut w = vec![0.0; self.k as usize];
                let mut p = vec![0.0; self.k as usize];
                let mut sum = 0.0;
                for i in 0 .. self.k as usize {
                    w[i] = (1.0 + s*r[i] as f64);
                    sum += w[i];
                }
                for i in 0 .. self.k as usize {
                    p[i] = w[i] / sum;
                }
                let dist = WeightedIndex::new(&p).unwrap();
                (0 .. self.k).nth(dist.sample(rng)).unwrap()
            };
            r[pod as usize] += 1;

            //choose edge switch
            let edge_switch= {
                let mut w = vec![0.0; (self.k/2) as usize];
                let mut p = vec![0.0; (self.k/2) as usize];
                let mut sum = 0.0;
                for j in 0 .. (self.k/2) as usize {
                    let mut contains_unselected = false;
                    for k in 0 .. (self.k/2) as usize {
                        if !sample.contains(&self.servers[&(pod, j as u32, k as u32)]) {
                            contains_unselected = true;
                            break;
                        }
                    }

                    w[j] = if contains_unselected {(1.0 + s*r_edge[pod as usize][j] as f64)} else {0.0};
                    sum += w[j];
                }
                if sum == 0.0 {
                    continue;
                }
                for j in 0 .. (self.k/2) as usize {
                    p[j] = w[j] / sum;
                }
                let dist = WeightedIndex::new(&p).unwrap();
                (0 .. self.k/2).nth(dist.sample(rng)).unwrap()
            };
            r_edge[pod as usize][edge_switch as usize] += 1;

            //choose server
            let server= {
                let mut w = vec![0.0; (self.k/2) as usize];
                let mut p = vec![0.0; (self.k/2) as usize];
                let mut sum = 0.0;
                for k in 0 .. (self.k/2) as usize {
                    w[k] = if sample.contains(&self.servers[&(pod, edge_switch, k as u32)]) {0.0} else {1.0};
                    sum += w[k];
                }
                for k in 0 .. (self.k/2) as usize {
                    p[k] = w[k] / sum;
                }
                let dist = WeightedIndex::new(&p).unwrap();
                (0 .. self.k/2).nth(dist.sample(rng)).unwrap()
            };
            sample.insert(self.servers[&(pod, edge_switch, server)]);
        }

        Vec::from_iter(sample.iter().copied())
    }
}


fn generate_fat_tree(k: u32) -> FatTree {
    let mut graph: Graph<(), f64, Undirected> = UnGraph::with_capacity(((k / 2).pow(2) + k.pow(2) + k*(k / 2).pow(2)) as usize, ((k / 2)*k + k*(k/2).pow(2) + k*(k / 2).pow(2)) as usize);

    //core  nodes
    let mut core_switches = Vec::with_capacity((k / 2).pow(2) as usize);
    for _i in 0 .. (k / 2).pow(2) {
        core_switches.push(graph.add_node(()));
    }

    //aggregation layer of pods
    let mut agg_switches: HashMap<(u32, u32), NodeIndex> = HashMap::with_capacity((k*(k/2)) as usize);
    for pod in 0 .. k {
        for i in 0 .. k/2 {
            let switch = graph.add_node(());

            //edges to core switches
            for j in 0 .. k/2 {
                graph.add_edge(switch, core_switches[(i*(k/2)+j) as usize], 1.0);
            }

            agg_switches.insert((pod, i), switch);
        }
    }

    //edge switches
    let mut edge_switches: HashMap<(u32, u32), NodeIndex> = HashMap::with_capacity((k*(k/2)) as usize);
    for pod in 0 .. k {
        for i in 0 .. k / 2 {
            let switch = graph.add_node(());

            //edges to aggregation layer
            for j in 0 .. k/2 {
                graph.add_edge(switch, agg_switches[&(pod, j)], 1.0);
            }

            edge_switches.insert((pod, i), switch);
        }
    }

    let mut servers: HashMap<(u32, u32, u32), NodeIndex> = HashMap::with_capacity((k*(k/2).pow(2)) as usize);
    let mut hosts = Vec::with_capacity((k*(k/2).pow(2)) as usize);
    let mut pods = Vec::with_capacity(k as usize);
    for pod in 0 .. k {
        pods.push(Vec::with_capacity((k/2).pow(2) as usize));
        for i in 0 .. k / 2 {
            for j in 0 .. k/2 {
                let server = graph.add_node(());

                graph.add_edge(server, edge_switches[&(pod, i)], 1.0);

                servers.insert((pod, i, j), server);
                hosts.push(server);
                pods[pod as usize].push(server);
            }
        }
    }

    FatTree {
        graph,
        k,
        core_switches,
        agg_switches,
        edge_switches,
        servers,
        pods,
        hosts,
    }
}

struct RouterRing {
    graph: Graph<(), f64, Undirected>,
    nodes: Vec<NodeIndex>,
}

fn generate_router_ring(n: u32, k: u32) -> Ring {
    let mut graph = Graph::new_undirected();
    let mut nodes = Vec::with_capacity(n as usize);
    let first_router = graph.add_node(());
    for _j in 0 .. k {
        let node = graph.add_node(());
        graph.add_edge(node, first_router, 1.0);
        nodes.push(node);
    }

    let mut pred = first_router;
    for _i in 0 .. n-1 {
        let router = graph.add_node(());
        graph.add_edge(pred, router, 1.0);

        for _j in 0 .. k {
            let node = graph.add_node(());
            graph.add_edge(node, router, 1.0);
            nodes.push(node);
        }

        pred = router;
    }
    graph.add_edge(pred, first_router, 1.0);

    Ring {
        graph,
        nodes,
    }
}

impl Topology for RouterRing {
    fn graph(&self) -> &Graph<(), f64, Undirected> {
        &self.graph
    }

    fn hosts(&self) -> &Vec<NodeIndex> {
        &self.nodes
    }

    fn bier_sds(&self, bitstring_length: u32) -> Vec<Vec<NodeIndex>> {
        let mut sds = Vec::with_capacity(self.nodes.len() / bitstring_length as usize + 1);
        let mut sd = Vec::with_capacity(bitstring_length as usize);
        for node in &self.nodes {
            sd.push(*node);
            if sd.len() == bitstring_length as usize {
                sds.push(sd);
                sd = Vec::with_capacity(bitstring_length as usize);
            }
        }
        if sd.len() > 0 {
            sds.push(sd);
        }
        sds
    }

    fn sample(&self, num: u32, s: f64, rng: &mut StdRng) -> Vec<NodeIndex> {
        let mut destinations = self.graph.node_indices().choose_multiple(rng, num as usize);
        destinations.sort_by(|n1, n2| n1.index().cmp(&n2.index()));
        destinations
    }
}


struct Ring {
    graph: Graph<(), f64, Undirected>,
    nodes: Vec<NodeIndex>,
}

fn generate_ring(n: u32) -> Ring {
    let mut graph = Graph::new_undirected();
    let mut nodes = Vec::with_capacity(n as usize);
    let first_node = graph.add_node(());
    nodes.push(first_node);
    let mut pred = first_node;
    for _i in 0 .. n-1 {
        let node = graph.add_node(());
        nodes.push(node);
        graph.add_edge(pred, node, 1.0);
        pred = node;
    }
    graph.add_edge(pred, first_node, 1.0);

    Ring {
        graph,
        nodes,
    }
}

impl Topology for Ring {
    fn graph(&self) -> &Graph<(), f64, Undirected> {
        &self.graph
    }

    fn hosts(&self) -> &Vec<NodeIndex> {
        &self.nodes
    }

    fn bier_sds(&self, bitstring_length: u32) -> Vec<Vec<NodeIndex>> {
        let mut sds = Vec::with_capacity(self.nodes.len() / bitstring_length as usize + 1);
        let mut sd = Vec::with_capacity(bitstring_length as usize);
        for node in &self.nodes {
            sd.push(*node);
            if sd.len() == bitstring_length as usize {
                sds.push(sd);
                sd = Vec::with_capacity(bitstring_length as usize);
            }
        }
        if sd.len() > 0 {
            sds.push(sd);
        }
        sds
    }

    fn sample(&self, num: u32, s: f64, rng: &mut StdRng) -> Vec<NodeIndex> {
        let mut destinations = self.graph.node_indices().choose_multiple(rng, num as usize);
        destinations.sort_by(|n1, n2| n1.index().cmp(&n2.index()));
        destinations
    }
}


struct Line {
    graph: Graph<(), f64, Undirected>,
    nodes: Vec<NodeIndex>,
}

fn generate_line(n: u32) -> Line {
    let mut graph = Graph::new_undirected();
    let mut nodes = Vec::with_capacity(n as usize);
    let first_node = graph.add_node(());
    nodes.push(first_node);
    let mut pred = first_node;
    for _i in 0 .. n-1 {
        let node = graph.add_node(());
        nodes.push(node);
        graph.add_edge(pred, node, 1.0);
        pred = node;
    }

    Line {
        graph,
        nodes,
    }
}

impl Topology for Line {
    fn graph(&self) -> &Graph<(), f64, Undirected> {
        &self.graph
    }

    fn hosts(&self) -> &Vec<NodeIndex> {
        &self.nodes
    }

    fn bier_sds(&self, bitstring_length: u32) -> Vec<Vec<NodeIndex>> {
        let mut sds = Vec::with_capacity(self.nodes.len() / bitstring_length as usize + 1);
        let mut sd = Vec::with_capacity(bitstring_length as usize);
        for node in &self.nodes {
            sd.push(*node);
            if sd.len() == bitstring_length as usize {
                sds.push(sd);
                sd = Vec::with_capacity(bitstring_length as usize);
            }
        }
        if sd.len() > 0 {
            sds.push(sd);
        }
        sds
    }

    fn sample(&self, num: u32, s: f64, rng: &mut StdRng) -> Vec<NodeIndex> {
        let mut destinations = self.graph.node_indices().choose_multiple(rng, num as usize);
        destinations.sort_by(|n1, n2| n1.index().cmp(&n2.index()));
        destinations
    }
}



//First simple evaluation.
//Computes the average overall traffic for BIER, BIER-Trees, IPMC, Unicast for a given number of receivers, summed up for all possible source nodes.
fn eval_traffic<T : Topology + Sync>(topology: &T, bitstring_configs: &BitstringConfigurations, bitstring_length: u32, num_receivers: u32, max_header_size: u64, runs: u32, s: f64, rng: &mut StdRng) -> (EvalResult, EvalResult, EvalResult, EvalResult) {

    let bier_sds = topology.bier_sds(bitstring_length);

    let packet_format = PacketFormat::new(topology.hosts().len(), 2, 8, 500, 52);


    let mut destination_runs = Vec::with_capacity(runs as usize);
    for _r in 0 .. runs {
        let destinations = topology.sample(num_receivers, s, rng);
        destination_runs.push(destinations);
    }


    let results = topology.hosts().par_iter().copied().map(|source| {
        let mut paths = GraphPaths::new(source, &topology.graph());

        avg(&destination_runs.iter().map(|destinations| {
            let result_combined = optimize_second_approach(source, &destinations, max_header_size, &packet_format, &topology.graph(), &mut paths, &bitstring_configs);



            let result_bier = traffic_bier(destinations, &bier_sds, bitstring_length, &packet_format,  &mut paths);
            let result_uc = traffic_unicast(destinations, &packet_format,  &mut paths);
            let result_mc = traffic_multicast(destinations, &packet_format,  &mut paths);
            let result_overall = combined_traffic(destinations, &result_combined, &packet_format,  &mut paths);
            (result_overall, result_bier, result_uc, result_mc)
        }).collect::<Vec<_>>())

    }).collect::<Vec<_>>();


    sum(&results)
}


fn eval_runtime<T : Topology + Sync>(topology: &T, bitstring_configs: &BitstringConfigurations, num_receivers: u32, max_header_size: u64, runs: u32, rng: &mut StdRng) -> f64 {


    let packet_format = PacketFormat::new(topology.hosts().len(), 2, 8, 500, 52);


    let mut destination_runs = Vec::with_capacity(runs as usize);
    for _r in 0 .. runs {
        let destinations = topology.sample(num_receivers, 0.0, rng);
        destination_runs.push(destinations);
    }
    let start = Instant::now();


    let results = topology.hosts().par_iter().copied().map(|source| {
        let mut paths = GraphPaths::new(source, &topology.graph());

        let times: u128 = destination_runs.iter().map(|destinations| {
            let start = Instant::now();
            let result_combined = optimize_second_approach(source, &destinations, max_header_size, &packet_format, &topology.graph(), &mut paths, &bitstring_configs);

            start.elapsed().as_millis()
        }).collect::<Vec<_>>().iter().sum();
        times as f64 / destination_runs.len() as f64
    }).collect::<Vec<_>>();

    topology.hosts().len() as f64 / start.elapsed().as_secs_f64()
}



fn eval_no_header_limit<T : Topology + Sync>(topology: &T, bitstring_configs: &BitstringConfigurations, num_receivers: &Vec<usize>, runs: u32, rng: &mut StdRng) -> Vec<f64> {


    let packet_format = PacketFormat::new(topology.hosts().len(), 2, 8, 500, 52);


    let mut destination_runs = vec![Vec::with_capacity(runs as usize); num_receivers.len()];
    for (i, num) in num_receivers.iter().enumerate() {
        for _r in 0 .. runs {
            let destinations = topology.sample(*num as u32, 0.0, rng);
            destination_runs[i].push(destinations);
        }
    }


    let results = topology.hosts().par_iter().copied().map(|source| {
        let mut paths = GraphPaths::new(source, &topology.graph());

        let mut avg = Vec::with_capacity(num_receivers.len());
        for (i, num) in num_receivers.iter().enumerate() {
            let mut sum = 0;
            for dest in &destination_runs[i] {
                let result_combined = optimize_second_approach(source, dest, 1000000000, &packet_format, &topology.graph(), &mut paths, &bitstring_configs);
                if result_combined.len() > 0 {
                    sum += result_combined[0].header_size;
                }
            }
            avg.push(sum as f64 / runs as f64);
        }

        avg

    }).collect::<Vec<_>>();

    results.iter().fold(vec![0.0; num_receivers.len()], |mut sum, next| {
        for i in 0 .. sum.len() {
            sum[i] += next[i] / topology.hosts().len() as f64;
        }
        sum
    })
}



fn eval_header_limit<T : Topology + Sync>(topology: &T, bitstring_configs: &BitstringConfigurations, header_sizes: &Vec<usize>, num_receivers: &Vec<usize>, runs: u32, rng: &mut StdRng) -> (Vec<Vec<f64>>, Vec<Vec<f64>>, Vec<Vec<f64>>) {


    let packet_format = PacketFormat::new(topology.hosts().len(), 2, 8, 500, 52);


    let mut destination_runs = vec![Vec::with_capacity(runs as usize); num_receivers.len()];
    for (i, num) in num_receivers.iter().enumerate() {
        for _r in 0 .. runs {
            let destinations = topology.sample(*num as u32, 0.0, rng);
            destination_runs[i].push(destinations);
        }
    }


    let results = topology.hosts().par_iter().copied().map(|source| {
        let mut paths = GraphPaths::new(source, &topology.graph());
        let mut results = Vec::with_capacity(header_sizes.len());

        for (j, header_size) in header_sizes.iter().enumerate() {
            let mut avg = Vec::with_capacity(num_receivers.len());
            for (i, num) in num_receivers.iter().enumerate() {
                let mut sum = 0.0;
                for dest in &destination_runs[i] {
                    let headers = optimize_second_approach(source, dest, *header_size as u64, &packet_format, &topology.graph(), &mut paths, &bitstring_configs);
                    if headers.len() > 0 {
                        let eval_result = combined_traffic(dest, &headers, &packet_format, &mut paths);
                        sum += eval_result.additional_packets;
                    }
                }
                avg.push(sum as f64 / runs as f64);
            }

            results.push(avg);
        }

        results

    }).collect::<Vec<_>>();

    let mut bier_sds = Vec::with_capacity(header_sizes.len());
    for header_size in header_sizes {
        bier_sds.push(topology.bier_sds(*header_size as u32 * 8));
    }

    let results_bier = topology.hosts().par_iter().copied().map(|source| {
        let mut paths = GraphPaths::new(source, &topology.graph());
        let mut results = Vec::with_capacity(header_sizes.len());

        for (j, header_size) in header_sizes.iter().enumerate() {
            let mut avg = Vec::with_capacity(num_receivers.len());
            for (i, num) in num_receivers.iter().enumerate() {
                let mut sum = 0.0;
                for dest in &destination_runs[i] {
                    let eval_result = traffic_bier(dest, &bier_sds[j], *header_size as u32 * 8, &packet_format, &mut paths);
                    sum += eval_result.additional_packets;

                }
                avg.push(sum as f64 / runs as f64);
            }

            results.push(avg);
        }

        results

    }).collect::<Vec<_>>();

    let results_ipmc = topology.hosts().par_iter().copied().map(|source| {
        let mut paths = GraphPaths::new(source, &topology.graph());
        let mut results = Vec::with_capacity(header_sizes.len());

        for (j, header_size) in header_sizes.iter().enumerate() {
            let mut avg = Vec::with_capacity(num_receivers.len());
            for (i, num) in num_receivers.iter().enumerate() {
                let mut sum = 0.0;
                for dest in &destination_runs[i] {
                    let res = traffic_multicast(dest, &packet_format, &mut paths);
                    sum += res.pkts;

                }
                avg.push(sum as f64 / runs as f64);
            }

            results.push(avg);
        }

        results

    }).collect::<Vec<_>>();

    let averages = results.iter().fold(vec![vec![0.0; num_receivers.len()]; header_sizes.len()], |mut intermediate, next| {
        for i in 0 .. intermediate.len() {
            for j in 0 .. intermediate[i].len() {
                intermediate[i][j] += next[i][j] / topology.hosts().len() as f64;
            }
        }
        intermediate
    });

    let averages_bier = results_bier.iter().fold(vec![vec![0.0; num_receivers.len()]; header_sizes.len()], |mut intermediate, next| {
        for i in 0 .. intermediate.len() {
            for j in 0 .. intermediate[i].len() {
                intermediate[i][j] += next[i][j] / topology.hosts().len() as f64;
            }
        }
        intermediate
    });

    let averages_ipmc = results_ipmc.iter().fold(vec![vec![0.0; num_receivers.len()]; header_sizes.len()], |mut intermediate, next| {
        for i in 0 .. intermediate.len() {
            for j in 0 .. intermediate[i].len() {
                intermediate[i][j] += next[i][j] / topology.hosts().len() as f64;
            }
        }
        intermediate
    });

    (averages, averages_bier, averages_ipmc)
}


//Holds eval results for different metrics.
#[derive(Copy, Clone, Debug)]
struct EvalResult {
    overall_traffic: f64,
    pkts: f64,
    source_traffic: f64,
    pkts_from_source: f64,
    additional_packets: f64,
    denseness: f64,
}

fn avg(results: &Vec<(EvalResult,EvalResult,EvalResult,EvalResult)>) -> (EvalResult,EvalResult,EvalResult,EvalResult) {
    let avg_combined = avg_result(&results.iter().map(|r| r.0).collect::<Vec<_>>());
    let avg_bier = avg_result(&results.iter().map(|r| r.1).collect::<Vec<_>>());
    let avg_unicast = avg_result(&results.iter().map(|r| r.2).collect::<Vec<_>>());
    let avg_multicast = avg_result(&results.iter().map(|r| r.3).collect::<Vec<_>>());
    (avg_combined,avg_bier,avg_unicast,avg_multicast)
}

fn sum(results: &Vec<(EvalResult,EvalResult,EvalResult,EvalResult)>) -> (EvalResult,EvalResult,EvalResult,EvalResult) {
    let avg_combined = sum_result(&results.iter().map(|r| r.0).collect::<Vec<_>>());
    let avg_bier = sum_result(&results.iter().map(|r| r.1).collect::<Vec<_>>());
    let avg_unicast = sum_result(&results.iter().map(|r| r.2).collect::<Vec<_>>());
    let avg_multicast = sum_result(&results.iter().map(|r| r.3).collect::<Vec<_>>());
    (avg_combined,avg_bier,avg_unicast,avg_multicast)
}

fn avg_result(results: &Vec<EvalResult>) -> EvalResult {
    let mut avg = EvalResult {
        overall_traffic: 0.0,
        pkts: 0.0,
        source_traffic: 0.0,
        pkts_from_source: 0.0,
        additional_packets: 0.0,
        denseness: 0.0,
    };
    for result in results {
        avg.overall_traffic += result.overall_traffic / results.len() as f64;
        avg.pkts += result.pkts / results.len() as f64;
        avg.source_traffic += result.source_traffic / results.len() as f64;
        avg.pkts_from_source += result.pkts_from_source / results.len() as f64;
        avg.additional_packets += result.additional_packets / results.len() as f64;
        avg.denseness += result.denseness / results.len() as f64;
    }

    avg
}

fn sum_result(results: &Vec<EvalResult>) -> EvalResult {
    let mut avg = EvalResult {
        overall_traffic: 0.0,
        pkts: 0.0,
        source_traffic: 0.0,
        pkts_from_source: 0.0,
        additional_packets: 0.0,
        denseness: 0.0,
    };
    for result in results {
        avg.overall_traffic += result.overall_traffic;
        avg.pkts += result.pkts;
        avg.source_traffic += result.source_traffic;
        avg.pkts_from_source += result.pkts_from_source;
        avg.additional_packets += result.additional_packets;
        avg.denseness += result.denseness;
    }

    avg
}

fn print_result(result: &(EvalResult, EvalResult, EvalResult, EvalResult)) {
    //print!("{:.2};{:.2};{:.2};{:.2};", result.0.overall_traffic/1000000.0, result.1.overall_traffic/1000000.0, result.2.overall_traffic/1000000.0, result.3.overall_traffic/1000000.0);
    //print!("{:.2};{:.2};{:.2};{:.2};", result.0.pkts, result.1.pkts, result.2.pkts, result.3.pkts);
    //print!("{:.2};{:.2};{:.2};{:.2};", result.0.additional_packets, result.1.additional_packets, result.2.additional_packets, result.3.additional_packets);
    //print!("{:.2};{:.2};{:.2};{:.2};", result.0.source_traffic/1000000.0, result.1.source_traffic/1000000.0, result.2.source_traffic/1000000.0, result.3.source_traffic/1000000.0);
    //print!("{:.2};{:.2};{:.2};{:.2};\n", result.0.pkts_from_source, result.1.pkts_from_source, result.2.pkts_from_source, result.3.pkts_from_source);
    //print!("{:.2};{:.2};{:.2};{:.2};\n", result.0.denseness, result.1.denseness, result.2.denseness, result.3.denseness);
    print!("{:.2};{:.2};{:.2};", result.0.overall_traffic/result.3.overall_traffic, result.1.overall_traffic/result.3.overall_traffic, result.1.overall_traffic/result.0.overall_traffic);
    print!("{:.2};{:.2};{:.2};", result.0.pkts/result.3.pkts, result.1.pkts/result.3.pkts, result.1.pkts/result.0.pkts);
    print!("{:.2};{:.2};{:.2};\n", result.0.pkts_from_source/result.3.pkts_from_source, result.1.pkts_from_source/result.3.pkts_from_source, result.1.pkts_from_source/result.0.pkts_from_source);

}

fn main() {
    //let test_graph: Graph<(), (), Undirected> = barabasi_albert_graph(&mut rng, 1000, 2, None);

    let mut rng = StdRng::seed_from_u64(0);
    let fat_tree = generate_fat_tree(32);
    let torus = generate_torus(30);
    let router_ring = generate_router_ring(30, 254);
    let line = generate_line(10000);
    let china = generate_china_tree();
    //let mesh = construct_mesh("/root/RustroverProjects/multicast/graphs/graph1024_v4_1");
    let mesh2 = construct_mesh2("/home/student/multicast/graph1024_v4_1", 16, 1, false);
    //let mesh2 = construct_mesh2("/home/thomas/Dokumente/BIER2/graph1024_v4_1", 16, 0, false);

    let bitstring_configs = bitstring_configs(mesh2.graph());


    // let result = eval_no_header_limit(&mesh2, &bitstring_configs, &vec![1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384], 20, &mut rng);
    // for r in result {
    //     println!("{r}");
    // }
    // println!("----");

    // let (result, result_bier, results_ipmc) = eval_header_limit(&mesh2, &bitstring_configs, &vec![32, 64, 128, 256], &vec![1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384], 20, &mut rng);
    // for r1 in result {
    //     for r2 in r1 {
    //         print!("{};", r2);
    //     }
    //     print!("\n");
    // }
    //
    // for r1 in result_bier {
    //     for r2 in r1 {
    //         print!("{};", r2);
    //     }
    //     print!("\n");
    // }
    //
    // for r1 in results_ipmc {
    //     for r2 in r1 {
    //         print!("{};", r2);
    //     }
    //     print!("\n");
    // }

    //Eval for power of 2 receivers
    for hs in vec![32, 64, 256] {
        println!("Header size: {hs}");
        for r in (0 ..= 14).map(|n| 2u32.pow(n)) {
            let result = eval_traffic(&mesh2, &bitstring_configs, hs*8, r, hs as u64, 20, 0.0, &mut rng);
            //println!("BIER: {}\nCombined: {}\nIPMC: {}\nUnicast: {}", r_bier, r_combined, r_mc, r_uc);
            print_result(&result);
        }
    }

    for l in vec![1, 8, 16, 32] {
        println!("Leafs: {l}");
        let mesh2 = construct_mesh2("/home/student/multicast/graph1024_v4_1", l, 0, false);
        let bitstring_configs = crate::bitstring_configs(mesh2.graph());

        for r in (0..=14).map(|n| 2u32.pow(n)) {
            let result = eval_traffic(&mesh2, &bitstring_configs, 256, r, 32 as u64, 20, 0.0, &mut rng);
            //println!("BIER: {}\nCombined: {}\nIPMC: {}\nUnicast: {}", r_bier, r_combined, r_mc, r_uc);
            print!("{:.2};{:.2};{:.2};\n", result.0.overall_traffic / result.3.overall_traffic, result.1.overall_traffic / result.3.overall_traffic, result.1.overall_traffic / result.0.overall_traffic);
        }
    }
    // for r in (0 ..= 14).map(|n| 2u32.pow(n)) {
    //      let result = eval_traffic(&mesh2, &bitstring_configs, 256, r, 32, 1, 0.0, &mut rng);
    //      //println!("BIER: {}\nCombined: {}\nIPMC: {}\nUnicast: {}", r_bier, r_combined, r_mc, r_uc);
    //      print_result(&result);
    // }
    //
    // for r in (0 ..= 14).map(|n| 2u32.pow(n)) {
    //     let result = eval_traffic(&mesh2, &bitstring_configs, 256*8, r, 32*8, 1, 0.0, &mut rng);
    //     //println!("BIER: {}\nCombined: {}\nIPMC: {}\nUnicast: {}", r_bier, r_combined, r_mc, r_uc);
    //     print_result(&result);
    // }




    /*for r in (0 ..= 4).map(|n| 2u32.pow(n)) {
        let result = eval_runtime(&mesh2, &bitstring_configs, r, 32*8, 1, &mut rng);
        println!("{};{}", r, result)
    }


    for r in (0 ..= 14).map(|n| 2u32.pow(n)) {
        let result = eval_runtime(&mesh2, &bitstring_configs, r, 32*8, 1, &mut rng);
        println!("{};{}", r, result)
    }*/
    // let bitstring_configs = crate::bitstring_configs(fat_tree.graph());
    //
    //
    // let result = eval_no_header_limit(&fat_tree, &bitstring_configs, &vec![1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192], 1, &mut rng);
    // for r in result {
    //     println!("{r}");
    // }
    // println!("----");
    //
    // let (result, result_bier, results_ipmc) = eval_header_limit(&fat_tree, &bitstring_configs, &vec![32, 64, 128, 256], &vec![1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192], 1, &mut rng);
    // for r1 in result {
    //     for r2 in r1 {
    //         print!("{};", r2);
    //     }
    //     print!("\n");
    // }
    //
    // for r1 in result_bier {
    //     for r2 in r1 {
    //         print!("{};", r2);
    //     }
    //     print!("\n");
    // }
    //
    // for r1 in results_ipmc {
    //     for r2 in r1 {
    //         print!("{};", r2);
    //     }
    //     print!("\n");
    // }
    //
    // //Eval for power of 2 receivers
    // for r in (0 ..= 13).map(|n| 2u32.pow(n)) {
    //     let result = eval_traffic(&fat_tree, &bitstring_configs, 256, r, 32, 1, 0.0, &mut rng);
    //     //println!("BIER: {}\nCombined: {}\nIPMC: {}\nUnicast: {}", r_bier, r_combined, r_mc, r_uc);
    //     print_result(&result);
    // }

    //Evaluation for different receiver correlations.
    // let corr = vec![0.0, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0];
    // for s in corr {
    //     let (r_bier, r_combined, r_mc, r_uc) = eval_traffic(&fat_tree, 256, 512, 32, 1, s, &mut rng);
    //     //println!("BIER: {}\nCombined: {}\nIPMC: {}\nUnicast: {}", r_bier, r_combined, r_mc, r_uc);
    //     println!("{}\n{}\n{}\n{}", r_bier/1000000, r_combined/1000000, r_mc/1000000, r_uc/1000000);
    // }

}

