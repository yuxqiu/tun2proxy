use crate::error::Result;
use hashlink::{LruCache, linked_hash_map::RawEntryMut};
use std::{
    collections::HashMap,
    convert::TryInto,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use tproxy_config::IpCidr;

/// A virtual DNS server which allocates IP addresses to clients.
/// The IP addresses are in the range of private IP addresses.
/// The DNS server is implemented as a LRU cache.
pub struct VirtualDns {
    trailing_dot: bool,
    lru_cache: LruCache<IpAddr, NameCacheEntry>,
    name_to_ip: HashMap<String, IpAddr>,
    network_addr: IpAddr,
    broadcast_addr: IpAddr,
    next_addr: IpAddr,
}

struct NameCacheEntry {
    name: String,
}

impl VirtualDns {
    pub fn new(ip_pool: IpCidr) -> Self {
        let network_addr = ip_pool.first_address();
        let broadcast_addr = ip_pool.last_address();
        let capacity = match (network_addr, broadcast_addr) {
            (IpAddr::V4(n), IpAddr::V4(b)) => {
                let n: u32 = n.into();
                let b: u32 = b.into();
                (b - n + 1) as usize
            }
            (IpAddr::V6(n), IpAddr::V6(b)) => {
                let n: u128 = n.into();
                let b: u128 = b.into();
                (b - n + 1) as usize
            }
            _ => unreachable!(),
        };
        Self {
            trailing_dot: false,
            next_addr: network_addr,
            name_to_ip: HashMap::default(),
            lru_cache: LruCache::new(capacity),
            network_addr,
            broadcast_addr,
        }
    }

    /// Returns the DNS response to send back to the client.
    pub fn generate_query(&mut self, data: &[u8]) -> Result<(Vec<u8>, String, IpAddr)> {
        use crate::dns;
        let message = dns::parse_data_to_dns_message(data, false)?;
        let qname = dns::extract_domain_from_dns_message(&message)?;
        let ip = self.find_or_allocate_ip(qname.clone())?;
        let message = dns::build_dns_response(message, &qname, ip, 5)?;
        Ok((message.to_vec()?, qname, ip))
    }

    fn increment_ip(addr: IpAddr) -> Result<IpAddr> {
        let mut ip_bytes = match addr {
            IpAddr::V4(ip) => Vec::<u8>::from(ip.octets()),
            IpAddr::V6(ip) => Vec::<u8>::from(ip.octets()),
        };
        // Traverse bytes from right to left and stop when we can add one.
        for j in 0..ip_bytes.len() {
            let i = ip_bytes.len() - 1 - j;
            if ip_bytes[i] != 255 {
                // We can add 1 without carry and are done.
                ip_bytes[i] += 1;
                break;
            } else {
                // Zero this byte and carry over to the next one.
                ip_bytes[i] = 0;
            }
        }
        let addr = if addr.is_ipv4() {
            let bytes: [u8; 4] = ip_bytes.as_slice().try_into()?;
            IpAddr::V4(Ipv4Addr::from(bytes))
        } else {
            let bytes: [u8; 16] = ip_bytes.as_slice().try_into()?;
            IpAddr::V6(Ipv6Addr::from(bytes))
        };
        Ok(addr)
    }

    // This is to be called whenever we receive or send a packet on the socket
    // which connects the tun interface to the client, so existing IP address to name
    // mappings to not expire as long as the connection is active.
    pub fn touch_ip(&mut self, addr: &IpAddr) {
        let _ = self.lru_cache.get(addr);
    }

    pub fn resolve_ip(&mut self, addr: &IpAddr) -> Option<&String> {
        self.lru_cache.get(addr).map(|entry| &entry.name)
    }

    fn find_or_allocate_ip(&mut self, name: String) -> Result<IpAddr> {
        // This function is a search and creation function.
        // Thus, it is sufficient to canonicalize the name here.
        let insert_name = if name.ends_with('.') && !self.trailing_dot {
            String::from(name.trim_end_matches('.'))
        } else {
            name
        };

        // Return the IP if it is stored inside our name_to_ip map.
        if let Some(&ip) = self.name_to_ip.get(&insert_name) {
            self.lru_cache.get(&ip);
            return Ok(ip);
        }

        // Check if we are at capacity.
        if self.lru_cache.len() == self.lru_cache.capacity() {
            // Full, evict the LRU entry.
            if let Some((old_ip, old_entry)) = self.lru_cache.remove_lru() {
                self.name_to_ip.remove(&old_entry.name);
                let name_clone = insert_name.clone();
                self.lru_cache.insert(old_ip, NameCacheEntry { name: insert_name });
                self.name_to_ip.insert(name_clone, old_ip);
                self.next_addr = Self::increment_ip(old_ip)?;
                if self.next_addr > self.broadcast_addr || self.next_addr < self.network_addr {
                    self.next_addr = self.network_addr;
                }
                return Ok(old_ip);
            }
        }

        // Otherwise, find a vacant IP in the pool.
        let started_at = self.next_addr;
        loop {
            if let RawEntryMut::Vacant(vacant) = self.lru_cache.raw_entry_mut().from_key(&self.next_addr) {
                let name_clone = insert_name.clone();
                vacant.insert(self.next_addr, NameCacheEntry { name: insert_name });
                self.name_to_ip.insert(name_clone, self.next_addr);
                let allocated = self.next_addr;
                self.next_addr = Self::increment_ip(self.next_addr)?;
                if self.next_addr > self.broadcast_addr || self.next_addr < self.network_addr {
                    self.next_addr = self.network_addr;
                }
                return Ok(allocated);
            }
            self.next_addr = Self::increment_ip(self.next_addr)?;
            if self.next_addr > self.broadcast_addr || self.next_addr < self.network_addr {
                self.next_addr = self.network_addr;
            }
            if self.next_addr == started_at {
                // If we've looped back, treat as full and evict LRU.
                if let Some((old_ip, old_entry)) = self.lru_cache.remove_lru() {
                    self.name_to_ip.remove(&old_entry.name);
                    let name_clone = insert_name.clone();
                    self.lru_cache.insert(old_ip, NameCacheEntry { name: insert_name });
                    self.name_to_ip.insert(name_clone, old_ip);
                    self.next_addr = Self::increment_ip(old_ip)?;
                    if self.next_addr > self.broadcast_addr || self.next_addr < self.network_addr {
                        self.next_addr = self.network_addr;
                    }
                    return Ok(old_ip);
                } else {
                    return Err("Virtual IP space for DNS exhausted".into());
                }
            }
        }
    }
}
