//! Our implementation of `IVpnPlugIn` which is the bulk of the UWP VPN plugin.

use std::sync::Mutex;
use std::time::Duration;

use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Tunn, TunnResult};
use ipnetwork::IpNetwork;
use windows::{
    core::*,
    Networking::Sockets::*,
    Networking::Vpn::*,
    Networking::*,
    Win32::Foundation::{E_BOUNDS, E_INVALIDARG, E_UNEXPECTED},
};

use crate::config::WireGuardConfig;
use crate::logging::WireGuardUWPEvents;
use crate::utils::{debug_log, IBufferExt, Vector};

struct Inner {
    tunn: Option<Box<Tunn>>,
}

impl Inner {
    fn new() -> Self {
        Self { tunn: None }
    }
}

/// The VPN plugin object which provides the hooks that the UWP VPN platform will call into.
#[implement(IVpnPlugIn)]
pub struct VpnPlugin {
    inner: Mutex<Inner>,
    etw_logger: WireGuardUWPEvents,
}

impl IVpnPlugIn_Impl for VpnPlugin_Impl {
    /// Called by the platform so that we may connect and setup the VPN tunnel.
    fn Connect(&self, channel: Ref<VpnChannel>) -> Result<()> {
        // Call out to separate method so that we can capture any errors
        if let Err(err) = self.connect_inner(channel) {
            self.etw_logger
                .connect_fail(None, err.code().0 as u32, &err.to_string());
            Err(err)
        } else {
            Ok(())
        }
    }

    /// Called by the platform to indicate we should disconnect and cleanup the VPN tunnel.
    fn Disconnect(&self, channel: Ref<VpnChannel>) -> Result<()> {
        // Call out to separate method so that we can capture any errors
        if let Err(err) = self.disconnect_inner(channel) {
            self.etw_logger
                .disconnect(None, err.code().0 as u32, &err.to_string());
            Err(err)
        } else {
            self.etw_logger.disconnect(None, 0, "Operation successful.");
            Ok(())
        }
    }

    /// Called by the platform from time to time so that we may send some keepalive payload.
    ///
    /// If we decide we want to send any keepalive payload, we place it in `keepAlivePacket`.
    fn GetKeepAlivePayload(
        &self,
        channel: Ref<VpnChannel>,
        keepAlivePacket: OutRef<VpnPacketBuffer>,
    ) -> Result<()> {
        let channel = channel.as_ref().ok_or(Error::from(E_UNEXPECTED))?;

        let mut inner = self.inner.lock().unwrap();
        let tunn = if let Some(tunn) = &mut inner.tunn {
            &mut **tunn
        } else {
            // We haven't initalized tunn yet, just return
            return Ok(());
        };

        // Allocate a temporary buffer on the stack for sending any data.
        let mut dst = [0u8; 1500];

        // Any packets we need to send out?
        match tunn.update_timers(&mut dst) {
            // Nothing to do right now
            TunnResult::Done => {
                // TODO: Return unused `kaPacket` buffer
            }

            // Encountered an error, bail out
            TunnResult::Err(err) => {
                // TODO: Return unused `kaPacket` buffer
                return Err(Error::new(
                    // TODO: Better error than `E_UNEXPECTED`?
                    E_UNEXPECTED,
                    format!("update_timers error: {:?}", err),
                ));
            }

            // We got something to send to the remote
            TunnResult::WriteToNetwork(packet) => {
                // Grab a buffer for the keepalive packet
                let mut kaPacket = channel.GetVpnSendPacketBuffer()?;

                kaPacket
                    .Buffer()?
                    .SetLength(u32::try_from(packet.len()).map_err(|_| Error::from(E_BOUNDS))?)?;
                kaPacket.get_buf_mut()?.copy_from_slice(packet);

                self.etw_logger.keepalive(None, packet.len() as u32);

                // Place the packet in the out param to send to remote
                keepAlivePacket.write(Some(kaPacket))?;
                
                return Ok(())
            }

            // Impossible cases for update_timers
            TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                panic!("unexpected result from update_timers")
            }
        }

        keepAlivePacket.write(None)?;
        Ok(())
    }

    /// Called by the platform to indicate there are outgoing packets ready to be encapsulated.
    ///
    /// `packets` contains outgoing L3 IP packets that we should encapsulate in whatever protocol
    /// dependant manner before placing them in `encapsulatedPackets` so that they may be sent to
    /// the remote endpoint.
    fn Encapsulate(
        &self,
        channel: Ref<VpnChannel>,
        packets: Ref<VpnPacketBufferList>,
        encapsulatedPackets: Ref<VpnPacketBufferList>,
    ) -> Result<()> {
        // Call out to separate method so that we can capture any errors
        match self.encapsulate_inner(channel, packets, encapsulatedPackets) {
            Ok(_) => Ok(()),
            Err(err) => {
                self.etw_logger
                    .encapsulate_fail(None, err.code().0 as u32, &err.to_string());
                Err(err)
            }
        }
    }

    /// Called by the platform to indicate we've received a frame from the remote endpoint.
    ///
    /// `buffer` will contain whatever data we received from the remote endpoint which may
    /// either contain control or data payloads. For data payloads, we will decapsulate into
    /// 1 (or more) L3 IP packet(s) before returning them to the platform by placing them in
    /// `decapsulatedPackets`, making them ready to be injected into the virtual tunnel. If
    /// we need to send back control payloads or otherwise back to the remote endpoint, we
    /// may place such frames into `controlPackets`.
    fn Decapsulate(
        &self,
        channel: Ref<VpnChannel>,
        buffer: Ref<VpnPacketBuffer>,
        decapsulatedPackets: Ref<VpnPacketBufferList>,
        controlPackets: Ref<VpnPacketBufferList>,
    ) -> Result<()> {
        // Call out to separate method so that we can capture any errors
        match self.decapsulate_inner(channel, buffer, decapsulatedPackets, controlPackets) {
            Ok(_) => Ok(()),
            Err(err) => {
                self.etw_logger
                    .decapsulate_fail(None, err.code().0 as u32, &err.to_string());
                Err(err)
            }
        }
    }
}

impl VpnPlugin {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner::new()),
            etw_logger: WireGuardUWPEvents::new(),
        }
    }

    /// Internal `Connect` implementation.
    fn connect_inner(&self, channel: Ref<VpnChannel>) -> Result<()> {
        let channel = channel.as_ref().ok_or(Error::from(E_UNEXPECTED))?;
        let mut inner = self.inner.lock().unwrap();

        let config = channel.Configuration()?;

        // Grab custom config field from VPN profile and try to parse the config
        // In theory this would totally be fine to deal with as INI to match
        // most other wireguard config, but it's a bit of pain since a number of
        // places assume this will be XML...
        let wg_config = match WireGuardConfig::from_str(&config.CustomField()?.to_string()) {
            Ok(conf) => conf,
            Err(err) => {
                channel
                    .SetErrorMessage(&HSTRING::from(format!("failed to parse config: {}", err)))?;
                return Err(Error::from(E_INVALIDARG));
            }
        };

        let static_private = wg_config.interface.private_key;
        let peer_static_public = wg_config.peer.public_key;
        let persistent_keepalive = wg_config.peer.persistent_keepalive;
        let preshared_key = wg_config.peer.preshared_key;

        // Grab interface addresses
        let iface_addrs = wg_config.interface.address;
        // Now massage em into the right form
        let (ipv4, ipv6) = iface_addrs
            .into_iter()
            .partition::<Vec<_>, _>(IpNetwork::is_ipv4);
        let ipv4_addrs = ipv4
            .into_iter()
            .map(|ip| HostName::CreateHostName(&HSTRING::from(ip.ip().to_string())))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .map(Some)
            .collect::<Vec<_>>();
        let ipv4_addrs = if ipv4_addrs.is_empty() {
            None
        } else {
            Some(Vector::<HostName>::new(ipv4_addrs).GetView()?)
        };
        let ipv6_addrs = ipv6
            .into_iter()
            .map(|ip| HostName::CreateHostName(&HSTRING::from(ip.ip().to_string())))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .map(Some)
            .collect::<Vec<_>>();
        let ipv6_addrs = if ipv6_addrs.is_empty() {
            None
        } else {
            Some(Vector::<HostName>::new(ipv6_addrs).GetView()?)
        };

        let build_routes = |routes: Vec<IpNetwork>| -> Result<_> {
            let mut ipv4 = vec![];
            let mut ipv6 = vec![];

            for ip in routes {
                let route = VpnRoute::CreateVpnRoute(
                    &HostName::CreateHostName(&HSTRING::from(ip.network().to_string()))?,
                    ip.prefix(),
                )?;
                if ip.is_ipv4() {
                    ipv4.push(Some(route));
                } else {
                    ipv6.push(Some(route));
                }
            }

            Ok((ipv4, ipv6))
        };

        let routes = VpnRouteAssignment::new()?;

        // Grab AllowedIPs and build routes from it
        let (allowed_ipv4, allowed_ipv6) = build_routes(wg_config.peer.allowed_ips)?;

        if !allowed_ipv4.is_empty() {
            routes.SetIpv4InclusionRoutes(&Vector::new(allowed_ipv4))?;
        }
        if !allowed_ipv6.is_empty() {
            routes.SetIpv6InclusionRoutes(&Vector::new(allowed_ipv6))?;
        }

        // Grab ExcludedIPs to determine exclusion routes
        let (excluded_ipv4, excluded_ipv6) = build_routes(wg_config.peer.excluded_ips)?;

        if !excluded_ipv4.is_empty() {
            routes.SetIpv4ExclusionRoutes(&Vector::new(excluded_ipv4))?;
        }
        if !excluded_ipv6.is_empty() {
            routes.SetIpv6ExclusionRoutes(&Vector::new(excluded_ipv6))?;
        }

        // Setup DNS
        let namespace_assignment = VpnNamespaceAssignment::new()?;
        let dns_servers = wg_config
            .interface
            .dns_servers
            .into_iter()
            .map(|server| HostName::CreateHostName(&HSTRING::from(server.to_string())))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .map(Some)
            .collect::<Vec<_>>();
        let search_domains = wg_config.interface.search_domains;

        let namespace_count = search_domains.len() + !dns_servers.is_empty() as usize;
        let mut namespaces = Vec::with_capacity(namespace_count);

        // Add the search domains as suffix NRPT rules so that
        // they get added to the virtual interface's
        // Connection-Specific DNS Suffix Search List.
        for mut search_domain in search_domains {
            // Prefix with . to make it a suffix rule
            search_domain.insert(0, '.');
            let dns_servers = Vector::new(dns_servers.clone());
            let namespace = VpnNamespaceInfo::CreateVpnNamespaceInfo(
                &HSTRING::from(search_domain),
                &dns_servers,
                None,
            )?;
            namespaces.push(Some(namespace));
        }

        if !dns_servers.is_empty() {
            // We set the namespace name to '.' so it applies to everything instead of
            // a specific set of domains (see NRPT)
            let dns_servers = Vector::new(dns_servers);
            let namespace =
                VpnNamespaceInfo::CreateVpnNamespaceInfo(&HSTRING::from("."), &dns_servers, None)?;
            namespaces.push(Some(namespace));
        }

        namespace_assignment.SetNamespaceList(&Vector::new(namespaces))?;

        // Create WG tunnel object
        let tunn = Tunn::new(
            static_private,
            peer_static_public,
            preshared_key,
            persistent_keepalive,
            rand::random(), // Our sender index. Needs to be a pseudorandom number.
            None,           // TODO: No rate limiter
        );

        // Stuff it into our inner state
        // Just forget the previous tunn state and start over (if one exists at all)
        if let Some(_) = std::mem::replace(&mut inner.tunn, Some(Box::new(tunn))) {
            debug_log!("Replacing leftover tunn state.");
        }

        // Create socket and register with VPN platform
        let sock = DatagramSocket::new()?;
        channel.AddAndAssociateTransport(&sock, None)?;

        // Just use the first server listed to connect to remote endpoint
        let server = config.ServerHostNameList()?.GetAt(0)?;
        let port = wg_config.peer.port;

        debug_log!("Server: {} Port: {}", server.ToString()?.to_string(), port);

        // We "block" here with the call to `.get()` but given this is a UDP socket
        // connect isn't actually something that will hang (DNS aside perhaps?).
        sock.ConnectAsync(&server, &HSTRING::from(port.to_string()))?
            .get()?;

        // Kick off the VPN setup
        channel.Start(
            ipv4_addrs.as_ref(),
            ipv6_addrs.as_ref(),
            None, // Interface ID portion of IPv6 address for VPN tunnel
            &routes,
            &namespace_assignment,
            1500,  // MTU size of VPN tunnel interface
            1600,  // Max frame size of incoming buffers from remote endpoint
            false, // Disable low cost network monitoring
            &sock, // Pass in the socket to the remote endpoint
            None,  // No secondary socket used.
        )?;

        // Log successful connection
        self.etw_logger
            .connected(None, &server.ToString()?.to_string(), port);

        Ok(())
    }

    /// Internal `Disconnect` implementation.
    fn disconnect_inner(&self, channel: Ref<VpnChannel>) -> Result<()> {
        let channel = channel.as_ref().ok_or(Error::from(E_UNEXPECTED))?;

        let mut inner = self.inner.lock().unwrap();
        inner.tunn = None;

        channel.Stop()?;

        Ok(())
    }

    fn encapsulate_inner(
        &self,
        channel: Ref<VpnChannel>,
        packets: Ref<VpnPacketBufferList>,
        encapsulatedPackets: Ref<VpnPacketBufferList>,
    ) -> Result<()> {
        let channel = channel.as_ref().ok_or(Error::from(E_UNEXPECTED))?;
        let packets = packets.as_ref().ok_or(Error::from(E_UNEXPECTED))?;
        let encapsulatedPackets = encapsulatedPackets
            .as_ref()
            .ok_or(Error::from(E_UNEXPECTED))?;

        let mut inner = self.inner.lock().unwrap();
        let tunn = if let Some(tunn) = &mut inner.tunn {
            &mut **tunn
        } else {
            // We haven't initalized tunn yet, just return
            return Ok(());
        };

        let mut ret_buffers = vec![];
        let mut encap_err = None;

        // Usually this would be called in the background by some periodic timer
        // but a UWP VPN plugin will get suspended if there's no traffic and that
        // includes any background threads or such we could create.
        // So we may find ourselves with a stale session and need to do a new
        // handshake. Thus, we just call this opportunistically here before
        // trying to encapsulate.
        if tunn.time_since_last_handshake() >= Some(Duration::from_millis(250)) {
            const HANDSHAKE_INIT_SZ: usize = 148;
            let mut handshake_buf = [0u8; HANDSHAKE_INIT_SZ];
            match tunn.update_timers(&mut handshake_buf) {
                // Session still valid, nothing more to do.
                TunnResult::Done => (),

                // Encountered an error, bail out
                TunnResult::Err(err) => {
                    return Err(Error::new(
                        E_UNEXPECTED,
                        format!("update_timers error: {:?}", err),
                    ));
                }

                // Looks like we need to get things updated
                TunnResult::WriteToNetwork(packet) => {
                    // Request a new buffer
                    let mut handshake_buffer = channel.GetVpnSendPacketBuffer()?;
                    handshake_buffer.Buffer()?.SetLength(
                        u32::try_from(packet.len()).map_err(|_| Error::from(E_BOUNDS))?,
                    )?;

                    // Copy data over and update length on WinRT buffer
                    handshake_buffer.get_buf_mut()?.copy_from_slice(packet);

                    // Now queue it up to be sent
                    encapsulatedPackets.Append(&handshake_buffer)?;
                }

                // Impossible cases for update_timers
                TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                    panic!("unexpected result from update_timers");
                }
            }
        }

        let packets_sz = packets.Size()?;
        self.etw_logger.encapsulate_begin(None, packets_sz);

        // Process outgoing packets from VPN tunnel.
        // TODO: Not using the simpler `for packet in packets` because
        //       `packets.First()?` fails with E_NOINTERFACE for some reason.
        for _ in 0..packets_sz {
            let packet = packets.RemoveAtBegin()?;
            let src = packet.get_buf()?;

            // Grab a destination buffer for the encapsulated packet
            let mut encapPacket = channel.GetVpnSendPacketBuffer()?;

            // Maximize the buffer's length to its capacity.
            encapPacket
                .Buffer()?
                .SetLength(encapPacket.Buffer()?.Capacity()?)?;
            let dst = encapPacket.get_buf_mut()?;

            // Try to encapsulate packet
            let res = tunn.encapsulate(src, dst);

            if let TunnResult::WriteToNetwork(packet) = res {
                // Packet was encap'd successfully, make sure to update length on the WinRT side
                let new_len = u32::try_from(packet.len()).map_err(|_| Error::from(E_BOUNDS))?;
                // drop(packet);
                encapPacket.Buffer()?.SetLength(new_len)?;

                // Now, tack it onto `encapsulatedPackets` to send to remote endpoint
                encapsulatedPackets.Append(&encapPacket)?;
            } else {
                match res {
                    // Handled above
                    TunnResult::WriteToNetwork(_) => {}

                    // Packet was queued while we complete the handshake
                    TunnResult::Done => {}

                    // Encountered an error while trying to encapsulate
                    TunnResult::Err(err) => {
                        if encap_err.is_none() {
                            encap_err =
                                Some(Error::new(E_UNEXPECTED, format!("encap error: {:?}", err)));
                        }
                    }

                    // Impossible cases for encapsulate
                    TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                        panic!("unexpected result from encapsulate")
                    }
                }

                // We must return the `encapPacket` we requested
                ret_buffers.push(encapPacket);
            }

            // Note: this loop does not consume the items in packets which is important
            //       as ANY `VpnPacketBuffer` we get (whether as some argument to a `IVpnPlugIn`
            //       method or via methods on `VpnChannel`) we are expected to return to the
            //       platform. Since we're not en/decapsulating in-place, it works out to leave
            //       the buffers in `packets` so that the platform may clean them up.
            packets.Append(&packet)?;
        }

        self.etw_logger
            .encapsulate_end(None, encapsulatedPackets.Size()?);

        // Just stick the unneeded buffers onto `packets` so the platform can clean them up
        for packet in ret_buffers {
            packets.Append(&packet)?;
        }

        // If we encountered an error, return it
        if let Some(err) = encap_err {
            Err(err)
        } else {
            Ok(())
        }
    }

    fn decapsulate_inner(
        &self,
        channel: Ref<VpnChannel>,
        buffer: Ref<VpnPacketBuffer>,
        decapsulatedPackets: Ref<VpnPacketBufferList>,
        controlPackets: Ref<VpnPacketBufferList>,
    ) -> Result<()> {
        let channel = channel.as_ref().ok_or(Error::from(E_UNEXPECTED))?;
        let buffer = buffer.as_ref().ok_or(Error::from(E_UNEXPECTED))?;
        let decapsulatedPackets = decapsulatedPackets
            .as_ref()
            .ok_or(Error::from(E_UNEXPECTED))?;
        let controlPackets = controlPackets.as_ref().ok_or(Error::from(E_UNEXPECTED))?;

        let mut inner = self.inner.lock().unwrap();
        let tunn = if let Some(tunn) = &mut inner.tunn {
            &mut **tunn
        } else {
            // We haven't initalized tunn yet, just return
            return Ok(());
        };

        self.etw_logger
            .decapsulate_begin(None, buffer.Buffer()?.Length()?);

        // Allocate a temporary buffer on the stack for the decapsulated packet.
        let mut dst = [0u8; 1500];

        // Get a slice to the datagram we just received from the remote endpoint and try to decap
        let datagram = buffer.get_buf()?;
        let res = tunn.decapsulate(None, datagram, &mut dst);

        match res {
            // Nothing to do with this decap result
            TunnResult::Done => {
                // TODO: Return unused `decapPacket` buffer
            }

            // DD-WRT sometimes sends us packets that are destined for someone else?
            // Either way, just ignore the packet.
            TunnResult::Err(WireGuardError::WrongIndex) => {}

            // Encountered an error while trying to decapsulate
            TunnResult::Err(err) => {
                // TODO: Return unused `decapPacket` buffer
                return Err(Error::new(E_UNEXPECTED, format!("decap error: {:?}", err)));
            }

            // We need to send at least one response back to remote endpoint
            TunnResult::WriteToNetwork(packet) => {
                let mut res = TunnResult::WriteToNetwork(packet);
                while let TunnResult::WriteToNetwork(packet) = res {
                    // Allocate a buffer for the decapsulate packet
                    let mut controlPacket = channel.GetVpnSendPacketBuffer()?;

                    // Set the buffer's length.
                    controlPacket.Buffer()?.SetLength(
                        u32::try_from(packet.len()).map_err(|_| Error::from(E_BOUNDS))?,
                    )?;

                    // Now copy the output buffer.
                    controlPacket.get_buf_mut()?.copy_from_slice(packet);

                    // Tack onto `controlPackets` so that they get sent to remote endpoint
                    controlPackets.Append(&controlPacket)?;

                    // Probe for more packets to send.
                    res = tunn.decapsulate(None, &[], &mut dst);
                }
            }

            // Successfully decapsulated data packet
            TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                // Allocate a buffer for the decapsulate packet
                let mut decapPacket = channel.GetVpnReceivePacketBuffer()?;

                // Make sure to update length on WinRT buffer
                let new_len = u32::try_from(packet.len()).map_err(|_| Error::from(E_BOUNDS))?;
                decapPacket.Buffer()?.SetLength(new_len)?;

                // Now copy the output buffer.
                decapPacket.get_buf_mut()?.copy_from_slice(packet);

                // Tack onto `decapsulatedPackets` to inject into VPN interface
                decapsulatedPackets.Append(&decapPacket)?;
            }
        }

        self.etw_logger
            .decapsulate_end(None, decapsulatedPackets.Size()?, controlPackets.Size()?);

        Ok(())
    }
}
