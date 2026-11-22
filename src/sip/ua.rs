use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tracing::{debug, info, trace};

use super::client::{Client, ClientConfig};
use super::dialog::{build_sip_response, SipDialogUAC, SipDialogUAS};
use super::message::Message;
use crate::config::Config;
use crate::dialog::Dialog;
use crate::error::{Error, Result};
use crate::transport::SipTransport;

#[allow(clippy::type_complexity)]
struct Inner {
    drop_handler: Option<Arc<dyn Fn() + Send + Sync>>,
    incoming_handler: Option<Arc<dyn Fn(String, String) + Send + Sync>>,
    dialog_invite_handler:
        Option<Arc<dyn Fn(Arc<dyn Dialog>, String, String, String) + Send + Sync>>,
    bye_handler: Option<Arc<dyn Fn(String) + Send + Sync>>,
    notify_handler: Option<Arc<dyn Fn(String, u16) + Send + Sync>>,
    info_dtmf_handler: Option<Arc<dyn Fn(String, String) + Send + Sync>>,
    mwi_notify_handler: Option<Arc<dyn Fn(String) + Send + Sync>>,
    message_handler: Option<Arc<dyn Fn(String, String, String) + Send + Sync>>,
    subscription_notify_handler:
        Option<Arc<dyn Fn(String, String, String, String, String) + Send + Sync>>,
}

/// Production SIP transport backed by `sip::client::Client`.
/// Implements the `SipTransport` trait for real network communication.
pub struct SipUA {
    client: Mutex<Option<ClientState>>,
    cfg: Config,
    inner: Arc<Mutex<Inner>>,
}

struct ClientState {
    client: Arc<Client>,
    reconnect: bool,
}

impl std::fmt::Debug for SipUA {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SipUA").finish()
    }
}

impl SipUA {
    /// Creates a new SipUA from a phone Config.
    pub fn new(cfg: &Config) -> Result<Self> {
        if cfg.host.is_empty() {
            return Err(Error::HostRequired);
        }

        // Validate transport.
        let transport = cfg.transport.to_lowercase();
        match transport.as_str() {
            "udp" | "tcp" | "tls" => {}
            other => {
                return Err(Error::Other(format!(
                    "xphone: unsupported transport: {}",
                    other
                )));
            }
        }

        if transport == "tls" && cfg.tls_config.is_none() {
            return Err(Error::TlsConfigRequired);
        }

        let inner = Arc::new(Mutex::new(Inner {
            drop_handler: None,
            incoming_handler: None,
            dialog_invite_handler: None,
            bye_handler: None,
            notify_handler: None,
            info_dtmf_handler: None,
            mwi_notify_handler: None,
            message_handler: None,
            subscription_notify_handler: None,
        }));

        let client = Self::connect_client(cfg, &inner)?;
        Ok(Self {
            client: Mutex::new(Some(ClientState {
                client,
                reconnect: false,
            })),
            cfg: cfg.clone(),
            inner,
        })
    }

    fn connect_client(cfg: &Config, inner: &Arc<Mutex<Inner>>) -> Result<Arc<Client>> {
        let mut server_addrs_iter = format!("{}:{}", cfg.host, cfg.port)
            .to_socket_addrs()
            .map_err(|e| Error::Other(format!("invalid server address: {}", e)))?;
        let server_addr = server_addrs_iter
            .next()
            .ok_or_else(|| Error::Other(format!("server address not resolvable: {}", cfg.host)))?;

        trace!(server_addr = %server_addr, "Resolved server address");

        // Resolve the configured next hop again when replacing the socket.
        let outbound_proxy = cfg
            .outbound_proxy
            .as_deref()
            .map(|uri| {
                parse_proxy_uri(uri)
                    .ok_or_else(|| Error::Other(format!("unable to resolve outbound proxy: {uri}")))
            })
            .transpose()?;

        let client_cfg = ClientConfig {
            // Intentionally NOT plumbed from `Config::local_ip` / any
            // `rtp_address` override. Contact/Via must stay on the socket the
            // OS actually bound; media-side overrides (SDP `c=`) happen at
            // SDP build time, not here. Plumbing a user-supplied IP here
            // would rewrite Contact with the ephemeral bound SIP port (not
            // NAT-forwarded), silently breaking inbound signaling behind NAT.
            local_addr: "0.0.0.0:0".into(),
            server_addr,
            username: cfg.username.clone(),
            password: cfg.password.clone(),
            auth_username: cfg.auth_username.clone(),
            domain: cfg.host.clone(),
            transport: cfg.transport.to_lowercase(),
            tls_config: cfg.tls_config.clone(),
            stun_server: cfg.stun_server.clone(),
            outbound_proxy,
            outbound_username: cfg.outbound_username.clone(),
            outbound_password: cfg.outbound_password.clone(),
            user_agent: cfg.user_agent.clone(),
            nat: cfg.nat,
        };

        let client = Arc::new(Client::new(client_cfg)?);

        // Reattach the application's handlers to each new socket. The reader
        // must not keep its own client alive.
        let inner_clone = Arc::clone(inner);
        let weak_client = Arc::downgrade(&client);
        client.on_incoming(move |msg, addr| {
            if let Some(client) = weak_client.upgrade() {
                handle_incoming_request(&inner_clone, &client, &msg, addr);
            }
        });
        let inner_clone = Arc::clone(inner);
        client.on_drop(move || {
            let handler = inner_clone.lock().drop_handler.clone();
            if let Some(handler) = handler {
                handler();
            }
        });

        Ok(client)
    }

    fn client(&self) -> Result<Arc<Client>> {
        self.client
            .lock()
            .as_ref()
            .map(|state| Arc::clone(&state.client))
            .ok_or_else(|| Error::Other("sip: client closed".into()))
    }

    fn registration_client(&self) -> Result<Arc<Client>> {
        let mut guard = self.client.lock();
        let state = guard
            .as_mut()
            .ok_or_else(|| Error::Other("sip: client closed".into()))?;
        if !state.reconnect && !state.client.has_transport_failure() {
            return Ok(Arc::clone(&state.client));
        }

        let replacement = Self::connect_client(&self.cfg, &self.inner)?;
        let previous = std::mem::replace(&mut state.client, Arc::clone(&replacement));
        state.reconnect = false;
        drop(guard);
        previous.close();
        Ok(replacement)
    }

    fn reconnect_after_error(&self, client: &Arc<Client>) {
        if let Some(state) = self.client.lock().as_mut() {
            if Arc::ptr_eq(&state.client, client) {
                state.reconnect = true;
            }
        }
    }
}

fn handle_incoming_request(
    inner: &Arc<Mutex<Inner>>,
    client: &Arc<Client>,
    msg: &Message,
    from_addr: SocketAddr,
) {
    debug!(method = %msg.method, from = %from_addr, "SIP <<< incoming request");
    match msg.method.as_str() {
        "INVITE" => handle_invite(inner, client, msg, from_addr),
        "BYE" => handle_bye(inner, client, msg, from_addr),
        "CANCEL" => handle_cancel(inner, client, msg, from_addr),
        "ACK" => {
            debug!("SIP <<< ACK received");
        }
        "NOTIFY" => handle_notify(inner, client, msg, from_addr),
        "INFO" => handle_info(inner, client, msg, from_addr),
        "MESSAGE" => handle_message(inner, client, msg, from_addr),
        "OPTIONS" => {
            debug!("SIP <<< OPTIONS keepalive, responding 200 OK");
            let resp = build_sip_response(msg, 200, "OK");
            let _ = client.send_raw_to(&resp.to_bytes(), from_addr);
        }
        other => {
            debug!(method = other, "SIP <<< unhandled request");
        }
    }
}

fn handle_invite(
    inner: &Arc<Mutex<Inner>>,
    client: &Arc<Client>,
    msg: &Message,
    from_addr: SocketAddr,
) {
    let from = msg.header("From").to_string();
    let to = msg.header("To").to_string();
    let remote_sdp = String::from_utf8_lossy(&msg.body).to_string();

    info!(from = %from, to = %to, call_id = %msg.header("Call-ID"), "SIP <<< incoming INVITE");

    // Send 100 Trying immediately to stop INVITE retransmissions.
    let trying = build_sip_response(msg, 100, "Trying");
    debug!("SIP >>> 100 Trying");
    let _ = client.send_raw_to(&trying.to_bytes(), from_addr);

    // Check for dialog-based handler first.
    let dialog_handler = inner.lock().dialog_invite_handler.clone();
    if let Some(handler) = dialog_handler {
        let dlg = Arc::new(SipDialogUAS::new(
            Arc::clone(client),
            msg.clone(),
            from_addr,
        ));
        handler(dlg as Arc<dyn Dialog>, from, to, remote_sdp);
        return;
    }

    // Fall back to simple (from, to) handler for backward compatibility.
    let cb = inner.lock().incoming_handler.clone();
    if let Some(f) = cb {
        f(from, to);
    }
}

fn handle_bye(
    inner: &Arc<Mutex<Inner>>,
    client: &Arc<Client>,
    msg: &Message,
    from_addr: SocketAddr,
) {
    let call_id = msg.header("Call-ID").to_string();
    info!(call_id = %call_id, "SIP <<< BYE received");

    // Always respond 200 OK to BYE to stop retransmissions.
    let resp = build_sip_response(msg, 200, "OK");
    debug!("SIP >>> 200 OK (BYE)");
    let _ = client.send_raw_to(&resp.to_bytes(), from_addr);

    // Fire BYE handler with Call-ID.
    let cb = inner.lock().bye_handler.clone();
    if let Some(f) = cb {
        f(call_id);
    }
}

fn handle_cancel(
    inner: &Arc<Mutex<Inner>>,
    client: &Arc<Client>,
    msg: &Message,
    from_addr: SocketAddr,
) {
    let call_id = msg.header("Call-ID").to_string();
    info!(call_id = %call_id, "SIP <<< CANCEL received");

    // Respond 200 OK to CANCEL to stop retransmissions.
    let resp = build_sip_response(msg, 200, "OK");
    debug!("SIP >>> 200 OK (CANCEL)");
    let _ = client.send_raw_to(&resp.to_bytes(), from_addr);

    // Also send 487 Request Terminated for the original INVITE.
    let mut terminated = build_sip_response(msg, 487, "Request Terminated");
    // The 487 should use the original INVITE's CSeq, not the CANCEL's.
    // Since CANCEL has the same Call-ID, branch, and CSeq method=INVITE,
    // we can reconstruct it.
    let (cseq_num, _) = msg.cseq();
    terminated.set_header("CSeq", &format!("{} INVITE", cseq_num));
    debug!("SIP >>> 487 Request Terminated");
    let _ = client.send_raw_to(&terminated.to_bytes(), from_addr);

    // Fire BYE handler with Call-ID to terminate the ringing call.
    let cb = inner.lock().bye_handler.clone();
    if let Some(f) = cb {
        f(call_id);
    }
}

fn handle_notify(
    inner: &Arc<Mutex<Inner>>,
    client: &Arc<Client>,
    msg: &Message,
    from_addr: SocketAddr,
) {
    let call_id = msg.header("Call-ID").to_string();
    let event = msg.header("Event").to_string();
    info!(call_id = %call_id, event = %event, "SIP <<< NOTIFY received");

    // Always respond 200 OK to NOTIFY.
    let resp = build_sip_response(msg, 200, "OK");
    debug!("SIP >>> 200 OK (NOTIFY)");
    let _ = client.send_raw_to(&resp.to_bytes(), from_addr);

    let content_type = msg.header("Content-Type").to_string();
    let body = String::from_utf8_lossy(&msg.body).to_string();
    let sub_state = msg.header("Subscription-State").to_string();

    // Dispatch by Event header (RFC 6665).
    let event_base = event.split(';').next().unwrap_or("").trim();
    if event_base.eq_ignore_ascii_case("message-summary") {
        // MWI NOTIFY (RFC 3842).
        let cb = inner.lock().mwi_notify_handler.clone();
        if let Some(f) = cb {
            f(body);
        }
        return;
    }

    // Subscription NOTIFYs (dialog, presence, etc.) — dispatch to subscription manager.
    if !event_base.is_empty() && !event_base.eq_ignore_ascii_case("refer") {
        let from_uri = msg.header("From").to_string();
        let cb = inner.lock().subscription_notify_handler.clone();
        if let Some(f) = cb {
            f(event, content_type, body, sub_state, from_uri);
        }
        return;
    }

    // Fallback: REFER progress (sipfrag body) or legacy Content-Type based dispatch.
    let media_type = content_type.split(';').next().unwrap_or("").trim();
    if media_type.eq_ignore_ascii_case("application/simple-message-summary") {
        let cb = inner.lock().mwi_notify_handler.clone();
        if let Some(f) = cb {
            f(body);
        }
        return;
    }

    let status_code = parse_sipfrag_status(&body);
    if let Some(code) = status_code {
        let cb = inner.lock().notify_handler.clone();
        if let Some(f) = cb {
            f(call_id, code);
        }
    }
}

fn handle_info(
    inner: &Arc<Mutex<Inner>>,
    client: &Arc<Client>,
    msg: &Message,
    from_addr: SocketAddr,
) {
    let call_id = msg.header("Call-ID").to_string();
    debug!(call_id = %call_id, "SIP <<< INFO received");

    // Always respond 200 OK to INFO.
    let resp = build_sip_response(msg, 200, "OK");
    debug!("SIP >>> 200 OK (INFO)");
    let _ = client.send_raw_to(&resp.to_bytes(), from_addr);

    // Only process application/dtmf-relay bodies.
    let content_type = msg.header("Content-Type");
    if !content_type
        .to_ascii_lowercase()
        .contains("application/dtmf-relay")
    {
        debug!(content_type = %content_type, "INFO: ignoring non-dtmf-relay body");
        return;
    }

    let body = String::from_utf8_lossy(&msg.body);
    if let Some(digit) = parse_dtmf_relay(&body) {
        // Normalize lowercase a-d to uppercase for RFC 4733 compatibility.
        let digit = digit.to_ascii_uppercase();
        // Validate the digit before passing to callbacks.
        if crate::dtmf::digit_to_code(&digit).is_none() {
            debug!(digit = %digit, "INFO: ignoring invalid DTMF digit");
            return;
        }
        info!(call_id = %call_id, digit = %digit, "SIP <<< INFO DTMF");
        let cb = inner.lock().info_dtmf_handler.clone();
        if let Some(f) = cb {
            f(call_id, digit);
        }
    }
}

fn handle_message(
    inner: &Arc<Mutex<Inner>>,
    client: &Arc<Client>,
    msg: &Message,
    from_addr: SocketAddr,
) {
    info!("SIP <<< MESSAGE received");

    // Always respond 200 OK to MESSAGE.
    let resp = build_sip_response(msg, 200, "OK");
    debug!("SIP >>> 200 OK (MESSAGE)");
    let _ = client.send_raw_to(&resp.to_bytes(), from_addr);

    let from = msg.header("From").to_string();
    let content_type = msg.header("Content-Type").to_string();
    let body = String::from_utf8_lossy(&msg.body).to_string();

    let cb = inner.lock().message_handler.clone();
    if let Some(f) = cb {
        f(from, content_type, body);
    }
}

/// Parses the Signal value from an `application/dtmf-relay` body.
/// Case-insensitive key matching for PBX interop.
/// Example body: "Signal=5\r\nDuration=160\r\n" → Some("5")
fn parse_dtmf_relay(body: &str) -> Option<String> {
    for line in body.lines() {
        let line = line.trim();
        if let Some(eq_pos) = line.find('=') {
            let key = line[..eq_pos].trim();
            if key.eq_ignore_ascii_case("signal") {
                let val = line[eq_pos + 1..].trim();
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

/// Parses the status code from a message/sipfrag body.
/// Example: "SIP/2.0 200 OK" → Some(200)
fn parse_sipfrag_status(body: &str) -> Option<u16> {
    let line = body.lines().next()?.trim();
    if line.starts_with("SIP/") {
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() >= 2 {
            return parts[1].parse().ok();
        }
    }
    None
}

impl SipTransport for SipUA {
    fn send_request(
        &self,
        method: &str,
        _headers: Option<&HashMap<String, String>>,
        timeout: Duration,
    ) -> Result<Message> {
        if method == "REGISTER" {
            let client = self.registration_client()?;
            let (code, reason) = client.send_register(timeout).inspect_err(|_| {
                self.reconnect_after_error(&client);
            })?;
            let msg = Message::new_response(code, &reason);
            return Ok(msg);
        }

        Err(Error::Other(format!(
            "sip: method {} not supported via send_request, use dial() for INVITE",
            method
        )))
    }

    fn read_response(&self, _timeout: Duration) -> Result<Message> {
        Err(Error::Other(
            "sip: read_response not used in production transport".into(),
        ))
    }

    fn send_keepalive(&self) -> Result<()> {
        let client = self.client()?;
        client.send_keepalive().inspect_err(|_| {
            self.reconnect_after_error(&client);
        })
    }

    fn respond(&self, _code: u16, _reason: &str) {
        // Responses now handled via Dialog.respond() in production.
    }

    fn on_drop(&self, f: Box<dyn Fn() + Send + Sync>) {
        self.inner.lock().drop_handler = Some(Arc::from(f));
    }

    fn on_incoming(&self, f: Box<dyn Fn(String, String) + Send + Sync>) {
        self.inner.lock().incoming_handler = Some(Arc::from(f));
    }

    fn dial(
        &self,
        target: &str,
        local_sdp: &[u8],
        timeout: Duration,
        opts: &crate::config::DialOptions,
    ) -> Result<crate::transport::DialResult> {
        let client = self.client()?;
        // Normalize target to SIP URI.
        let target_uri = if target.starts_with("sip:") {
            target.to_string()
        } else {
            format!("sip:{}@{}", target, client.domain())
        };

        info!(target = %target_uri, "SIP >>> dialing");

        // Build extra headers from DialOptions (caller_id, custom_headers).
        let mut extra = HashMap::new();
        if let Some(ref cid) = opts.caller_id {
            // If caller_id is already a SIP URI (contains @), use as-is.
            // Otherwise, format with the configured domain.
            let pai = if cid.contains('@') {
                if cid.starts_with('<') {
                    cid.clone()
                } else {
                    format!("<{cid}>")
                }
            } else {
                format!("<sip:{}@{}>", cid, client.domain())
            };
            extra.insert("P-Asserted-Identity".to_string(), pai);
        }
        for (k, v) in &opts.custom_headers {
            extra.insert(k.clone(), v.clone());
        }
        let extra_ref = if extra.is_empty() { None } else { Some(&extra) };

        let auth_override = &opts.auth;

        let result = client.send_invite_cancellable(
            &target_uri,
            local_sdp,
            timeout,
            extra_ref,
            auth_override.as_ref(),
            opts.cancellation.as_ref(),
        )?;
        let remote_sdp = String::from_utf8_lossy(&result.response.body).to_string();
        info!(
            status = result.response.status_code,
            "SIP <<< INVITE final response"
        );

        let dlg = Arc::new(SipDialogUAC::new(client, result.invite, result.response));

        // A final 2xx may cross CANCEL on the wire. The client has
        // acknowledged it; end the established dialog immediately.
        if opts
            .cancellation
            .as_ref()
            .is_some_and(crate::DialCancellation::is_cancelled)
        {
            dlg.send_bye()?;
            return Err(Error::DialCancelled);
        }

        Ok(crate::transport::DialResult {
            dialog: dlg as Arc<dyn Dialog>,
            remote_sdp,
            early_sdp: result.early_sdp,
        })
    }

    fn on_dialog_invite(
        &self,
        f: Box<dyn Fn(Arc<dyn Dialog>, String, String, String) + Send + Sync>,
    ) {
        self.inner.lock().dialog_invite_handler = Some(Arc::from(f));
    }

    fn on_bye(&self, f: Box<dyn Fn(String) + Send + Sync>) {
        self.inner.lock().bye_handler = Some(Arc::from(f));
    }

    fn on_notify(&self, f: Box<dyn Fn(String, u16) + Send + Sync>) {
        self.inner.lock().notify_handler = Some(Arc::from(f));
    }

    fn on_info_dtmf(&self, f: Box<dyn Fn(String, String) + Send + Sync>) {
        self.inner.lock().info_dtmf_handler = Some(Arc::from(f));
    }

    fn send_subscribe(
        &self,
        uri: &str,
        headers: &HashMap<String, String>,
        timeout: Duration,
    ) -> Result<Message> {
        let (code, reason) = self.client()?.send_subscribe(uri, headers, timeout)?;
        let msg = Message::new_response(code, &reason);
        Ok(msg)
    }

    fn on_mwi_notify(&self, f: Box<dyn Fn(String) + Send + Sync>) {
        self.inner.lock().mwi_notify_handler = Some(Arc::from(f));
    }

    fn send_message(
        &self,
        target: &str,
        content_type: &str,
        body: &[u8],
        timeout: Duration,
    ) -> Result<()> {
        let client = self.client()?;
        // Normalize target to SIP URI.
        let target_uri = if target.starts_with("sip:") {
            target.to_string()
        } else {
            format!("sip:{}@{}", target, client.domain())
        };

        let (code, reason) = client.send_message(&target_uri, content_type, body, timeout)?;
        if (200..300).contains(&code) {
            Ok(())
        } else {
            Err(Error::Other(format!(
                "MESSAGE rejected: {} {}",
                code, reason
            )))
        }
    }

    fn on_message(&self, f: Box<dyn Fn(String, String, String) + Send + Sync>) {
        self.inner.lock().message_handler = Some(Arc::from(f));
    }

    fn on_subscription_notify(
        &self,
        f: Box<dyn Fn(String, String, String, String, String) + Send + Sync>,
    ) {
        self.inner.lock().subscription_notify_handler = Some(Arc::from(f));
    }

    fn unregister(&self, timeout: Duration) -> Result<()> {
        let _ = self.client()?.send_unregister(timeout)?;
        Ok(())
    }

    fn advertised_addr(&self) -> Option<std::net::SocketAddr> {
        self.client().ok().map(|client| client.local_addr())
    }

    fn close(&self) -> Result<()> {
        let state = self.client.lock().take();
        if let Some(state) = state {
            state.client.close();
        }
        Ok(())
    }
}

/// Parse a SIP proxy URI to a `SocketAddr`. Strips `sip:`/`sips:` scheme
/// and delegates to `sip::resolve_host` for address resolution.
fn parse_proxy_uri(uri: &str) -> Option<SocketAddr> {
    let default_port: u16 = if uri.starts_with("sips:") { 5061 } else { 5060 };
    let host_part = uri
        .strip_prefix("sip:")
        .or_else(|| uri.strip_prefix("sips:"))
        .unwrap_or(uri);
    super::resolve_host(host_part, default_port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phone_reregisters_on_a_new_tcp_connection_after_retry_exhaustion() {
        use std::io::{BufReader, Write};
        use std::net::{TcpListener, TcpStream};
        use std::time::Instant;

        let read_message = |stream: &mut BufReader<TcpStream>| {
            let bytes = super::super::conn::read_sip_message(stream).unwrap();
            super::super::message::parse(&bytes).unwrap()
        };
        let timeout = Duration::from_secs(5);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (drop_tx, drop_rx) = crossbeam_channel::bounded(1);
        let (recover_tx, recover_rx) = crossbeam_channel::bounded(1);
        let (options_tx, options_rx) = crossbeam_channel::bounded(1);
        let server = std::thread::spawn(move || {
            let accept = || {
                let deadline = Instant::now() + timeout;
                loop {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream.set_read_timeout(Some(timeout)).unwrap();
                            return BufReader::new(stream);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "expected a SIP connection");
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(e) => panic!("accept failed: {e}"),
                    }
                }
            };
            let respond = |stream: &mut BufReader<TcpStream>, request: &Message| {
                let response = build_sip_response(request, 200, "OK");
                stream.get_mut().write_all(&response.to_bytes()).unwrap();
            };

            let mut first = accept();
            let initial_register = read_message(&mut first);
            assert_eq!(initial_register.method, "REGISTER");
            respond(&mut first, &initial_register);
            drop_rx.recv_timeout(timeout).unwrap();
            drop(first);

            // The server stays unavailable through the first reconnect attempt.
            let mut second = accept();
            assert_eq!(read_message(&mut second).method, "REGISTER");
            drop(second);

            let mut third = accept();
            let register = read_message(&mut third);
            assert_eq!(register.method, "REGISTER");
            recover_rx.recv_timeout(timeout).unwrap();
            respond(&mut third, &register);

            let mut options = Message::new_request("OPTIONS", "sip:1001@127.0.0.1");
            options.set_header("Via", "SIP/2.0/TCP 127.0.0.1;branch=z9hG4bK-test");
            options.set_header("From", "<sip:server@127.0.0.1>;tag=server");
            options.set_header("To", "<sip:1001@127.0.0.1>");
            options.set_header("Call-ID", "options-after-reconnect");
            options.set_header("CSeq", "1 OPTIONS");
            third.get_mut().write_all(&options.to_bytes()).unwrap();
            assert_eq!(read_message(&mut third).status_code, 200);
            options_tx.send(()).unwrap();

            let unregister = read_message(&mut third);
            assert_eq!(unregister.method, "REGISTER");
            assert_eq!(unregister.header("Expires"), "0");
            respond(&mut third, &unregister);
        });

        let phone = crate::Phone::new(Config {
            host: "127.0.0.1".into(),
            port,
            username: "1001".into(),
            transport: "tcp".into(),
            register_max_retry: 1,
            register_retry: Duration::from_millis(50),
            ..Config::default()
        });
        let (registered_tx, registered_rx) = crossbeam_channel::unbounded();
        phone.on_registered(move || {
            let _ = registered_tx.send(());
        });
        let (error_tx, error_rx) = crossbeam_channel::unbounded();
        phone.on_error(move |error| {
            let _ = error_tx.send(error);
        });

        phone.connect().unwrap();
        registered_rx.recv_timeout(timeout).unwrap();
        drop_tx.send(()).unwrap();
        assert!(matches!(
            error_rx.recv_timeout(timeout).unwrap(),
            Error::RegistrationFailed { code: 0, .. }
        ));
        assert_eq!(phone.state(), crate::PhoneState::RegistrationFailed);

        recover_tx.send(()).unwrap();
        registered_rx.recv_timeout(timeout).unwrap();
        assert_eq!(phone.state(), crate::PhoneState::Registered);
        options_rx.recv_timeout(timeout).unwrap();
        phone.disconnect().unwrap();
        assert_eq!(phone.state(), crate::PhoneState::Disconnected);
        server.join().unwrap();
    }

    #[test]
    fn new_requires_host() {
        let cfg = Config::default();
        let result = SipUA::new(&cfg);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Host"));
    }

    #[test]
    fn new_with_valid_config() {
        let cfg = Config {
            host: "127.0.0.1".into(),
            port: 15060,
            username: "1001".into(),
            password: "test".into(),
            ..Config::default()
        };
        let ua = SipUA::new(&cfg).unwrap();
        ua.close().unwrap();
    }

    #[test]
    fn close_is_idempotent() {
        let cfg = Config {
            host: "127.0.0.1".into(),
            port: 15061,
            username: "1001".into(),
            password: "test".into(),
            ..Config::default()
        };
        let ua = SipUA::new(&cfg).unwrap();
        ua.close().unwrap();
        ua.close().unwrap();
    }

    #[test]
    fn unsupported_method_returns_error() {
        let cfg = Config {
            host: "127.0.0.1".into(),
            port: 15062,
            username: "1001".into(),
            password: "test".into(),
            ..Config::default()
        };
        let ua = SipUA::new(&cfg).unwrap();
        let result = ua.send_request("INVITE", None, Duration::from_secs(1));
        assert!(result.is_err());
        ua.close().unwrap();
    }

    #[test]
    fn unsupported_transport_returns_error() {
        let cfg = Config {
            host: "127.0.0.1".into(),
            port: 15064,
            transport: "sctp".into(),
            ..Config::default()
        };
        let result = SipUA::new(&cfg);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unsupported"));
    }

    #[test]
    fn tls_without_config_returns_error() {
        let cfg = Config {
            host: "127.0.0.1".into(),
            port: 15065,
            transport: "tls".into(),
            tls_config: None,
            ..Config::default()
        };
        let result = SipUA::new(&cfg);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("TLS"));
    }

    #[test]
    fn tcp_transport_accepted() {
        // TCP connect will fail (no server), but we validate the transport string is accepted.
        let cfg = Config {
            host: "127.0.0.1".into(),
            port: 15066,
            transport: "tcp".into(),
            ..Config::default()
        };
        // TCP connect will fail since no server is listening,
        // but the transport validation should pass.
        let result = SipUA::new(&cfg);
        assert!(result.is_err()); // connection refused, not "unsupported transport"
        let err = result.unwrap_err().to_string();
        assert!(
            !err.contains("unsupported"),
            "should not be unsupported transport error: {}",
            err
        );
    }

    #[test]
    fn parse_dtmf_relay_signal_digit() {
        assert_eq!(
            parse_dtmf_relay("Signal=5\r\nDuration=160\r\n"),
            Some("5".into())
        );
    }

    #[test]
    fn parse_dtmf_relay_star_and_hash() {
        assert_eq!(parse_dtmf_relay("Signal=*\r\n"), Some("*".into()));
        assert_eq!(parse_dtmf_relay("Signal=#\r\n"), Some("#".into()));
    }

    #[test]
    fn parse_dtmf_relay_with_spaces() {
        assert_eq!(
            parse_dtmf_relay("Signal = 9\r\nDuration = 250\r\n"),
            Some("9".into())
        );
    }

    #[test]
    fn parse_dtmf_relay_empty_body() {
        assert_eq!(parse_dtmf_relay(""), None);
    }

    #[test]
    fn parse_dtmf_relay_no_signal_line() {
        assert_eq!(parse_dtmf_relay("Duration=160\r\n"), None);
    }

    #[test]
    fn parse_dtmf_relay_case_insensitive() {
        assert_eq!(parse_dtmf_relay("signal=3\r\n"), Some("3".into()));
        assert_eq!(parse_dtmf_relay("SIGNAL=0\r\n"), Some("0".into()));
    }

    #[test]
    fn keepalive_does_not_panic() {
        let cfg = Config {
            host: "127.0.0.1".into(),
            port: 15063,
            username: "1001".into(),
            password: "test".into(),
            ..Config::default()
        };
        let ua = SipUA::new(&cfg).unwrap();
        let _ = ua.send_keepalive();
        ua.close().unwrap();
    }
}
