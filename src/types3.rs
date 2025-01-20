use crate::ffi::{HQUIC, QUIC_BUFFER, QUIC_NEW_CONNECTION_INFO};

/// Listener event converted from ffi type.
pub enum ListenerEvent<'a> {
    NewConnection {
        info: NewConnectionInfo<'a>,
        connection: HQUIC,
    },
    StopComplete {
        app_close_in_progress: bool,
    },
}

pub struct NewConnectionInfo<'a> {
    pub quic_version: u32,
    pub local_address: &'a crate::Addr,
    pub remote_address: &'a crate::Addr,
    pub crypto_buffer: &'a [u8],
    pub client_alpn_list: &'a [u8],
    pub server_name: &'a [u8],
    pub negotiated_alpn: &'a [u8],
}

impl<'a> From<&'a QUIC_NEW_CONNECTION_INFO> for NewConnectionInfo<'a> {
    fn from(value: &QUIC_NEW_CONNECTION_INFO) -> Self {
        Self {
            quic_version: value.QuicVersion,
            local_address: unsafe { (value.LocalAddress as *const crate::Addr).as_ref().unwrap() },
            remote_address: unsafe {
                (value.RemoteAddress as *const crate::Addr)
                    .as_ref()
                    .unwrap()
            },
            crypto_buffer: unsafe {
                bytes_conv(value.CryptoBuffer, value.CryptoBufferLength as usize)
            },
            client_alpn_list: unsafe {
                bytes_conv(value.ClientAlpnList, value.ClientAlpnListLength as usize)
            },
            server_name: unsafe {
                bytes_conv(
                    value.ServerName as *const u8,
                    value.ServerNameLength as usize,
                )
            },
            negotiated_alpn: unsafe {
                bytes_conv(value.NegotiatedAlpn, value.NegotiatedAlpnLength as usize)
            },
        }
    }
}

impl<'a> From<&'a crate::ffi::QUIC_LISTENER_EVENT> for ListenerEvent<'a> {
    fn from(value: &'a crate::ffi::QUIC_LISTENER_EVENT) -> Self {
        match value.Type {
            crate::ffi::QUIC_LISTENER_EVENT_TYPE_QUIC_LISTENER_EVENT_NEW_CONNECTION => {
                let ev = unsafe { &value.__bindgen_anon_1.NEW_CONNECTION };
                Self::NewConnection {
                    info: NewConnectionInfo::from(unsafe { ev.Info.as_ref().unwrap() }),
                    connection: ev.Connection,
                }
            }
            crate::ffi::QUIC_LISTENER_EVENT_TYPE_QUIC_LISTENER_EVENT_STOP_COMPLETE => {
                let ev = unsafe { &value.__bindgen_anon_1.STOP_COMPLETE };
                Self::StopComplete {
                    app_close_in_progress: ev.AppCloseInProgress() != 0,
                }
            }
            _ => panic!("unknown listener event {}", value.Type),
        }
    }
}
/// convert buffer to slice.
/// allow empty buffer. slice::from_raw_parts does not allow empty buffer.
#[inline]
unsafe fn bytes_conv<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(ptr, len)
    }
}

/// Buffer with same abi as ffi type
#[repr(transparent)]
pub struct Buffer(pub QUIC_BUFFER);

impl Buffer {
    /// get the bytes as slice.
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { bytes_conv(self.0.Buffer, self.0.Length as usize) }
    }
}

#[cfg(test)]
mod tests {
    use super::bytes_conv;

    #[test]
    fn conv_test() {
        {
            let ptr = std::ptr::null::<u8>();
            let len = 0;
            let buff = unsafe { bytes_conv(ptr, len) };
            assert_eq!(buff.len(), 0)
        }
        {
            let original = b"hello";
            let buff = unsafe { bytes_conv(original.as_ptr(), original.len()) };
            assert_eq!(buff, original.as_slice())
        }
    }
}
