use std::ffi::c_void;

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
                slice_conv(value.CryptoBuffer, value.CryptoBufferLength as usize)
            },
            client_alpn_list: unsafe {
                slice_conv(value.ClientAlpnList, value.ClientAlpnListLength as usize)
            },
            server_name: unsafe {
                slice_conv(
                    value.ServerName as *const u8,
                    value.ServerNameLength as usize,
                )
            },
            negotiated_alpn: unsafe {
                slice_conv(value.NegotiatedAlpn, value.NegotiatedAlpnLength as usize)
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
/// Convert array pointer to slice.
/// Allows empty buffer. slice::from_raw_parts does not allow empty buffer.
#[inline]
unsafe fn slice_conv<'a, T>(ptr: *const T, len: usize) -> &'a [T] {
    if len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(ptr, len)
    }
}

/// Buffer with same abi as ffi type.
/// It has no ownership of the memory chunk.
#[repr(transparent)]
pub struct BufferRef(pub QUIC_BUFFER);

impl BufferRef {
    /// get the bytes as slice.
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { slice_conv(self.0.Buffer, self.0.Length as usize) }
    }
}

/// Slice of buffer used to convert array of buffers in callback events.
pub struct BufferRefSlice<'a>(pub &'a [QUIC_BUFFER]);

impl<'a> BufferRefSlice<'a> {
    /// Get a slice of buffers.
    pub fn as_slice(&self) -> &'a [BufferRef] {
        // because inner slice type and the return type has the same abi repr, it is ok to convert them
        unsafe { slice_conv(self.0.as_ptr() as *const BufferRef, self.0.len()) }
    }
}

/// Buffers with owned memory used for sending data.
pub trait BuffersOwned {
    /// Get the buffers to pass to ffi api.
    /// Buffers memory should not change, since they are passed to ffi.
    fn as_ffi(&self) -> &[QUIC_BUFFER];
}

pub trait BuffersOwnedDetachable: BuffersOwned {
    /// Detach memory onwership to pass in ffi api as client_context.
    fn into_raw(self) -> *const c_void;

    /// Reattach memory ownership from what previously returned by into_raw().
    /// # Safety
    /// raw needs to be previously returned by into_raw().
    ///
    /// ffi usually gives back the client_context in the callback after
    /// finishing using the buffer.
    unsafe fn from_raw(raw: *const c_void) -> Self;
}

/// Buffers backed by vectors.
/// T is the buffer type that can convert to slice, typically Vec<u8> or array
/// are used.
pub struct VecBuffers<T: AsRef<[u8]>> {
    /// buffers. Each chunk T is heap allocated via Vec,
    _data: Vec<T>,
    meta: Vec<QUIC_BUFFER>,
}

impl<T: AsRef<[u8]>> BuffersOwned for VecBuffers<T> {
    fn as_ffi(&self) -> &[QUIC_BUFFER] {
        self.meta.as_slice()
    }
}

impl<T: AsRef<[u8]>> VecBuffers<T> {
    pub fn new(data: Vec<T>) -> Self {
        let meta = data
            .iter()
            .by_ref()
            .map(|b| {
                let buf_ref = b.as_ref();
                QUIC_BUFFER {
                    Buffer: buf_ref.as_ptr() as *mut u8,
                    Length: buf_ref.len() as u32,
                }
            })
            .collect();
        Self { _data: data, meta }
    }
}

/// Detachable wrapper using Box.
pub struct BoxedBuffersOwned<T: BuffersOwned> {
    inner: Box<T>,
}

impl<T: BuffersOwned> BoxedBuffersOwned<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner: Box::new(inner),
        }
    }

    /// Unbox the inner.
    pub fn into_inner(self) -> T {
        *self.inner
    }
}

/// pass through inner type to get buffers.
impl<T: BuffersOwned> BuffersOwned for BoxedBuffersOwned<T> {
    fn as_ffi(&self) -> &[QUIC_BUFFER] {
        self.inner.as_ffi()
    }
}

impl<T: BuffersOwned> BuffersOwnedDetachable for BoxedBuffersOwned<T> {
    fn into_raw(self) -> *const c_void {
        Box::into_raw(self.inner) as *const c_void
    }

    unsafe fn from_raw(raw: *const c_void) -> Self {
        Self {
            inner: Box::from_raw(raw as *mut T),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        ffi::QUIC_BUFFER,
        types3::{BoxedBuffersOwned, BuffersOwnedDetachable},
    };

    use super::{slice_conv, BufferRefSlice, BuffersOwned, VecBuffers};

    #[test]
    fn conv_test() {
        {
            let ptr = std::ptr::null::<u8>();
            let len = 0;
            let buff = unsafe { slice_conv(ptr, len) };
            assert_eq!(buff.len(), 0)
        }
        {
            let original = b"hello";
            let buff = unsafe { slice_conv(original.as_ptr(), original.len()) };
            assert_eq!(buff, original.as_slice())
        }
    }

    const FIRST: &[u8; 5] = b"aaaaa";
    const SECOND: &[u8; 5] = b"bbbbb";

    #[test]
    fn buffer_read_test() {
        let first = Box::new(b"first");
        let second = b"second";
        let buffers = Box::new([
            QUIC_BUFFER {
                Buffer: first.as_ptr() as *mut u8,
                Length: first.len() as u32,
            },
            QUIC_BUFFER {
                Buffer: second.as_ptr() as *mut u8,
                Length: second.len() as u32,
            },
        ]);
        let buffs = BufferRefSlice(buffers.as_ref());
        // In callback events, BufferSlice buffs is the given type and memory is from C,
        // and it has the right lifetime.
        // In this test, `buffers` variable emulates the memory from C.

        let first1 = &buffs.as_slice()[0];
        // If we drop buffers here on this line, compiler can catch the first1's lifetime is violated.
        // This shows that the BufferSlice wrapper captures the right lifetime of the buffers.
        // However there is no way to carry the lifetime of the var `first` into var `buffers` because the C style
        // api raw pointer boundary has been crossed.
        // TODO: msquic has feature to hold on to buffers even after callback have returned. This is
        // is not supported safely in rust. (event if we support this, buffs reference's lifetime is still only valid
        // at the end of the callback function. However, the lifetime of content of the buffer, i.e. &[u8], can be extended.)
        let second1 = &buffs.as_slice()[1];
        assert_eq!(first.as_slice(), first1.as_bytes());
        assert_eq!(second, second1.as_bytes());
    }

    #[test]
    fn buffer_write_test_vec() {
        let buffers = VecBuffers::new(vec![FIRST.to_vec(), SECOND.to_vec()]);
        buffer_write_test(buffers);
    }

    #[test]
    fn buffer_write_test_array() {
        let buffers = VecBuffers::new(vec![FIRST.to_owned(), SECOND.to_owned()]);
        buffer_write_test(buffers);
    }

    fn buffer_write_test<T: BuffersOwned>(buffers: T) {
        let buffers = BoxedBuffersOwned::new(buffers);

        let refs = BufferRefSlice(buffers.as_ffi());
        // try read it
        assert_eq!(refs.as_slice()[0].as_bytes(), FIRST);
        assert_eq!(refs.as_slice()[1].as_bytes(), SECOND);

        // detach and reattach and check content
        let raw = buffers.into_raw();
        let buffers2 = unsafe { BoxedBuffersOwned::<T>::from_raw(raw) }.into_inner();
        let refs2 = BufferRefSlice(buffers2.as_ffi());
        assert_eq!(refs2.as_slice()[0].as_bytes(), FIRST);
        assert_eq!(refs2.as_slice()[1].as_bytes(), SECOND);
    }
}
