/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#ifdef QUIC_CLOG
#include "stream.h.clog.h"
#endif

typedef struct QUIC_CONNECTION QUIC_CONNECTION;

//
// The stream type is encoded into the low bits of the stream ID:
//
// Client;Bi-Directional    0b00
// Server;Bi-Directional    0b01
// Client;Uni-Directional   0b10
// Server;Uni-Directional   0b11
//

#define NUMBER_OF_STREAM_TYPES          4

#define STREAM_ID_MASK                  0b11

#define STREAM_ID_FLAG_IS_CLIENT        0b00
#define STREAM_ID_FLAG_IS_SERVER        0b01

#define STREAM_ID_FLAG_IS_BI_DIR        0b00
#define STREAM_ID_FLAG_IS_UNI_DIR       0b10

#define STREAM_ID_IS_CLIENT(ID)         ((ID & 1) == 0)
#define STREAM_ID_IS_SERVER(ID)         ((ID & 1) == 1)

#define STREAM_ID_IS_BI_DIR(ID)         ((ID & 2) == 0)
#define STREAM_ID_IS_UNI_DIR(ID)        ((ID & 2) == 2)

#define QUIC_STREAM_SHUTDOWN_SILENT         0x8000  // Used in conjunction with the abort flags.
                                                    // Doesn't send anything out on the network.

#define QUIC_STREAM_EVENT_RECEIVE_TLS_INIT     0xff    // Private event for server receive ClientHello.

//
// Internal send flags. The public ones are defined in msquic.h.
//
#define QUIC_SEND_FLAG_BUFFERED     ((QUIC_SEND_FLAGS)0x80000000)

#define QUIC_SEND_FLAGS_INTERNAL \
( \
    QUIC_SEND_FLAG_BUFFERED \
)

#define QUIC_STREAM_PRIORITY_DEFAULT 0x7FFF // Medium priority by default

//
// Tracks the data queued up for sending by an application.
//
typedef struct QUIC_SEND_REQUEST {

    //
    // The pointer to the next item in the list.
    //
    struct QUIC_SEND_REQUEST* Next;

    //
    // Array of buffers to send.
    //
    _Field_size_bytes_(BufferCount)
    const QUIC_BUFFER* Buffers;

    //
    // The size of the Buffers array.
    //
    uint32_t BufferCount;

    //
    // A set of flags.
    //
    QUIC_SEND_FLAGS Flags;

    //
    // The starting stream offset.
    //
    uint64_t StreamOffset;

    //
    // The length of all the Buffers.
    //
    uint64_t TotalLength;

    //
    // Data descriptor for buffered requests.
    //
    QUIC_BUFFER InternalBuffer;

    //
    // API Client completion context.
    //
    void* ClientContext;

} QUIC_SEND_REQUEST;

//
// Different flags of a stream.
// Note - Keep quictypes.h's copy up to date.
//
typedef union QUIC_STREAM_FLAGS {
    uint64_t AllFlags;
    struct {
        BOOLEAN Allocated               : 1;    // Allocated by Connection. Used for Debugging.
        BOOLEAN Initialized             : 1;    // Initialized successfully. Used for Debugging.
        BOOLEAN Started                 : 1;    // The app has started the stream.
        BOOLEAN StartedIndicated        : 1;    // The app received a start complete event.
        BOOLEAN PeerStreamStartEventActive : 1; // The app is processing QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED
        BOOLEAN Unidirectional          : 1;    // Sends/receives in 1 direction only.
        BOOLEAN Opened0Rtt              : 1;    // A 0-RTT packet opened the stream.
        BOOLEAN IndicatePeerAccepted    : 1;    // The app requested the PEER_ACCEPTED event.

        BOOLEAN SendOpen                : 1;    // Send a STREAM frame immediately on start.
        BOOLEAN SendOpenAcked           : 1;    // A STREAM frame has been acknowledged.

        BOOLEAN LocalNotAllowed         : 1;    // Peer's unidirectional stream.
        BOOLEAN LocalCloseFin           : 1;    // Locally closed (graceful).
        BOOLEAN LocalCloseReset         : 1;    // Locally closed (locally aborted).
        BOOLEAN LocalCloseResetReliable : 1;    // Indicates that we should shutdown the send path once we sent/ACK'd ReliableOffsetSend bytes.
        BOOLEAN LocalCloseResetReliableAcked : 1; // Indicates the peer has acknowledged we will stop sending once we sent/ACK'd ReliableOffsetSend bytes.
        BOOLEAN RemoteCloseResetReliable : 1;   // Indicates that the peer initiated a reliable reset. Keep Recv path available for RecvMaxLength bytes.
        BOOLEAN ReceivedStopSending     : 1;    // Peer sent STOP_SENDING frame.
        BOOLEAN LocalCloseAcked         : 1;    // Any close acknowledged.
        BOOLEAN FinAcked                : 1;    // Our FIN was acknowledged.
        BOOLEAN InRecovery              : 1;    // Lost data is being retransmitted and is
                                                // unacknowledged.

        BOOLEAN RemoteNotAllowed        : 1;    // Our unidirectional stream.
        BOOLEAN RemoteCloseFin          : 1;    // Remotely closed.
        BOOLEAN RemoteCloseReset        : 1;    // Remotely closed (remotely aborted).
        BOOLEAN SentStopSending         : 1;    // We sent STOP_SENDING frame.
        BOOLEAN RemoteCloseAcked        : 1;    // Any close acknowledged.

        BOOLEAN SendEnabled             : 1;    // Application is allowed to send data.
        BOOLEAN ReceiveEnabled          : 1;    // Application is ready for receive callbacks.
        BOOLEAN ReceiveMultiple         : 1;    // The app supports multiple parallel receive indications.
        BOOLEAN UseAppOwnedRecvBuffers  : 1;    // The stream is using app provided receive buffers.
        BOOLEAN ReceiveFlushQueued      : 1;    // The receive flush operation is queued.
        BOOLEAN ReceiveDataPending      : 1;    // Data (or FIN) is queued and ready for delivery.
        BOOLEAN SendDelayed             : 1;    // A delayed send is currently queued.
        BOOLEAN CancelOnLoss            : 1;    // Indicates that the stream is to be canceled
                                                // if loss is detected.

        BOOLEAN HandleSendShutdown      : 1;    // Send shutdown complete callback delivered.
        BOOLEAN HandleShutdown          : 1;    // Shutdown callback delivered.
        BOOLEAN HandleClosed            : 1;    // Handle closed by application layer.

        BOOLEAN ShutdownComplete        : 1;    // Both directions have been shutdown and acknowledged.
        BOOLEAN Uninitialized           : 1;    // Uninitialize started/completed. Used for Debugging.
        BOOLEAN Freed                   : 1;    // Freed after last ref count released. Used for Debugging.

        BOOLEAN InStreamTable           : 1;    // The stream is currently in the connection's table.
        BOOLEAN InWaitingList           : 1;    // The stream is currently in the waiting list for stream id FC.
        BOOLEAN DelayIdFcUpdate         : 1;    // Delay stream ID FC updates to StreamClose.
    };
} QUIC_STREAM_FLAGS;

CXPLAT_STATIC_ASSERT(
    sizeof(QUIC_STREAM_FLAGS) == sizeof(uint64_t),
    "QUIC_STREAM_FLAGS AllFlags size is mismatched.");

typedef enum QUIC_STREAM_SEND_STATE {
    QUIC_STREAM_SEND_DISABLED,
    QUIC_STREAM_SEND_STARTED,
    QUIC_STREAM_SEND_RESET,
    QUIC_STREAM_SEND_RESET_ACKED,
    QUIC_STREAM_SEND_FIN,
    QUIC_STREAM_SEND_FIN_ACKED,
    QUIC_STREAM_SEND_RELIABLE_RESET,
    QUIC_STREAM_SEND_RELIABLE_RESET_ACKED
} QUIC_STREAM_SEND_STATE;

typedef enum QUIC_STREAM_RECV_STATE {
    QUIC_STREAM_RECV_DISABLED,
    QUIC_STREAM_RECV_STARTED,
    QUIC_STREAM_RECV_PAUSED,
    QUIC_STREAM_RECV_STOPPED,
    QUIC_STREAM_RECV_RESET,
    QUIC_STREAM_RECV_FIN,
    QUIC_STREAM_RECV_RELIABLE_RESET
} QUIC_STREAM_RECV_STATE;

//
// Different references on a stream.
//
typedef enum QUIC_STREAM_REF {

    QUIC_STREAM_REF_APP,
    QUIC_STREAM_REF_STREAM_SET,
    QUIC_STREAM_REF_SEND,
    QUIC_STREAM_REF_SEND_PACKET,
    QUIC_STREAM_REF_LOOKUP,
    QUIC_STREAM_REF_OPERATION,

    QUIC_STREAM_REF_COUNT

} QUIC_STREAM_REF;

//
// This structure represents all the per connection specific data.
//
typedef struct QUIC_STREAM {

#ifdef __cplusplus
    struct QUIC_HANDLE _;
#else
    struct QUIC_HANDLE;
#endif

    //
    // Number of references to the handle.
    //
    CXPLAT_REF_COUNT RefCount;

#if DEBUG
    short RefTypeCount[QUIC_STREAM_REF_COUNT];
#endif

    //
    // Number of outstanding sent metadata items currently being tracked for
    // this stream.
    //
    uint32_t OutstandingSentMetadata;

    //
    // Linkage in the stream set
    //
    union {
        //
        // Link in the hash-table when the stream is open.
        //
        CXPLAT_HASHTABLE_ENTRY TableEntry;

        //
        // Link in the waiting list when the stream if waiting for stream
        // id flow control.
        //
        CXPLAT_LIST_ENTRY WaitingLink;

        //
        // Link in the closed list when closed and waiting for clean up.
        //
        CXPLAT_LIST_ENTRY ClosedLink;
    };

    //
    // The list entry in the output module's send list.
    //
    CXPLAT_LIST_ENTRY SendLink;

#if DEBUG
    //
    // The list entry in the stream set's list of all allocated streams.
    //
    CXPLAT_LIST_ENTRY AllStreamsLink;
#endif

    //
    // The parent connection for this stream.
    //
    QUIC_CONNECTION* Connection;

    //
    // The identifier for this stream.
    //
    uint64_t ID;

    //
    // The current flags for this stream.
    //
    QUIC_STREAM_FLAGS Flags;


    //
    // Set of Send flags indicating data is ready to be sent.
    //
    uint16_t SendFlags;

    //
    // Set of current reasons sending more packets is currently blocked.
    //
    uint8_t OutFlowBlockedReasons; // Set of QUIC_FLOW_BLOCKED_* flags

    //
    // Send State
    //

    //
    // API calls to StreamSend queue the send request here and then queue the
    // send operation. That operation moves the send request onto the
    // SendRequests list.
    //
    CXPLAT_DISPATCH_LOCK ApiSendRequestLock;
    QUIC_SEND_REQUEST* ApiSendRequests;

    //
    // Queued send requests.
    //
    QUIC_SEND_REQUEST* SendRequests;
    QUIC_SEND_REQUEST** SendRequestsTail;

    //
    // Shortcut pointer: NULL, or the request containing the next byte to send.
    //
    QUIC_SEND_REQUEST* SendBookmark;

    //
    // Shortcut pointer: NULL, or the next unbuffered send request.
    //
    QUIC_SEND_REQUEST* SendBufferBookmark;

    //
    // The total send offset for all queued send requests.
    //
    uint64_t QueuedSendOffset;

    //
    // The contiguous length of queued 0RTT-permitted data, and the
    // amount of data that was actually sent 0RTT.
    //
    uint64_t Queued0Rtt;
    uint64_t Sent0Rtt;

    //
    // The max allowed send offset according to per-stream flow control.
    //
    uint64_t MaxAllowedSendOffset;

    //
    // Estimate of the peer's flow control window.
    //
    uint32_t SendWindow;

    //
    // The ByteCount value in the last indicated IDEAL_SEND_BUFFER_SIZE event.
    //
    uint64_t LastIdealSendBuffer;

    //
    // The length of bytes that have been sent at least once.
    //
    uint64_t MaxSentLength;

    //
    // The smallest offset for unacknowledged send data. This variable is
    // similar to RFC793 SND.UNA.
    //
    uint64_t UnAckedOffset;

    //
    // The next offset we will start sending at.
    //
    uint64_t NextSendOffset;

    //
    // Recovery window
    //
    uint64_t RecoveryNextOffset;
    uint64_t RecoveryEndOffset;

    //
    // If > 0, bytes up to offset must be re-transmitted and ACK'd from peer before we can abort this stream.
    //
    uint64_t ReliableOffsetSend;

    #define RECOV_WINDOW_OPEN(S) ((S)->RecoveryNextOffset < (S)->RecoveryEndOffset)

    //
    // The error code for why the send path was shutdown.
    //
    QUIC_VAR_INT SendShutdownErrorCode;

    //
    // The ACK ranges greater than 'UnAckedOffset', with holes between them.
    //
    QUIC_RANGE SparseAckRanges;

    //
    // The relative priority between the different streams that determines the
    // order that queued data will be sent out.
    //
    uint16_t SendPriority;

    //
    // Recv State
    //

    //
    // The max allowed RecvOffset (i.e., the number we report in
    // MAX_STREAM_DATA frames). When we have zero bytes buffered,
    // (MaxAllowedRecvOffset - RecvOffset) is the max allowed buffer
    // space for the stream.
    //
    uint64_t MaxAllowedRecvOffset;

    //
    // The number of bytes received since the last recv window update.
    //
    uint64_t RecvWindowBytesDelivered;

    //
    // Timestamp of the last recv window update.
    //
    uint64_t RecvWindowLastUpdate;

    //
    // The structure for tracking received buffers.
    //
    QUIC_RECV_BUFFER RecvBuffer;

    //
    // The maximum length of 0-RTT secured payload received.
    //
    uint64_t RecvMax0RttLength;

    //
    // Maximum allowed inbound byte offset, established when the FIN is received.
    //
    uint64_t RecvMaxLength;

    //
    // The number of bytes that are currently outstanding up to the app.
    //
    uint64_t RecvPendingLength;

    //
    // The number of received bytes the app has completed but not yet processed
    // by MsQuic. The top bit of RecvCompletionLength is used to indicate that
    // there is an active receive to the app. The second highest bit is used to
    // detect overflow. This structure allows us to synchronize both the receive
    // indication flag and the number of bytes completed in a single atomic operation,
    // for a lock-free implementation
    //
    volatile uint64_t RecvCompletionLength;

    //
    // The error code for why the receive path was shutdown.
    //
    QUIC_VAR_INT RecvShutdownErrorCode;

    //
    // The handler for the API client's callbacks.
    //
    QUIC_STREAM_CALLBACK_HANDLER ClientCallbackHandler;

    //
    // Preallocated operation for receive complete
    //
    QUIC_OPERATION* ReceiveCompleteOperation;
    QUIC_OPERATION ReceiveCompleteOperationStorage;
    QUIC_API_CONTEXT ReceiveCompleteApiCtxStorage;

    //
    // Stream blocked timings.
    //
    struct {
        QUIC_FLOW_BLOCKED_TIMING_TRACKER StreamIdFlowControl;
        QUIC_FLOW_BLOCKED_TIMING_TRACKER FlowControl;
        QUIC_FLOW_BLOCKED_TIMING_TRACKER App;
        uint64_t CachedConnSchedulingUs;
        uint64_t CachedConnPacingUs;
        uint64_t CachedConnAmplificationProtUs;
        uint64_t CachedConnCongestionControlUs;
        uint64_t CachedConnFlowControlUs;
    } BlockedTimings;
} QUIC_STREAM;

//
// There is an active receive to the app
//
#define QUIC_STREAM_RECV_COMPLETION_LENGTH_RECEIVE_CALL_ACTIVE_FLAG 0x8000000000000000
//
// The second highest bit is used to detect overflow
//
#define QUIC_STREAM_RECV_COMPLETION_LENGTH_CANARY_BIT               0x4000000000000000

QUIC_INLINE
QUIC_STREAM_SEND_STATE
QuicStreamSendGetState(
    _In_ const QUIC_STREAM* Stream
    )
{
    if (Stream->Flags.LocalNotAllowed) {
        return QUIC_STREAM_SEND_DISABLED;
    } else if (Stream->Flags.LocalCloseResetReliable) {
        if (Stream->Flags.LocalCloseResetReliableAcked) {
            return QUIC_STREAM_SEND_RELIABLE_RESET_ACKED;
        } else {
            return QUIC_STREAM_SEND_RELIABLE_RESET;
        }
    } else if (Stream->Flags.LocalCloseAcked) {
        if (Stream->Flags.FinAcked) {
            return QUIC_STREAM_SEND_FIN_ACKED;
        } else {
            return QUIC_STREAM_SEND_RESET_ACKED;
        }
    } else if (Stream->Flags.LocalCloseReset) {
        return QUIC_STREAM_SEND_RESET;
    } else if (Stream->Flags.LocalCloseFin) {
        return QUIC_STREAM_SEND_FIN;
    } else {
        return QUIC_STREAM_SEND_STARTED;
    }
}

QUIC_INLINE
QUIC_STREAM_RECV_STATE
QuicStreamRecvGetState(
    _In_ const QUIC_STREAM* Stream
    )
{
    if (Stream->Flags.RemoteNotAllowed) {
        return QUIC_STREAM_RECV_DISABLED;
    } else if (Stream->Flags.RemoteCloseReset) {
        return QUIC_STREAM_RECV_RESET;
    } else if (Stream->Flags.RemoteCloseResetReliable) {
        return QUIC_STREAM_RECV_RELIABLE_RESET;
    } else if (Stream->Flags.RemoteCloseFin) {
        return QUIC_STREAM_RECV_FIN;
    } else if (Stream->Flags.SentStopSending) {
        return QUIC_STREAM_RECV_STOPPED;
    } else if (!Stream->Flags.ReceiveEnabled) {
        return QUIC_STREAM_RECV_PAUSED;
    } else {
        return QUIC_STREAM_RECV_STARTED;
    }
}

//
// Returns TRUE if the stream has anything to send.
//
BOOLEAN
QuicStreamCanSendNow(
    _In_ const QUIC_STREAM* Stream,
    _In_ BOOLEAN ZeroRtt
    );

//
// Returns TRUE if the peer has indicated the stream ID is allowed to be used
// yet.
//
BOOLEAN
QuicStreamAllowedByPeer(
    _In_ const QUIC_STREAM* Stream
    );

QUIC_INLINE
uint64_t
QuicStreamGetInitialMaxDataFromTP(
    _In_ uint64_t StreamID,
    _In_ BOOLEAN IsServer,
    _In_ const QUIC_TRANSPORT_PARAMETERS* const TransportParams
    )
{
    if (STREAM_ID_IS_UNI_DIR(StreamID)) {
        return TransportParams->InitialMaxStreamDataUni;
    } else if (IsServer) {
        if (STREAM_ID_IS_CLIENT(StreamID)) {
            return TransportParams->InitialMaxStreamDataBidiLocal;
        } else {
            return TransportParams->InitialMaxStreamDataBidiRemote;
        }
    } else {
        if (STREAM_ID_IS_CLIENT(StreamID)) {
            return TransportParams->InitialMaxStreamDataBidiRemote;
        } else {
            return TransportParams->InitialMaxStreamDataBidiLocal;
        }
    }
}

//
// Allocates and partially initializes a new stream object.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicStreamInitialize(
    _In_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN OpenedRemotely,
    _In_ QUIC_STREAM_OPEN_FLAGS Flags,
    _Outptr_ _At_(*Stream, __drv_allocatesMem(Mem))
        QUIC_STREAM** Stream
    );

//
// Free the stream object.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicStreamFree(
    _In_ __drv_freesMem(Mem) QUIC_STREAM* Stream
    );

//
// Associates a new ID with the stream and inserts it into the connection's
// table.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicStreamStart(
    _In_ QUIC_STREAM* Stream,
    _In_ QUIC_STREAM_START_FLAGS Flags,
    _In_ BOOLEAN IsRemoteStream
    );

//
// Releases the application's reference on the stream.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamClose(
    _In_ __drv_freesMem(Mem) QUIC_STREAM* Stream
    );

//
// Tracing rundown for the stream set.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamTraceRundown(
    _In_ QUIC_STREAM* Stream
    );

//
// Indicates an event to the application layer.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicStreamIndicateEvent(
    _In_ QUIC_STREAM* Stream,
    _Inout_ QUIC_STREAM_EVENT* Event
    );

//
// Indicates the stream start complete event to the application layer.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamIndicateStartComplete(
    _In_ QUIC_STREAM* Stream,
    _In_ QUIC_STATUS Status
    );

//
// Initiates an asychronous shutdown of one or both directions of the stream.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamShutdown(
    _In_ QUIC_STREAM* Stream,
    _In_ QUIC_STREAM_SHUTDOWN_FLAGS Flags,
    _In_ QUIC_VAR_INT ErrorCode
    );

//
// Marks the Stream as shutdown complete if both directions are closed and
// acknowledged as closed.
//
void
QuicStreamTryCompleteShutdown(
    _In_ QUIC_STREAM* Stream
    );

//
// Sets a stream parameter.
//
QUIC_STATUS
QuicStreamParamSet(
    _In_ QUIC_STREAM* Stream,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    );

//
// Gets a stream parameter.
//
QUIC_STATUS
QuicStreamParamGet(
    _In_ QUIC_STREAM* Stream,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        void* Buffer
    );

//
// Adds a ref to a stream.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_INLINE
void
QuicStreamAddRef(
    _In_ QUIC_STREAM* Stream,
    _In_ QUIC_STREAM_REF Ref
    )
{
    CXPLAT_DBG_ASSERT(Stream->Connection);
    CXPLAT_DBG_ASSERT(Stream->RefCount > 0);

#if DEBUG
    InterlockedIncrement16((volatile short*)&Stream->RefTypeCount[Ref]);
#else
    UNREFERENCED_PARAMETER(Ref);
#endif

    CxPlatRefIncrement(&Stream->RefCount);
}

//
// Releases a ref on a stream.
//
#pragma warning(push)
#pragma warning(disable:6014) // SAL doesn't understand ref counts
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_INLINE
BOOLEAN
QuicStreamRelease(
    _In_ __drv_freesMem(Mem) QUIC_STREAM* Stream,
    _In_ QUIC_STREAM_REF Ref
    )
{
    CXPLAT_DBG_ASSERT(Stream->Connection);
    CXPLAT_TEL_ASSERT(Stream->RefCount > 0);

#if DEBUG
    CXPLAT_TEL_ASSERT(Stream->RefTypeCount[Ref] > 0);
    uint16_t result = (uint16_t)InterlockedDecrement16((volatile short*)&Stream->RefTypeCount[Ref]);
    CXPLAT_TEL_ASSERT(result != 0xFFFF);
#else
    UNREFERENCED_PARAMETER(Ref);
#endif

    if (CxPlatRefDecrement(&Stream->RefCount)) {
#if DEBUG
        for (uint32_t i = 0; i < QUIC_STREAM_REF_COUNT; i++) {
            CXPLAT_TEL_ASSERT(Stream->RefTypeCount[i] == 0);
        }
#endif
        QuicStreamFree(Stream);
        return TRUE;
    }
    return FALSE;
}
#pragma warning(pop)

//
// Increments the sent metadata counter.
// No synchronization necessary as it's always called on the worker thread.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_INLINE
void
QuicStreamSentMetadataIncrement(
    _In_ QUIC_STREAM* Stream
    )
{
    if (++Stream->OutstandingSentMetadata == 1) {
        QuicStreamAddRef(Stream, QUIC_STREAM_REF_SEND_PACKET);
    }
    CXPLAT_DBG_ASSERT(Stream->OutstandingSentMetadata != 0);
}

//
// Decrements the sent metadata counter.
// No synchronization necessary as it's always called on the worker thread.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_INLINE
void
QuicStreamSentMetadataDecrement(
    _In_ QUIC_STREAM* Stream
    )
{
    CXPLAT_DBG_ASSERT(Stream->OutstandingSentMetadata != 0);
    if (--Stream->OutstandingSentMetadata == 0) {
        QuicStreamRelease(Stream, QUIC_STREAM_REF_SEND_PACKET);
    }
}

//
// Send Functions
//

QUIC_INLINE
BOOLEAN
QuicStreamAddOutFlowBlockedReason(
    _In_ QUIC_STREAM* Stream,
    _In_ QUIC_FLOW_BLOCK_REASON Reason
    )
{
    CXPLAT_DBG_ASSERT((Reason & QUIC_FLOW_BLOCKED_STREAM_ID_FLOW_CONTROL) == 0);
    CXPLAT_DBG_ASSERTMSG(
        (Reason & (Reason - 1)) == 0,
        "More than one reason is not allowed");
    if (!(Stream->OutFlowBlockedReasons & Reason)) {
        uint64_t Now = CxPlatTimeUs64();
        if (Reason & QUIC_FLOW_BLOCKED_STREAM_FLOW_CONTROL) {
            Stream->BlockedTimings.FlowControl.LastStartTimeUs = Now;
        }

        if (Reason & QUIC_FLOW_BLOCKED_APP) {
            Stream->BlockedTimings.App.LastStartTimeUs = Now;
        }

        Stream->OutFlowBlockedReasons |= Reason;
        QuicTraceEvent(
            StreamOutFlowBlocked,
            "[strm][%p] Send Blocked Flags: %hhu",
            Stream,
            Stream->OutFlowBlockedReasons);
        return TRUE;
    }
    return FALSE;
}

QUIC_INLINE
BOOLEAN
QuicStreamRemoveOutFlowBlockedReason(
    _In_ QUIC_STREAM* Stream,
    _In_ QUIC_FLOW_BLOCK_REASON Reason
    )
{
    if ((Stream->OutFlowBlockedReasons & Reason)) {
        uint64_t Now = CxPlatTimeUs64();
        if ((Stream->OutFlowBlockedReasons & QUIC_FLOW_BLOCKED_STREAM_FLOW_CONTROL) &&
            (Reason & QUIC_FLOW_BLOCKED_STREAM_FLOW_CONTROL)) {
            Stream->BlockedTimings.FlowControl.CumulativeTimeUs +=
                CxPlatTimeDiff64(
                    Stream->BlockedTimings.FlowControl.LastStartTimeUs, Now);
            Stream->BlockedTimings.FlowControl.LastStartTimeUs = 0;
        }

        if ((Stream->OutFlowBlockedReasons & QUIC_FLOW_BLOCKED_APP) &&
            (Reason & QUIC_FLOW_BLOCKED_APP)) {
            Stream->BlockedTimings.App.CumulativeTimeUs +=
                CxPlatTimeDiff64(
                    Stream->BlockedTimings.App.LastStartTimeUs, Now);
            Stream->BlockedTimings.App.LastStartTimeUs = 0;
        }

        if ((Stream->OutFlowBlockedReasons & QUIC_FLOW_BLOCKED_STREAM_ID_FLOW_CONTROL) &&
            (Reason & QUIC_FLOW_BLOCKED_STREAM_ID_FLOW_CONTROL)) {
            Stream->BlockedTimings.StreamIdFlowControl.CumulativeTimeUs +=
                CxPlatTimeDiff64(
                    Stream->BlockedTimings.StreamIdFlowControl.LastStartTimeUs, Now);
            Stream->BlockedTimings.StreamIdFlowControl.LastStartTimeUs = 0;
        }

        Stream->OutFlowBlockedReasons &= ~Reason;
        QuicTraceEvent(
            StreamOutFlowBlocked,
            "[strm][%p] Send Blocked Flags: %hhu",
            Stream,
            Stream->OutFlowBlockedReasons);
        return TRUE;
    }
    return FALSE;
}

//
// Initiates async shutdown of send path.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamSendShutdown(
    _In_ QUIC_STREAM* Stream,
    _In_ BOOLEAN Graceful,
    _In_ BOOLEAN Silent,
    _In_ BOOLEAN DelaySend,
    _In_ QUIC_VAR_INT ErrorCode   // Only for !Graceful
    );

//
// Send path has completed shutdown.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamIndicateSendShutdownComplete(
    _In_ QUIC_STREAM* Stream,
    _In_ BOOLEAN GracefulShutdown
    );

//
// Indicates data has been queued up to be sent out on the stream.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamSendFlush(
    _In_ QUIC_STREAM* Stream
    );

//
// Copies the bytes of a send request and completes it early.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicStreamSendBufferRequest(
    _Inout_ QUIC_STREAM* Stream,
    _Inout_ QUIC_SEND_REQUEST* Req
    );

//
// Called on a stream to allow it to write any frames it needs to the packet
// buffer. Returns TRUE if frames were written; FALSE if it ran out of space
// to write anything.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicStreamSendWrite(
    _In_ QUIC_STREAM* Stream,
    _Inout_ QUIC_PACKET_BUILDER* Builder
    );

//
// Called when a stream frame is inferred to be lost. Returns TRUE if data is
// queued to be sent.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicStreamOnLoss(
    _In_ QUIC_STREAM* Stream,
    _In_ QUIC_SENT_FRAME_METADATA* FrameMetadata
    );

//
// Called when an ACK is received for a stream frame.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamOnAck(
    _In_ QUIC_STREAM* Stream,
    _In_ QUIC_SEND_PACKET_FLAGS PacketFlags,
    _In_ QUIC_SENT_FRAME_METADATA* FrameMetadata
    );

//
// Called when an ACK is received for a RESET_STREAM frame we sent.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamOnResetAck(
    _In_ QUIC_STREAM* Stream
    );

//
// Called when an ACK is received for a RELIABLE_RESET frame we sent.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamOnResetReliableAck(
    _In_ QUIC_STREAM* Stream
    );

//
// Cancels any queued send requests. Usually right before we abort.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamCancelRequests(
    _In_ QUIC_STREAM* Stream
    );

//
// Dumps send state to the logs.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamSendDumpState(
    _In_ QUIC_STREAM* Stream
    );

//
// Receive Functions
//

//
// Initiates async shutdown of receive path.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamRecvShutdown(
    _In_ QUIC_STREAM* Stream,
    _In_ BOOLEAN Silent,
    _In_ QUIC_VAR_INT ErrorCode
    );

//
// Completes a receive call that was pended by the app.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamReceiveCompletePending(
    _In_ QUIC_STREAM* Stream
    );

//
// Processes a received frame for the given stream.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicStreamRecv(
    _In_ QUIC_STREAM* Stream,
    _In_ QUIC_RX_PACKET* Packet,
    _In_ QUIC_FRAME_TYPE FrameType,
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Inout_ BOOLEAN* UpdatedFlowControl
    );

//
// Processes queued events and delivers them to the API client.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamRecvFlush(
    _In_ QUIC_STREAM* Stream
    );

//
// Enables or disables receive callbacks for the stream.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicStreamRecvSetEnabledState(
    _In_ QUIC_STREAM* Stream,
    _In_ BOOLEAN NewRecvEnabled
    );

//
// Convert a stream receive buffer to app-owned mode.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicStreamSwitchToAppOwnedBuffers(
    _In_ QUIC_STREAM *Stream
    );

//
// Provide new chunks for the stream receive buffer.
// Terminate the connection on failure.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicStreamProvideRecvBuffers(
    _In_ QUIC_STREAM* Stream,
    _Inout_ CXPLAT_LIST_ENTRY* /* QUIC_RECV_CHUNK */ Chunks
    );
