namespace Netimobiledevice.Backup;

/// <summary>
/// C ErrNo error codes
/// </summary>
internal enum ErrNo : int
{
    /// <summary>
    /// No Error.
    /// </summary>
    ENOERR = 0,
    /// <summary>
    /// Not found.
    /// </summary>
    ENOENT = 2,
    EIO = 5,
    /// <summary>
    /// Permission denied.
    /// </summary>
    EACCES = 13,
    /// <summary>
    /// Already exists.
    /// </summary>
    EEXIST = 17,
    EISDIR = 21,
    /// <summary>
    /// Operation not supported (Darwin/iOS errno 45). #2199 (P2-3): returned in the DeviceLink status
    /// response for an unsupported/unknown command so a future-iOS message type is answered gracefully
    /// instead of killing the backup.
    /// </summary>
    ENOTSUP = 45,
}
