using System;
using System.IO;

namespace Netimobiledevice.Backup;


public class DetailedErrorEventArgs(Exception exception, string details) : ErrorEventArgs(exception)
{
    public string Details { get; set; } = details;
}
