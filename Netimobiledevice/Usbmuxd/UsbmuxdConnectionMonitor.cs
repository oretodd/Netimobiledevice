using Microsoft.Extensions.Logging;
using Netimobiledevice.Plist;
using Netimobiledevice.Usbmuxd.Responses;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace Netimobiledevice.Usbmuxd;

internal class UsbmuxdConnectionMonitor(Action<UsbmuxdDevice, UsbmuxdConnectionEventType> callback, Action<Exception>? errorCallback = null, ILogger? logger = null) {
    private readonly Action<UsbmuxdDevice, UsbmuxdConnectionEventType> _callback = callback;
    private readonly ConcurrentDictionary<long, UsbmuxdDevice> _connectedDevices = [];
    private readonly Action<Exception>? _errorCallback = errorCallback;
    /// <summary>
    /// The internal logger
    /// </summary>
    private readonly ILogger? _logger = logger;

    private CancellationTokenSource _cancellationTokenSource = new CancellationTokenSource();

    private Task? _connectionMonitorTask;

    private void AddDevice(UsbmuxdDevice usbmuxdDevice) {
        _connectedDevices.TryAdd(usbmuxdDevice.DeviceId, usbmuxdDevice);
        _callback(usbmuxdDevice, UsbmuxdConnectionEventType.Add);
    }

    /// <summary>
    /// Resolves the device for a BINARY-protocol Add event into one carrying its REAL
    /// <see cref="UsbmuxdConnectionType"/> (+NetworkAddress). The binary Add record cannot carry the
    /// connection type, so a literal construction is always <see cref="UsbmuxdConnectionType.Usb"/> —
    /// which misclassifies a WiFi device and breaks any WiFi-vs-USB transport gating downstream
    /// (ScribeHold #1914 flap). Rather than guess, this cross-references usbmuxd's device list, which is
    /// served over the Plist protocol and DOES carry the per-device <c>ConnectionType</c>, and returns
    /// the matching authoritative entry. This is an authoritative lookup, NOT synthesis: a genuinely
    /// cabled device still comes back <c>USB</c>, so there is no inverse-misclassification risk. Falls
    /// back to the legacy <c>Usb</c> construction if the lookup finds nothing or fails (single device
    /// dropped between Add and lookup, daemon truly binary-only, transient error) — never worse than
    /// before.
    /// </summary>
    private UsbmuxdDevice ResolveAddedDevice(uint deviceId, string serial) {
        try {
            List<UsbmuxdDevice> devices = Usbmux.GetDeviceList(logger: _logger);

            // The DeviceId is the unique per-connection id usbmuxd assigned to THIS Add, so it
            // disambiguates a device present on both USB and Network (each connection has its own
            // DeviceId). Prefer it.
            foreach (UsbmuxdDevice candidate in devices) {
                if (candidate.DeviceId == deviceId && candidate.ConnectionType != UsbmuxdConnectionType.None) {
                    return candidate;
                }
            }

            // No DeviceId match (e.g. the daemon's list churned between the Add and this lookup). Fall
            // back to a serial match, preferring a USB entry over a Network one when the same serial
            // appears on both — matching usbmuxd's own "prefer USB" lookup and ScribeHold's prefer-USB
            // cross-transport policy.
            if (!string.IsNullOrEmpty(serial)) {
                UsbmuxdDevice? bySerial = null;
                foreach (UsbmuxdDevice candidate in devices) {
                    if (candidate.Serial != serial || candidate.ConnectionType == UsbmuxdConnectionType.None) {
                        continue;
                    }
                    if (candidate.ConnectionType == UsbmuxdConnectionType.Usb) {
                        return candidate; // USB wins outright
                    }
                    bySerial ??= candidate; // remember the first (e.g. Network) match
                }
                if (bySerial is not null) {
                    return bySerial;
                }
            }
        }
        catch (Exception ex) {
            // The lookup opens its own short-lived connection; a failure here must not abort the listen
            // loop. Fall through to the legacy Usb construction so behaviour is never worse than before.
            _logger?.LogDebug(ex, "usbmux binary Add: device-list lookup failed for {Serial}; defaulting to Usb", serial);
        }
        return new UsbmuxdDevice(deviceId, serial, UsbmuxdConnectionType.Usb);
    }

    private async Task ConnectionListener() {
        CancellationToken ct = _cancellationTokenSource.Token;
        do {
            using (CancellationTokenSource localCancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(ct)) {
                UsbmuxConnection muxConnection;
                try {
                    muxConnection = UsbmuxConnection.Create(logger: _logger);
                }
                catch (UsbmuxConnectionException ex) {
                    _errorCallback?.Invoke(ex);
                    _logger?.LogWarning(ex, "Issue trying to create UsbmuxConnection");

                    // Put a delay here so that it doesn't immedietly retry creating the UsbmuxConnection
                    await Task.Delay(500).ConfigureAwait(false);
                    continue;
                }

                UsbmuxdResult usbmuxError = await muxConnection.ListenAsync(localCancellationTokenSource.Token).ConfigureAwait(false);
                if (usbmuxError != UsbmuxdResult.Ok) {
                    continue;
                }

                while (!localCancellationTokenSource.Token.IsCancellationRequested) {
                    UsbmuxdResult result = await GetAndProcessNextEvent(muxConnection, localCancellationTokenSource.Token).ConfigureAwait(false);
                    if (result != UsbmuxdResult.Ok) {
                        break;
                    }
                }
            }
        } while (!ct.IsCancellationRequested);
    }

    /// <summary>
    /// Waits for an event to occur, i.e. a packet coming from usbmuxd.
    /// Calls GenerateEvent to pass the event via callback to the client program.
    /// </summary>
    private async Task<UsbmuxdResult> GetAndProcessNextEvent(UsbmuxConnection connection, CancellationToken cancellationToken = default) {
        UsbmuxPacket packet = await connection.ReceiveAsync(cancellationToken: cancellationToken).ConfigureAwait(false);
        if (packet.Header.Length <= 0) {
            if (!cancellationToken.IsCancellationRequested) {
                _logger?.LogError("Error in usbmuxd connection, disconnecting all devices!");
            }

            // When then usbmuxd connection fails, generate remove events for every device that
            // is still present so applications know something has happened
            foreach (long deviceId in _connectedDevices.Keys) {
                _connectedDevices.Remove(deviceId, out UsbmuxdDevice? device);
                if (device is not null) {
                    _callback(device, UsbmuxdConnectionEventType.Remove);
                }
            }
            return UsbmuxdResult.UnknownError;
        }

        if (packet.Header.Length > Marshal.SizeOf(packet.Header) && packet.Header.Length == 0) {
            _logger?.LogError("Invalid packet received, payload is missing");
            return UsbmuxdResult.UnknownError;
        }

        switch (packet.Header.Message) {
            case UsbmuxdMessageType.Add: {
                AddResponse response = new AddResponse(packet.Header, packet.Payload);
                // The BINARY usbmux Add record (UsbmuxdDeviceRecord) predates network devices and carries
                // NO ConnectionType — taken literally it can only be Usb. But a WiFi device delivered over
                // this path would then classify Usb downstream, and any consumer that gates WiFi behaviour
                // on ConnectionType (ScribeHold's disconnect grace window) would treat a WiFi socket
                // idle-drop as a USB unplug = a connect/disconnect FLAP (ScribeHold #1914). So instead of
                // hardcoding Usb, recover the REAL ConnectionType (+NetworkAddress) by cross-referencing
                // the daemon's device list — which is served over the Plist protocol and DOES carry the
                // per-device ConnectionType. This mirrors how the Plist Attached path is already enriched.
                UsbmuxdDevice usbmuxdDevice =
                    ResolveAddedDevice(response.DeviceRecord.DeviceId, response.DeviceRecord.SerialNumber);
                _logger?.LogInformation(
                    "usbmux Add event (BINARY path) for device {Serial} id {DeviceId}: ConnectionType={ConnectionType}",
                    usbmuxdDevice.Serial, usbmuxdDevice.DeviceId, usbmuxdDevice.ConnectionType);
                AddDevice(usbmuxdDevice);
                break;
            }
            case UsbmuxdMessageType.Remove: {
                RemoveResponse response = new RemoveResponse(packet.Header, packet.Payload);
                RemoveDevice(response.DeviceId);
                break;
            }
            case UsbmuxdMessageType.Paired: {
                PairedResposne response = new PairedResposne(packet.Header, packet.Payload);
                PairedDevice(response.DeviceId);
                break;
            }
            case UsbmuxdMessageType.Plist: {
                PlistResponse response = new PlistResponse(packet.Header, packet.Payload);
                DictionaryNode responseDict = response.Plist.AsDictionaryNode();
                string messageType = responseDict["MessageType"].AsStringNode().Value;
                if (messageType == "Attached") {
                    UsbmuxdDevice usbmuxdDevice = new UsbmuxdDevice(responseDict["DeviceID"].AsIntegerNode(), responseDict["Properties"].AsDictionaryNode());
                    // The PLIST protocol's Attached payload carries the real per-device ConnectionType
                    // (USB vs Network) + NetworkAddress, parsed by the UsbmuxdDevice(IntegerNode,
                    // DictionaryNode) ctor. Log it so a real-device run shows exactly how each device was
                    // classified at the source — the decisive datum for ScribeHold #1914's WiFi-flap
                    // diagnosis (a device reported here as Network must reach ScribeHold as WiFi transport
                    // so the disconnect grace window engages; one reported as Usb correctly takes the fast
                    // unplug path).
                    _logger?.LogInformation(
                        "usbmux Attached event (PLIST path) for device {Serial} id {DeviceId}: ConnectionType={ConnectionType}",
                        usbmuxdDevice.Serial, usbmuxdDevice.DeviceId, usbmuxdDevice.ConnectionType);
                    AddDevice(usbmuxdDevice);
                }
                else if (messageType == "Detached") {
                    long deviceId = responseDict["DeviceID"].AsIntegerNode().SignedValue;
                    RemoveDevice(deviceId);
                }
                else if (messageType == "Paired") {
                    long deviceId = responseDict["DeviceID"].AsIntegerNode().SignedValue;
                    PairedDevice(deviceId);
                }
                else {
                    throw new UsbmuxException($"Unexpected message type {packet.Header.Message} with length {packet.Header.Length}");
                }
                break;
            }
            default: {
                if (packet.Header.Length > 0) {
                    _logger?.LogWarning("Unexpected message type {Message} with length {Length}", packet.Header.Message, packet.Header.Length);
                }
                break;
            }
        }

        return UsbmuxdResult.Ok;
    }

    private void PairedDevice(long deviceId) {
        if (_connectedDevices.TryGetValue(deviceId, out UsbmuxdDevice? device)) {
            _callback(device, UsbmuxdConnectionEventType.Paired);
        }
        else {
            _logger?.LogWarning("Got device paired message for id {deviceId}, but couldn't find the corresponding device in the list. This event will be ignored.", deviceId);
        }
    }

    private void RemoveDevice(long deviceId) {
        if (_connectedDevices.TryRemove(deviceId, out UsbmuxdDevice? device)) {
            _callback(device, UsbmuxdConnectionEventType.Remove);
        }
        else {
            _logger?.LogWarning("Got device remove message for id {deviceId}, but couldn't find the corresponding device in the list. This event will be ignored.", deviceId);
        }
    }

    public void Start() {
        if (_connectionMonitorTask == null) {
            _cancellationTokenSource = new CancellationTokenSource();
            _connectionMonitorTask = Task.Run(ConnectionListener, _cancellationTokenSource.Token);
        }
    }

    public void Stop() {
        _cancellationTokenSource.Cancel();
        _connectionMonitorTask = null;
    }
}
