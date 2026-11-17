# OpenBikeControl Server for macOS

Standalone OpenBikeControl server that connects your **Zwift Click V2** controller to **MyWhoosh** via encrypted BLE and OpenBikeControl protocol.

## Features

✓ **Zwift Click V2 BLE Support** - Encrypted ECDH + AES-CCM protocol  
✓ **OpenBikeControl Protocol** - Binary button events on port 36867  
✓ **mDNS Advertisement** - MyWhoosh auto-discovers the server  
✓ **Keyboard Fallback** - Press E/Q for testing  
✓ **Auto-Retry** - Reconnects if BLE drops  

## Quick Start

### 1. Install

```bash
cd <repo>
uv sync
```

### 2. Run

```bash
uv run python openbikecontrol_server.py
```

### 3. Connect MyWhoosh

1. Open MyWhoosh on your Mac
2. Enable **Settings → Companion App** (or **OpenBikeControl**)
3. Server auto-discovers within 5-10 seconds
4. Select **"Zwift OpenBikeControl"** and connect

### 4. Test

Press **+** or **-** on your Zwift Click → watch gears change in MyWhoosh!

## Expected Output

```
============================================================
OpenBikeControl Server Ready
============================================================

MyWhoosh should auto-discover this server.
If not, manually add it in MyWhoosh settings.

Starting BLE scan for Zwift Click V2...
============================================================

Fallback keyboard control (if BLE not available):
  E = Shift UP   (gear +)
  Q = Shift DOWN (gear -)
  Ctrl-C = Quit
============================================================

[SERVER] Starting OpenBikeControl Server on port 36867
[SERVER] TCP listening on 0.0.0.0:36867
[mDNS] Advertising on 192.168.1.X:36867
[mDNS] Service registered
[SERVER] Ready for connections from MyWhoosh
[BLE] Scanning for Zwift Click V2 device (timeout: 10 s)...
[BLE] Found: 'Zwift Click' (1AE77357-D182-AE59-5253-41DE14FE0F8A)
[BLE] Connected to Zwift Click
[BLE] Subscribed to notifications
[BLE] Handshake sent - waiting for session key...
[BLE] Session key established - notifications are encrypted
[BLE] Ready - press +/- on Zwift Click to shift
```

## Troubleshooting

### Zwift Click not found
- ✓ Check device is powered on
- ✓ Check it's not connected to another app  
- ✓ If new: pair once in official Zwift app first
- ✓ Auto-retries every 2 seconds

### MyWhoosh doesn't find the server
- ✓ Check mDNS is working (should show in network settings)
- ✓ Manually add `127.0.0.1:36867` in MyWhoosh settings
- ✓ Wait 5-10 seconds for mDNS propagation

### Buttons work but MyWhoosh doesn't shift
- ✓ Verify **Companion App** is enabled in MyWhoosh
- ✓ Check MyWhoosh window has focus
- ✓ Try keyboard test first (press E/Q)

## Keyboard Test Mode

If BLE device isn't available, test with keyboard:

```bash
uv run python openbikecontrol_server.py

# Press 'E' in terminal → Shift UP
# Press 'Q' in terminal → Shift DOWN
```

## Debug Mode

Enable detailed debug output:

```bash
ZWIFT_DEBUG=1 uv run python openbikecontrol_server.py
```

Shows:
- Raw BLE notifications
- Encryption/decryption details
- Protobuf parsing
- Session key exchange

## Technical Details

### Zwift Click V2 BLE Protocol

- **Service UUIDs**: 
  - `00000001-19ca-4651-86e5-fa29dcdd09d1`
  - `0000fc82-0000-1000-8000-00805f9b34fb`
  
- **Characteristics**:
  - `00000002-...` = Async notifications (button events)
  - `00000003-...` = Sync RX (send handshake)
  - `00000004-...` = Sync TX (receive session key)

- **Encryption**:
  - ECDH key exchange (P-256)
  - HKDF-SHA256 key derivation
  - AES-CCM-128 with 4-byte tag

- **Button Events**:
  - Opcode: `0x37`
  - Protobuf-encoded button state
  - Field 1: Plus button (right puck)
  - Field 2: Minus button (left puck)
  - Value: 0 = pressed, 1 = released

### OpenBikeControl Protocol (port 36867)

**Message Format:**
```
[0x01] [ButtonID] [ButtonState]
  0x01 = Shift UP
  0x02 = Shift DOWN
  0x01 = Pressed
  0x00 = Released
```

**mDNS Service:**
- Type: `_openbikecontrol._tcp.local.`
- UUID: `d273f680-d548-419d-b9d1-fa0472345229`
- Model: VirtualBike

## Files

- `openbikecontrol_server.py` - Main server
- `pyproject.toml` - Python project config
- `README.md` - This file

## Requirements

- macOS 10.14+
- Python 3.11+
- Zwift Click V2
- MyWhoosh app
- Bluetooth adapter

## License

Part of BikeControl project. See LICENSE in parent directory.

## References

- Protocol reverse-engineered from qdomyos-zwift
- Encryption based on official Zwift app behavior
- OpenBikeControl standard (Companion App protocol)
