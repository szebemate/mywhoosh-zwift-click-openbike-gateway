#!/usr/bin/env python3
"""
Standalone OpenBikeControl Server for macOS

Acts as a virtual trainer / controller bridge that:
1. Listens on TCP port 36867
2. Advertises via mDNS as _openbikecontrol._tcp.local.
3. Accepts connections from MyWhoosh
4. Connects to Zwift Click V2 via BLE and listens for button presses
5. Falls back to keyboard input (q/e) for testing

Zwift Click V2 Protocol:
  - Encrypted BLE notifications (ECDH + AES-CCM)
  - Opcode 0x37 = button event
  - Requires handshake and session key establishment

Requirements:
  uv sync

Usage:
  uv run python openbikecontrol_server.py

Keys (fallback):
  E = Shift UP   (gear +)
  Q = Shift DOWN (gear -)
  Ctrl-C = Quit
"""

import asyncio
import os
import socket
import sys
import threading
import termios
import tty
import time
from zeroconf import ServiceInfo, Zeroconf
from bleak import BleakClient, BleakScanner

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH, SECP256R1, EllipticCurvePublicKey, generate_private_key,
)
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

DEBUG = os.environ.get("ZWIFT_DEBUG", "").lower() in ("1", "true", "yes")

# OpenBikeControl Protocol constants
MESSAGE_TYPE_BUTTON_STATE = 0x01
MESSAGE_TYPE_DEVICE_STATUS = 0x02

BUTTON_SHIFT_UP = 0x01
BUTTON_SHIFT_DOWN = 0x02

BUTTON_PRESSED = 0x01
BUTTON_RELEASED = 0x00

PORT = 36867

# Zwift Click V2 BLE constants
ZWIFT_SERVICE_UUID = "00000001-19ca-4651-86e5-fa29dcdd09d1"
ZWIFT_SERVICE_UUID_2 = "0000fc82-0000-1000-8000-00805f9b34fb"

ASYNC_CHAR_UUID = "00000002-19ca-4651-86e5-fa29dcdd09d1"
SYNC_RX_CHAR_UUID = "00000003-19ca-4651-86e5-fa29dcdd09d1"
SYNC_TX_CHAR_UUID = "00000004-19ca-4651-86e5-fa29dcdd09d1"
UNKNOWN_5_CHAR_UUID = "00000005-19ca-4651-86e5-fa29dcdd09d1"
UNKNOWN_6_CHAR_UUID = "00000006-19ca-4651-86e5-fa29dcdd09d1"

OPCODE_CLICK = 0x37
OPCODE_BATTERY = 0x19

# Protobuf field indices
FIELD_PLUS = 1   # + button (right puck) → Shift UP
FIELD_MINUS = 2  # − button (left puck) → Shift DOWN

# Handshake constants
_RIDEON = b"RideOn"
_REQUEST_MARKER = bytes([0x00, 0x09])
_RESPONSE_HEADER = b"RideOn\x01\x03"

# AES-CCM parameters
_AES_TAG_LEN = 4
_COUNTER_LEN = 4
_HKDF_LEN = 36  # 32 bytes AES key + 4 bytes IV prefix


# ─────────────────────────────────────────────────────────────────────────────
# Crypto Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    """Minimal protobuf varint decoder."""
    result = shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
    return result, pos


def parse_button_states(payload: bytes) -> tuple[int, int]:
    """Parse button states from protobuf payload. Returns (plus, minus) where 0=pressed, 1=released."""
    plus = minus = 1  # default: released
    pos = 0
    while pos < len(payload):
        tag, pos = _read_varint(payload, pos)
        field_num = tag >> 3
        wire_type = tag & 0x07
        if wire_type == 0:
            value, pos = _read_varint(payload, pos)
            if field_num == FIELD_PLUS:
                plus = value
            elif field_num == FIELD_MINUS:
                minus = value
        elif wire_type == 2:
            length, pos = _read_varint(payload, pos)
            pos += length
        else:
            break
    return plus, minus


def _make_handshake() -> tuple[bytes, object]:
    """Generate ECDH handshake."""
    priv = generate_private_key(SECP256R1())
    pub_bytes = priv.public_key().public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint)
    handshake = _RIDEON + _REQUEST_MARKER + pub_bytes[1:]  # Strip 0x04 prefix
    return handshake, priv


def _derive_session_key(priv_key, device_response: bytes) -> tuple[bytes, bytes]:
    """Derive AES key from ECDH shared secret. Returns (aes_key_32, iv_prefix_4)."""
    device_key_64 = device_response[8:]
    device_pub = EllipticCurvePublicKey.from_encoded_point(
        SECP256R1(), b"\x04" + device_key_64)

    shared_secret = priv_key.exchange(ECDH(), device_pub)

    our_key_64 = priv_key.public_key().public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint
    )[1:]  # Strip 0x04 prefix

    hkdf_out = HKDF(
        algorithm=hashes.SHA256(),
        length=_HKDF_LEN,
        salt=device_key_64 + our_key_64,
        info=b"",
    ).derive(shared_secret)

    return hkdf_out[:32], hkdf_out[32:]


def _decrypt(raw: bytes, aes_key: bytes, iv_prefix: bytes) -> bytes:
    """Decrypt AES-CCM notification frame."""
    counter = raw[:_COUNTER_LEN]
    ct_plus_tag = raw[_COUNTER_LEN:]
    nonce = iv_prefix + counter
    aesccm = AESCCM(aes_key, tag_length=_AES_TAG_LEN)
    return aesccm.decrypt(nonce, ct_plus_tag, None)


# ─────────────────────────────────────────────────────────────────────────────
# BLE Handler
# ─────────────────────────────────────────────────────────────────────────────

class ZwiftClickV2Handler:
    """Handles Zwift Click V2 BLE device (encrypted ECDH + AES-CCM protocol)."""

    def __init__(self, server):
        self.server = server
        self.client = None
        self.last_plus = 1  # 1 = released
        self.last_minus = 1
        self.aes_key = None
        self.iv_prefix = None
        self.priv_key = None

    async def find_device(self, timeout=10):
        """Scan for Zwift Click device."""
        print(
            "[BLE] Scanning for Zwift Click V2 device (timeout: {} s)...".format(timeout))

        def device_filter(device, adv_data):
            name = (device.name or "").lower()
            uuids = {str(u).lower() for u in (adv_data.service_uuids or [])}
            return (
                "click" in name
                or ZWIFT_SERVICE_UUID.lower() in uuids
                or ZWIFT_SERVICE_UUID_2.lower() in uuids
            )

        try:
            device = await asyncio.wait_for(
                BleakScanner.find_device_by_filter(device_filter),
                timeout=timeout
            )
            if device:
                print(f"[BLE] Found: {device.name!r} ({device.address})")
                return device
        except asyncio.TimeoutError:
            print("[BLE] Scan timeout - no Zwift Click device found")
            return None

    async def connect(self, device):
        """Connect to Zwift Click and perform handshake."""
        try:
            self.client = BleakClient(device)
            await self.client.connect()
            print(f"[BLE] Connected to {device.name}")

            # Find service
            service_uuid = None
            for service in self.client.services:
                if service.uuid in [ZWIFT_SERVICE_UUID, ZWIFT_SERVICE_UUID_2]:
                    service_uuid = service.uuid
                    break

            if not service_uuid:
                print(
                    "[BLE] Zwift service not found - device may need unlock via Zwift app")
                return False

            # Subscribe to notifications in correct order
            await self.client.start_notify(ASYNC_CHAR_UUID, self._on_async)
            await self.client.start_notify(SYNC_TX_CHAR_UUID, self._on_sync_tx)
            await self.client.start_notify(UNKNOWN_5_CHAR_UUID, self._on_async)
            await self.client.start_notify(UNKNOWN_6_CHAR_UUID, self._on_sync_tx)
            print("[BLE] Subscribed to notifications")

            # Send handshake
            handshake, self.priv_key = _make_handshake()
            if DEBUG:
                print(f"[DBG] Sending handshake: {handshake.hex()}")
            await self.client.write_gatt_char(SYNC_RX_CHAR_UUID, handshake, response=True)
            print("[BLE] Handshake sent - waiting for session key...")

            return True

        except Exception as e:
            print(f"[BLE] Connection error: {e}")
            return False

    def _on_async(self, sender, data):
        """Handle async notifications (button presses)."""
        if DEBUG:
            print(f"[DBG] async ({len(data)} B): {bytes(data).hex()}")

        if self.aes_key is None:
            # Try parsing as plaintext before key established
            self._handle_plaintext(bytes(data))
            return

        try:
            plaintext = _decrypt(bytes(data), self.aes_key, self.iv_prefix)
            self._handle_plaintext(plaintext)
        except Exception as exc:
            if DEBUG:
                print(f"[DBG] Decrypt error: {exc}")

    def _on_sync_tx(self, sender, data):
        """Handle sync_tx indications (key establishment)."""
        if DEBUG:
            print(f"[DBG] sync_tx ({len(data)} B): {bytes(data).hex()}")

        if bytes(data[:8]) == _RESPONSE_HEADER and len(data) >= 72:
            try:
                self.aes_key, self.iv_prefix = _derive_session_key(
                    self.priv_key, bytes(data))
                print("[BLE] Session key established - notifications are encrypted")
                if DEBUG:
                    print(
                        f"[DBG] aes_key={self.aes_key.hex()} iv_prefix={self.iv_prefix.hex()}")
            except Exception as exc:
                print(f"[BLE] Key derivation failed: {exc}")

    def _handle_plaintext(self, plaintext: bytes):
        """Process decrypted button event."""
        if not plaintext:
            return

        opcode = plaintext[0]
        if DEBUG:
            print(f"[DBG] opcode=0x{opcode:02x} payload={plaintext[1:].hex()}")

        if opcode != OPCODE_CLICK:
            return

        plus, minus = parse_button_states(plaintext[1:])
        if DEBUG:
            print(f"[DBG] plus={plus} minus={minus} (0=pressed 1=released)")

        # Rising edge detection
        if plus == 0 and self.last_plus == 1:
            print("[BLE] Button: Shift UP")
            self.server.send_shift(1)

        if minus == 0 and self.last_minus == 1:
            print("[BLE] Button: Shift DOWN")
            self.server.send_shift(-1)

        self.last_plus = plus
        self.last_minus = minus

    async def disconnect(self):
        """Disconnect from BLE device."""
        if self.client:
            try:
                await self.client.disconnect()
                print("[BLE] Disconnected")
            except Exception as e:
                print(f"[BLE] Disconnect error: {e}")


class OpenBikeControlServer:
    def __init__(self):
        self.server_socket = None
        self.clients = []
        self.running = False
        self.lock = threading.Lock()
        self.zeroconf = None
        self.service_info = None

    def start(self):
        """Start the TCP server and mDNS advertising."""
        print("[SERVER] Starting OpenBikeControl Server on port", PORT)

        # Create TCP server
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(("0.0.0.0", PORT))
        self.server_socket.listen(5)
        self.running = True

        print(f"[SERVER] TCP listening on 0.0.0.0:{PORT}")

        # Start mDNS advertising
        self._start_mdns()

        # Start accept thread
        threading.Thread(target=self._accept_loop, daemon=True).start()

        print("[SERVER] Ready for connections from MyWhoosh")

    def stop(self):
        """Stop server and clean up."""
        self.running = False

        with self.lock:
            for client in self.clients:
                try:
                    client.close()
                except:
                    pass
            self.clients.clear()

        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass

        if self.zeroconf:
            try:
                self.zeroconf.unregister_all_services()
                self.zeroconf.close()
            except:
                pass

        print("[SERVER] Stopped")

    def _start_mdns(self):
        """Advertise via mDNS as _openbikecontrol._tcp.local."""
        try:
            # Get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except:
            local_ip = "127.0.0.1"

        print(f"[mDNS] Advertising on {local_ip}:{PORT}")

        self.service_info = ServiceInfo(
            type_="_openbikecontrol._tcp.local.",
            name="OpenBikeControl._openbikecontrol._tcp.local.",
            addresses=[socket.inet_aton(local_ip)],
            port=PORT,
            properties={
                "version": "1",
                "id": "python-openbikecontrol",
                "name": "OpenBikeControl",
                "service-uuids": "d273f680-d548-419d-b9d1-fa0472345229",
                "manufacturer": "Open-Zwift",
                "model": "VirtualBike",
            },
            server="openbikecontrol.local.",
        )

        self.zeroconf = Zeroconf()
        self.zeroconf.register_service(self.service_info)
        print("[mDNS] Service registered")

    def _accept_loop(self):
        """Accept incoming connections from MyWhoosh."""
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                print(f"[CLIENT] Connected from {addr[0]}:{addr[1]}")

                with self.lock:
                    self.clients.append(client_socket)

                # Start receive thread for this client
                threading.Thread(
                    target=self._client_loop,
                    args=(client_socket, addr),
                    daemon=True,
                ).start()

            except Exception as e:
                if self.running:
                    print(f"[SERVER] Accept error: {e}")

    def _client_loop(self, client_socket, addr):
        """Handle client connection."""
        try:
            while self.running:
                data = client_socket.recv(1024)
                if not data:
                    print(f"[CLIENT] {addr[0]} disconnected")
                    break
                # Echo received data for debugging
                print(f"[RECV from {addr[0]}] {data.hex()}")

        except Exception as e:
            print(f"[CLIENT] Error from {addr[0]}: {e}")
        finally:
            with self.lock:
                try:
                    self.clients.remove(client_socket)
                except:
                    pass
            client_socket.close()

    def broadcast_button_state(self, button_id, button_state):
        """Send button state to all connected clients."""
        message = bytes([MESSAGE_TYPE_BUTTON_STATE, button_id, button_state])

        with self.lock:
            for client in self.clients:
                try:
                    client.sendall(message)
                except Exception as e:
                    print(f"[SEND] Error: {e}")

        state_str = "pressed" if button_state else "released"
        button_str = "SHIFT_UP" if button_id == BUTTON_SHIFT_UP else "SHIFT_DOWN"
        print(f"[SEND] {button_str} {state_str}: {message.hex()}")

    def send_shift(self, direction):
        """Send shift command. direction: 1 (up) or -1 (down)."""
        button_id = BUTTON_SHIFT_UP if direction > 0 else BUTTON_SHIFT_DOWN
        # Edge-triggered: press then release
        self.broadcast_button_state(button_id, BUTTON_PRESSED)
        self.broadcast_button_state(button_id, BUTTON_RELEASED)


async def ble_connect_loop(server):
    """Try to connect to Zwift Click V2, with retry logic."""
    while True:
        handler = ZwiftClickV2Handler(server)

        try:
            device = await handler.find_device(timeout=10)
            if device:
                if await handler.connect(device):
                    print("[BLE] Ready - press +/- on Zwift Click to shift")
                    # Keep connection alive
                    await asyncio.sleep(1000)
        except Exception as e:
            print(f"[BLE] Error: {e}")
        finally:
            await handler.disconnect()

        await asyncio.sleep(2)
        print("[BLE] Retrying scan...")


def run_ble_thread(server):
    """Run BLE event loop in background thread."""
    try:
        asyncio.run(ble_connect_loop(server))
    except KeyboardInterrupt:
        pass


def main():
    server = OpenBikeControlServer()
    server.start()

    print("\n" + "=" * 60)
    print("OpenBikeControl Server Ready")
    print("=" * 60)
    print("\nMyWhoosh should auto-discover this server.")
    print("If not, manually add it in MyWhoosh settings.\n")
    print("Starting BLE scan for Zwift Click V2...")
    print("=" * 60)

    # Start BLE connection thread
    ble_thread = threading.Thread(
        target=run_ble_thread, args=(server,), daemon=True)
    ble_thread.start()

    print("\nFallback keyboard control (if BLE not available):")
    print("  E = Shift UP   (gear +)")
    print("  Q = Shift DOWN (gear -)")
    print("  Ctrl-C = Quit")
    print("=" * 60 + "\n")

    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        while True:
            ch = sys.stdin.read(1)
            if ch in ("\x03", "\x1b"):  # Ctrl-C or Esc
                break
            if ch in ("e", "E"):
                server.send_shift(1)
            elif ch in ("q", "Q"):
                server.send_shift(-1)
    except KeyboardInterrupt:
        pass
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        server.stop()
        print("\nStopped.")


if __name__ == "__main__":
    main()
