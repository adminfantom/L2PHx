"""Inject packets via WebSocket API."""
import asyncio
import json
import sys

WS_URL = "ws://127.0.0.1:8877/ws"
OUT = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_ws_inject.txt"


async def run():
    import aiohttp
    lines = []

    def log(s):
        lines.append(s)
        with open(OUT, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        print(s)

    log(f"Connecting to {WS_URL}...")

    async with aiohttp.ClientSession() as session:
        async with session.ws_connect(WS_URL) as ws:
            log("Connected!")

            # 1. Get recent S2C packets to check for NPC dialogs
            await ws.send_json({"action": "get_packets", "direction": "S2C", "count": 200})
            resp = await ws.receive(timeout=5.0)
            if resp.type == aiohttp.WSMsgType.TEXT:
                data = json.loads(resp.data)
                pkts = data.get("data", {}).get("packets", [])
                log(f"\nGot {len(pkts)} S2C packets")

                # Look for ShowBoard or NPC HTML messages
                interesting = []
                for p in pkts:
                    name = p.get("name", "")
                    op = p.get("opcode", 0)
                    hex_data = p.get("hex", "")
                    # S_SHOW_BOARD = 0x7B, NPC HTML = 0x3E or similar
                    if "board" in name.lower() or "html" in name.lower() or op in [0x7B, 0x3E]:
                        interesting.append(p)
                        log(f"  NPC/Board: op=0x{op:02X} name={name} len={len(hex_data)//2}")
                        if hex_data:
                            try:
                                raw = bytes.fromhex(hex_data)
                                # Try to decode as UTF-16LE string
                                if len(raw) > 4:
                                    text = raw[1:].decode('utf-16-le', errors='replace')[:200]
                                    log(f"    text: {text[:100]}")
                            except:
                                pass

            # 2. Inject bypass "multisell 81381"
            log("\n--- Injecting bypass: multisell 81381 ---")
            await ws.send_json({"action": "inject_bypass", "command": "multisell 81381"})
            resp = await ws.receive(timeout=5.0)
            if resp.type == aiohttp.WSMsgType.TEXT:
                log(f"bypass result: {resp.data[:200]}")

            await asyncio.sleep(1.0)

            # 3. Check for new S2C packets (multisell response?)
            await ws.send_json({"action": "get_packets", "direction": "S2C", "count": 20})
            resp = await ws.receive(timeout=5.0)
            if resp.type == aiohttp.WSMsgType.TEXT:
                data = json.loads(resp.data)
                pkts = data.get("data", {}).get("packets", [])
                log(f"\nRecent S2C after bypass: {len(pkts)} pkts")
                for p in pkts[-10:]:
                    log(f"  {p.get('seq','?')} op=0x{p.get('opcode',0):02X} {p.get('name','?')} len={len(p.get('hex',''))//2}")

            log("\nDONE")


asyncio.run(run())
