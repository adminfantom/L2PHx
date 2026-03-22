#!/usr/bin/env python
"""
L2 MCP Bridge — тонкий MCP сервер (stdio) → REST API l2phx.py

Подключается к уже работающему l2phx.py через HTTP API.
Не требует админ-прав (WinDivert работает в l2phx.py).

Запуск: автоматически через .mcp.json
"""

import asyncio
import json
import sys
import urllib.request
import urllib.error

API_BASE = "http://127.0.0.1:8877/api"


def api_call(action: str, data: dict = None) -> dict:
    """POST запрос к REST API l2phx.py."""
    payload = json.dumps({"action": action, **(data or {})}).encode()
    req = urllib.request.Request(
        f"{API_BASE}/{action}",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.URLError as e:
        return {"error": f"l2phx.py not running or unreachable: {e}"}
    except Exception as e:
        return {"error": str(e)}


async def run_mcp():
    from mcp.server import Server
    import mcp.types as types

    server = Server("l2-packet-proxy")

    def _schema(**props):
        req = [k for k, v in props.items() if v.pop("required", False)]
        return {"type": "object", "properties": props,
                **({"required": req} if req else {})}

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        T = types.Tool
        return [
            T(name="l2_get_packets",
              description="Последние перехваченные L2 пакеты. "
                          "Фильтр по направлению, опкоду, имени.",
              inputSchema=_schema(
                  count={"type": "integer", "default": 50,
                         "description": "Количество пакетов"},
                  direction={"type": "string", "enum": ["C2S", "S2C", "all"],
                             "default": "all"},
                  opcode={"type": "string",
                          "description": "Hex опкод ('49' для Say2)"},
                  name_filter={"type": "string",
                               "description": "Подстрока в имени пакета"},
              )),
            T(name="l2_get_stats",
              description="Статистика пакетов: кол-во по типам и направлениям.",
              inputSchema={"type": "object", "properties": {}}),
            T(name="l2_get_crypto",
              description="Состояние криптографии: BF/XOR ключи, сессия.",
              inputSchema={"type": "object", "properties": {}}),
            T(name="l2_get_status",
              description="Статус прокси: running, connected, кол-во пакетов.",
              inputSchema={"type": "object", "properties": {}}),
            T(name="l2_inject_raw",
              description="Инъекция сырого C→S пакета (hex). "
                          "Первый байт = опкод.",
              inputSchema=_schema(
                  hex_data={"type": "string", "required": True,
                            "description": "Hex данные пакета без заголовка длины"},
              )),
            T(name="l2_inject_say2",
              description="Отправить сообщение в чат.",
              inputSchema=_schema(
                  text={"type": "string", "required": True},
                  chat_type={"type": "integer", "default": 0,
                             "description": "0=all,1=shout,2=tell,3=party,"
                                            "4=clan,8=trade,15=hero"},
                  target={"type": "string", "default": "",
                          "description": "Получатель (для tell)"},
              )),
            T(name="l2_inject_bypass",
              description="BypassToServer (0x23) — NPC диалоги, внутренние команды.",
              inputSchema=_schema(
                  command={"type": "string", "required": True,
                           "description": "Bypass строка"},
              )),
            T(name="l2_inject_admin",
              description="SendBypassBuildCmd (0x74) — GM/Admin команды.",
              inputSchema=_schema(
                  command={"type": "string", "required": True,
                           "description": "admin_gmspeed 5, admin_enchant 65535"},
              )),
            T(name="l2_inject_use_item",
              description="UseItem (0x19) — использовать предмет.",
              inputSchema=_schema(
                  object_id={"type": "integer", "required": True},
              )),
            T(name="l2_inject_enchant",
              description="RequestEnchantItem (0x5F).",
              inputSchema=_schema(
                  object_id={"type": "integer", "required": True},
              )),
            T(name="l2_inject_action",
              description="Action (0x1F) — клик по объекту.",
              inputSchema=_schema(
                  object_id={"type": "integer", "required": True},
                  shift={"type": "integer", "default": 0,
                         "description": "0=простой клик, 1=shift-клик"},
              )),
            T(name="l2_inject_s2c",
              description="Инъекция S→C пакета (hex) — спуфинг от сервера клиенту.",
              inputSchema=_schema(
                  hex_data={"type": "string", "required": True},
              )),
            T(name="l2_flood",
              description="Отправить пакет N раз — race condition тест.",
              inputSchema=_schema(
                  hex_data={"type": "string", "required": True},
                  count={"type": "integer", "default": 10},
              )),
            T(name="l2_multisell",
              description="MultiSellChoose (0xB0) — покупка в мультиселе.",
              inputSchema=_schema(
                  list_id={"type": "integer", "required": True},
                  entry_id={"type": "integer", "required": True},
                  amount={"type": "integer", "default": 1},
              )),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list:
        # Маппинг MCP tool name → REST API action
        action_map = {
            "l2_get_packets": "get_packets",
            "l2_get_stats": "get_stats",
            "l2_get_crypto": "get_crypto",
            "l2_get_status": "get_status",
            "l2_inject_raw": "inject_raw",
            "l2_inject_say2": "inject_say2",
            "l2_inject_bypass": "inject_bypass",
            "l2_inject_admin": "inject_admin",
            "l2_inject_use_item": "inject_use_item",
            "l2_inject_enchant": "inject_enchant",
            "l2_inject_action": "inject_action",
            "l2_inject_s2c": "inject_s2c",
            "l2_flood": "flood",
            "l2_multisell": "inject_raw",  # будет через raw
        }

        action = action_map.get(name, name.replace("l2_", ""))

        # Для multisell строим hex вручную
        if name == "l2_multisell":
            import struct
            pkt = struct.pack("<BIIq", 0xB0,
                              arguments["list_id"],
                              arguments["entry_id"],
                              arguments.get("amount", 1)) + b'\x00' * 24
            arguments = {"hex_data": pkt.hex()}
            action = "inject_raw"

        # Для say2 нужно построить пакет
        if name == "l2_inject_say2":
            text = arguments.get("text", "")
            chat_type = arguments.get("chat_type", 0)
            target = arguments.get("target", "")
            text_bytes = text.encode("utf-16-le") + b'\x00\x00'
            target_bytes = target.encode("utf-16-le") + b'\x00\x00'
            import struct
            pkt = b'\x49' + text_bytes + struct.pack("<I", chat_type) + target_bytes
            arguments = {"hex_data": pkt.hex()}
            action = "inject_raw"

        # Для bypass/admin/use_item/enchant/action — строим hex
        if name == "l2_inject_bypass":
            cmd = arguments["command"].encode("utf-16-le") + b'\x00\x00'
            arguments = {"hex_data": (b'\x23' + cmd).hex()}
            action = "inject_raw"

        if name == "l2_inject_admin":
            cmd = arguments["command"].encode("utf-16-le") + b'\x00\x00'
            arguments = {"hex_data": (b'\x74' + cmd).hex()}
            action = "inject_raw"

        if name == "l2_inject_use_item":
            import struct
            pkt = struct.pack("<BII", 0x19, arguments["object_id"], 0)
            arguments = {"hex_data": pkt.hex()}
            action = "inject_raw"

        if name == "l2_inject_enchant":
            import struct
            pkt = struct.pack("<BI", 0x5F, arguments["object_id"])
            arguments = {"hex_data": pkt.hex()}
            action = "inject_raw"

        if name == "l2_inject_action":
            import struct
            pkt = struct.pack("<BIIIIb", 0x1F, arguments["object_id"],
                              0, 0, 0, arguments.get("shift", 0))
            arguments = {"hex_data": pkt.hex()}
            action = "inject_raw"

        result = await asyncio.get_event_loop().run_in_executor(
            None, api_call, action, arguments)

        return [types.TextContent(
            type="text",
            text=json.dumps(result, ensure_ascii=False, indent=2),
        )]

    from mcp.server.stdio import stdio_server
    async with stdio_server() as (rs, ws):
        print("[MCP-BRIDGE] Serving on stdio → http://127.0.0.1:8877/api",
              file=sys.stderr)
        await server.run(rs, ws, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(run_mcp())
