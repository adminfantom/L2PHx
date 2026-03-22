"""Hot-patch: encrypt injected C2S packets with shadow XOR cipher.

Monkey-patches wrap_relay_0x06 to encrypt game_body via shadow_xor_c2s
before applying relay double-XOR obfuscation.

Inject via: python -c "import sys; sys.remote_exec(643444, '_hotpatch_xor_inject.py')"
"""
import sys
import importlib

def apply_patch():
    # Find the _engine module
    engine = sys.modules.get('_engine')
    if not engine:
        for name, mod in sys.modules.items():
            if 'engine' in name.lower() and hasattr(mod, 'wrap_relay_0x06'):
                engine = mod
                break
    if not engine:
        print("[HOTPATCH] ERROR: _engine module not found")
        return

    # Find the proxy instance to get crypto state
    proxy_instance = None
    bridge = sys.modules.get('__main__')
    if bridge:
        for attr_name in dir(bridge):
            obj = getattr(bridge, attr_name, None)
            if obj and hasattr(obj, 'proxy') and hasattr(getattr(obj, 'proxy', None), 'crypto'):
                proxy_instance = obj.proxy
                break
        # Also check global vars
        if not proxy_instance:
            for name in list(vars(bridge)):
                obj = vars(bridge)[name]
                if hasattr(obj, 'crypto') and hasattr(obj, 'server_sock'):
                    proxy_instance = obj
                    break

    # Try finding via engine's active instances
    if not proxy_instance:
        for name, mod in sys.modules.items():
            for attr_name in dir(mod):
                try:
                    obj = getattr(mod, attr_name, None)
                    if obj and hasattr(obj, 'proxy') and hasattr(getattr(obj, 'proxy', None), 'crypto'):
                        proxy_instance = obj.proxy
                        break
                except:
                    pass
            if proxy_instance:
                break

    if not proxy_instance:
        print("[HOTPATCH] WARNING: proxy instance not found, will search at call time")

    # Save reference to original function
    original_wrap = engine.wrap_relay_0x06

    # Check if already patched
    if hasattr(engine, '_original_wrap_relay_0x06'):
        print("[HOTPATCH] Already patched! Updating reference...")
        original_wrap = engine._original_wrap_relay_0x06
    else:
        engine._original_wrap_relay_0x06 = original_wrap

    def wrap_relay_0x06_encrypted(game_body):
        """Encrypt game body with shadow XOR before relay wrapping."""
        nonlocal proxy_instance

        encrypted = game_body
        try:
            # Find crypto at call time if not found earlier
            px = proxy_instance
            if not px:
                bridge = sys.modules.get('__main__')
                if bridge:
                    for name in list(vars(bridge)):
                        obj = vars(bridge).get(name)
                        if hasattr(obj, 'crypto') and hasattr(obj, 'server_sock'):
                            px = obj
                            proxy_instance = px
                            break

            if px and hasattr(px, 'crypto'):
                crypto = px.crypto
                if crypto and hasattr(crypto, 'shadow_xor_c2s') and crypto.shadow_xor_c2s:
                    encrypted = bytes(crypto.shadow_xor_c2s.encrypt(bytearray(game_body)))
                    op = game_body[0]
                    enc_op = encrypted[0]
                    print(f"[HOTPATCH] XOR-encrypted injection: plain_op=0x{op:02X} enc_op=0x{enc_op:02X} len={len(game_body)}")
                else:
                    print(f"[HOTPATCH] No shadow_xor_c2s available, sending plaintext")
            else:
                print(f"[HOTPATCH] No proxy/crypto found, sending plaintext")
        except Exception as e:
            print(f"[HOTPATCH] Encrypt error: {e}, sending plaintext")

        return original_wrap(encrypted)

    # Apply monkey-patch
    engine.wrap_relay_0x06 = wrap_relay_0x06_encrypted
    print(f"[HOTPATCH] wrap_relay_0x06 PATCHED with XOR encryption!")
    print(f"[HOTPATCH] proxy_instance: {proxy_instance}")
    if proxy_instance and hasattr(proxy_instance, 'crypto'):
        c = proxy_instance.crypto
        print(f"[HOTPATCH] crypto: shadow_enabled={getattr(c, 'shadow_enabled', '?')}")
        print(f"[HOTPATCH] shadow_xor_c2s: {c.shadow_xor_c2s}")
        if c.shadow_xor_c2s:
            print(f"[HOTPATCH] shadow key: {bytes(c.shadow_xor_c2s.key).hex()}")

apply_patch()
