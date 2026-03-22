import os
with open(r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_remote_test.txt", "w") as f:
    f.write("remote_exec works!\n")
    f.write(f"pid={os.getpid()}\n")
