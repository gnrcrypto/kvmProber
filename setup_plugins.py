import os

PLUGIN_DIR = "plugins"
os.makedirs(PLUGIN_DIR, exist_ok=True)

plugins = {
    "kvm.py": '''from dynamic_kvm_prober import generic_probe
import fcntl

def probe(dev_path):
    print(f"[PLUGIN:kvm] Probing {dev_path} with KVM-specific IOCTLs.")
    try:
        with open(dev_path, 'rb+', buffering=0) as f:
            for code in [0xAE00, 0xAE01]:
                try:
                    fcntl.ioctl(f, code, b'\\x00'*8)
                except Exception as e:
                    print(f"  [!] IOCTL {hex(code)} failed: {e}")
    except Exception as e:
        print(f"[-] Failed to open {dev_path}: {e}")
    generic_probe(dev_path)
''',
    "vhost-vsock.py": '''from dynamic_kvm_prober import generic_probe

def probe(dev_path):
    print(f"[PLUGIN:vhost-vsock] Probing {dev_path} with vhost-vsock logic.")
    # Add vhost-vsock specific IOCTLs or fuzzing here
    generic_probe(dev_path)
''',
    "vhost-net.py": '''from dynamic_kvm_prober import generic_probe

def probe(dev_path):
    print(f"[PLUGIN:vhost-net] Probing {dev_path} with vhost-net logic.")
    # Add vhost-net specific IOCTLs or fuzzing here
    generic_probe(dev_path)
''',
    "vfio.py": '''from dynamic_kvm_prober import generic_probe
import os

def probe(dev_path):
    print(f"[PLUGIN:vfio] Probing {dev_path} with vfio logic.")
    if not os.path.isfile(dev_path):
        print(f"  [!] {dev_path} is not a file, skipping.")
        return
    generic_probe(dev_path)
''',
    "net.py": '''from dynamic_kvm_prober import generic_probe
import os

def probe(dev_path):
    print(f"[PLUGIN:net] Probing {dev_path} with net logic.")
    if not os.path.isfile(dev_path):
        print(f"  [!] {dev_path} is not a file, skipping.")
        return
    generic_probe(dev_path)
'''
}

for fname, content in plugins.items():
    path = os.path.join(PLUGIN_DIR, fname)
    with open(path, "w") as f:
        f.write(content)
    print(f"[+] Wrote {path}")

print("[*] Plugin setup complete.")
