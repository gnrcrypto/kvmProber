from dynamic_kvm_prober import generic_probe
import fcntl

def probe(dev_path):
    print(f"[PLUGIN:kvm] Probing {dev_path} with KVM-specific IOCTLs.")
    try:
        with open(dev_path, 'rb+', buffering=0) as f:
            for code in [0xAE00, 0xAE01]:
                try:
                    fcntl.ioctl(f, code, b'\x00'*8)
                except Exception as e:
                    print(f"  [!] IOCTL {hex(code)} failed: {e}")
    except Exception as e:
        print(f"[-] Failed to open {dev_path}: {e}")
    generic_probe(dev_path)
