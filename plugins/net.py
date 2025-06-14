from dynamic_kvm_prober import generic_probe
import os

def probe(dev_path):
    print(f"[PLUGIN:net] Probing {dev_path} with net logic.")
    if not os.path.isfile(dev_path):
        print(f"  [!] {dev_path} is not a file, skipping.")
        return
    generic_probe(dev_path)
