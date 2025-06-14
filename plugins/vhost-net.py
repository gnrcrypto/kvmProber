from dynamic_kvm_prober import generic_probe

def probe(dev_path):
    print(f"[PLUGIN:vhost-net] Probing {dev_path} with vhost-net logic.")
    # Add vhost-net specific IOCTLs or fuzzing here
    generic_probe(dev_path)
