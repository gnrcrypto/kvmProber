from dynamic_kvm_prober import generic_probe

def probe(dev_path):
    print(f"[PLUGIN:vhost-vsock] Probing {dev_path} with vhost-vsock logic.")
    # Add vhost-vsock specific IOCTLs or fuzzing here
    generic_probe(dev_path)
