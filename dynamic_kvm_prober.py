import os
import fcntl
import importlib
import importlib.util
import subprocess

PLUGIN_DIR = "./plugins"

PLUGIN_TEMPLATE = '''from dynamic_kvm_prober import generic_probe

def probe(dev_path):
    print(f"[PLUGIN:kvm] Probing {dev_path} (auto-generated, dynamic).")
    generic_probe(dev_path)
'''

def get_kvm_related_modules():
    modules = []
    try:
        out = subprocess.check_output(['lsmod']).decode()
        for line in out.splitlines()[1:]:
            mod = line.split()[0]
            if any(x in mod for x in ['kvm', 'vhost', 'vfio']):
                modules.append(mod)
    except Exception as e:
        print(f"[-] Could not run lsmod: {e}")
    return modules

def enumerate_char_devices():
    devs = []
    for dev in os.listdir('/dev'):
        if dev.startswith(('kvm', 'vhost', 'vfio', 'net', 'tun')):
            devs.append(f"/dev/{dev}")
    return devs

def ensure_plugin(name):
    plugin_path = f"{PLUGIN_DIR}/{name}.py"
    if not os.path.exists(plugin_path):
        with open(plugin_path, "w") as f:
            f.write(PLUGIN_TEMPLATE.replace("{plugin_name}", name))
        print(f"[+] Auto-generated dynamic plugin: {plugin_path}")

def load_plugin(name):
    plugin_path = f"{PLUGIN_DIR}/{name}.py"
    if not os.path.exists(plugin_path):
        ensure_plugin(name)
    try:
        spec = importlib.util.spec_from_file_location(name, plugin_path)
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            print(f"[+] Loaded plugin: {name}")
            return module
    except Exception as e:
        print(f"[-] Could not load plugin {name}: {e}")
    return None

def generic_probe(dev_path):
    print(f"[GENERIC] Probing {dev_path} with generic IOCTL fuzzing.")
    try:
        with open(dev_path, 'rb+', buffering=0) as f:
            for code in range(0x40000000, 0x40000000 + 0x1000, 4):
                try:
                    fcntl.ioctl(f, code, b'\x00'*32)
                except Exception:
                    pass
    except Exception as e:
        print(f"[-] Failed to open {dev_path}: {e}")

def main():
    os.makedirs(PLUGIN_DIR, exist_ok=True)
    modules = get_kvm_related_modules()
    char_devices = enumerate_char_devices()

    for dev_path in char_devices:
        dev_name = os.path.basename(dev_path)
        plugin = None
        # Try to load plugin by device name
        plugin = load_plugin(dev_name)
        # If not found, try by module name
        if not plugin:
            for mod in modules:
                if mod in dev_name:
                    plugin = load_plugin(mod)
                    if plugin:
                        break
        # Use plugin if found, else generic probe
        if plugin and hasattr(plugin, 'probe'):
            print(f"[+] Using plugin for {dev_name}")
            plugin.probe(dev_path)
        else:
            generic_probe(dev_path)

if __name__ == "__main__":
    main()
