import logging
import sys
import time

from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.dictionary import Dictionary
from lib.cuckoo.common.exceptions import CuckooCriticalError, CuckooMachineError, CuckooOperationalError

try:
    from proxmoxer import ProxmoxAPI, ResourceException, AuthenticationError
    from proxmoxer.tools import Tasks
except ImportError:
    sys.exit("You need to install proxmoxer. Navigate to /opt/CAPEv2, then run 'poetry add proxmoxer'")

# silence overly verbose INFO level logging default of proxmoxer module
# logging.getLogger("proxmoxer").setLevel(logging.WARNING)

log = logging.getLogger(__name__)
cfg = Config()


class AutomatedProxmox(Machinery):
    """Manage Proxmox sandboxes, automatically."""

    module_name = "autoproxmox"

    def __init__(self):
        self.timeout = int(cfg.timeouts.vm_state)
        self.pm = None
        self.ssh = None
        super().__init__()

    def set_options(self, options: dict) -> None:
        """Set machine manager options.
        @param options: machine manager options dict.
        """
        self.options = options

    def _refresh_web_api(self):
        """Refresh web api, since password auth expires after 2 hours"""
        try:
            if self.main_backend == 'http':
                auth_info = self.web_auth
                if auth_info.auth_type == "password":
                    if self.pm is None or time.monotonic() - auth_info.birth_time >= 5400:
                        self.pm = ProxmoxAPI(
                            auth_info.hostname,
                            user=auth_info.username,
                            password=auth_info.password,
                            timeout=self.timeout,
                            verify_ssl=False,
                        )
                        auth_info.birth_time = time.monotonic()
                        self.pm.get()
                elif auth_info.auth_type == "token":
                    if self.pm is None:
                        self.pm = ProxmoxAPI(
                            auth_info.hostname,
                            user=auth_info.username,
                            token_name=auth_info.token_name,
                            token_value=auth_info.token_value,
                            timeout=self.timeout,
                            verify_ssl=False,
                        )
                        self.pm.get()
            elif self.main_backend == 'ssh':
                if self.pm is None:
                    auth_info = self.ssh_auth
                    self.pm = ProxmoxAPI(
                        auth_info.hostname,
                        user=auth_info.username,
                        private_key_file=auth_info.private_key_file,
                        password=auth_info.password,
                        timeout=self.timeout,
                        backend='ssh_paramiko',
                    )
                    self.pm.get()

        except TimeoutError as e:
            raise CuckooMachineError(f"Cannot connect to Proxmox, API timed out: {e}")
        except AuthenticationError as e:
            raise CuckooMachineError(f"Cannot connect to Proxmox, authentication failed: {e}")
        except ResourceException as e:
            raise CuckooMachineError(f"Cannot connect to Proxmox: {e}")


    def _web_auth_settings(self):
        opt = self.options.get(self.module_name)
        auth_info = Dictionary()
        auth_info.hostname = opt.hostname
        if auth_info.hostname is None:
            raise CuckooMachineError("Proxmox hostname is required!")
        auth_info.username = opt.username
        if auth_info.username is None:
            raise CuckooMachineError("Proxmox username is required!")

        if opt.token_name is not None and opt.token_value is not None:
            auth_info.auth_type = "token"
            auth_info.token_name = opt.token_name
            auth_info.token_value = opt.token_value
            log.info("Using token authentication.")
        elif opt.password is not None:
            auth_info.auth_type = "password"
            auth_info.password = opt.password
            log.info(
                "Using password authentication - consider switching to API tokens for better persistence and permission management.")
        else:
            raise CuckooMachineError(
                "No authentication specified! Either provide auth, or specify main_backend=ssh if you want to use SSH with a private key file instead!")
        self.web_auth = auth_info

    def _ssh_auth_settings(self):
        opt = self.options.get(self.module_name)
        auth_info = Dictionary()
        auth_info.hostname = opt.hostname
        if auth_info.hostname is None:
            raise CuckooMachineError("Proxmox hostname is required!")

        if opt.ssh_username is not None:
            auth_info.username = opt.ssh_username
        elif opt.username is not None:
            auth_info.username = opt.username
        else:
            raise CuckooMachineError("Proxmox ssh_username is required!")

        if opt.ssh_password is not None:
            auth_info.password = opt.ssh_password
        elif opt.password is not None:
            auth_info.password = opt.password

        if opt.private_key_file is not None:
            auth_info.private_key_file = opt.private_key_file

        if auth_info.password is not None and auth_info.private_key_file is None:
            log.info(
                "Password has been provided for SSH, but will be ignored if a private key file is found. Consider switching to private key files for better persistence and permission management.")

        self.ssh_auth = auth_info

    def _auth_settings(self):
        opt = self.options.get(self.module_name)
        self.main_backend = opt.main_backend
        self.ssh_required = opt.sniff or opt.dump
        if self.main_backend == 'http':
            self._web_auth_settings()
            self._refresh_web_api()

        if self.main_backend == 'ssh' or self.ssh_required:
            self._ssh_auth_settings()


    def _get(self, endpoint, *args, **kwargs):
        self._refresh_web_api()
        try:
            return endpoint.get(*args, **kwargs)
        except ResourceException as e:
            raise CuckooMachineError(f"Couldn't retrieve information from {endpoint}: {e}")

    def _post(self, endpoint, *args, **kwargs):
        self._refresh_web_api()
        try:
            return endpoint.post(*args, **kwargs)
        except ResourceException as e:
            raise CuckooMachineError(f"Couldn't give information to {endpoint}: {e}")

    def _exec(self, addresses, command):
        for address in addresses:
            try:
                auth_info = self.ssh_auth
                self.pm = ProxmoxAPI(
                    address,
                    user=auth_info.username,
                    private_key_file=auth_info.private_key_file,
                    password=auth_info.password,
                    timeout=self.timeout,
                    backend='ssh_paramiko',
                )
                self.ssh._backend.get_session()._exec(command)
                break
            except ResourceException as e:
                log.warning(f"Couldn't execute command: {e}")

    def _override_attributes(self, machine, section):
        # Allow node override of node options based on the node id
        for key, value in getattr(self.options, section, {}).items():
            if value and isinstance(value, str):
                machine[key] = value.strip()
            else:
                machine[key] = value

    def _vm_settings(self):
        opt = self.options.get(self.module_name)
        vms = self._get(self.pm.cluster.resources, type="vm")
        if len(vms) == 0:
            raise CuckooMachineError("No VMs found, perhaps this user does not have the required permissions?")
        for vm in vms:
            machine = Dictionary()
            machine.group = vm['name']
            machine.label = str(vm['vmid'])
            machine.node = vm['node']
            config = self._get(self.pm.node(vm['node'])(vm['id']).config)

            machine.interface = opt.get("interface")
            machine.platform = opt.get('platform')
            machine.arch = opt.get('arch')
            machine.autosnap = opt.get("autosnap")
            machine.sniff = opt.get("sniff")
            machine.dump = opt.get("dump")

            self._override_attributes(machine, machine.node)
            self._override_attributes(machine, machine.group)
            self._override_attributes(machine, machine.label)
            if machine.tags is None:
                machine.tags = ''
            # This makes sure there will always be tags so that
            # the submission view doesn't have to look into
            # the minimal config file
            tags = machine.tags.split(',')
            if 'tags' in config:
                tags += config['tags'].split(';')
            tags += [machine.arch, config["ostype"]]
            machine.tags = ','.join(tags)

            if machine.arch is None:
                if "x64" in machine.tags:
                    machine.arch = 'x64'
                elif "x86" in machine.tags:
                    machine.arch = 'x86'
                else:
                    log.warning("Unknown architecture for machine %s, skipping...", machine.label)
                    continue

            if machine.platform is None:
                if config is None:
                    log.warning("Unknown platform for machine %s, skipping...", machine.label)
                    continue
                if config["ostype"][:1] == "w":
                    machine.platform = "windows"
                elif config["ostype"][:1] == "l":
                    machine.platform = "linux"
                elif config["ostype"] == "other":
                    machine.platform = "darwin"
                else:
                    log.warning(f"Unknown platform for machine {machine.label}, skipping...")
                    continue

            if machine.resultserver_ip is None or machine.resultserver_ip == "0.0.0.0":
                machine.resultserver_ip = None
                if cfg.resultserver.ip != "0.0.0.0":
                    machine.resultserver_ip = cfg.resultserver.ip
            if machine.resultserver_port is None:
                # The ResultServer port might have been dynamically changed,
                # get it from the ResultServer singleton. Also avoid import
                # recursion issues by importing ResultServer here.
                from lib.cuckoo.core.resultserver import ResultServer
                machine.resultserver_port = ResultServer().port

            if machine.reserved is None:
                machine.reserved = "reserved" in machine.tags

            self.vms[machine.label] = machine

    def _auto_network(self):
        interfaces = self._get(self.pm.cluster.sdn.ipams.pve.status)
        if len(interfaces) == 0:
            log.info("No networking info found, perhaps this user does not have the required permissions?")
        mapping = {}
        for interface in interfaces:
            if "vmid" not in interface:
                continue
            mapping[interface["vmid"]] = interface

        cape_ip = None
        candidates = [i for i in mapping if i not in self.vms]
        if len(candidates) == 0:
            log.warning("Can't seem to find CAPE's VM in the network")
        if len(candidates) > 1:
            log.warning(f"Multiple candidates found, choosing the first IP as CAPE's VM: {cape_ip}", )
            log.warning(f"Other candidates were: {candidates}")
        cape_ip = mapping[candidates[0]]['ip']
        self.nodes = {vm.node: [] for vm in self.vms}
        for node in self.nodes:
            node_interfaces = self._get(self.pm.nodes(node).network)
            self.nodes[node] = [node_interface['address'] for node_interface in node_interfaces if
                                'address' in node_interface]
            if self.nodes[node]:
                log.info(f"No address found for {node}, perhaps this user does not have the required permissions? (add /sdn/zone/localnetwork)")

        for label in self.vms:
            machine = self.vms[label]
            if machine.ip is None:
                machine.ip = mapping[machine.label]['ip']
            if machine.resultserver_ip is None:
                machine.resultserver_ip = cape_ip
            if machine.interface is None:
                machine.interface = mapping[machine.label]['vnet']

    def _initialize(self):
        """
        Read configuration file, but tries to fill in the blanks when something isn't configured.
        @raise CuckooMachineError: if Proxmox cluster cannot be reached, if no VMs can be found, or if auto-networking is enabled but networking info cannot be found
        """
        # Handle the creation of self.pm and self.ssh for interacting with the API and sending shell commands
        self._auth_settings()

        self.vms = {}
        self._vm_settings()

        if self.options.get(self.module_name).get("auto_network"):
            self._auto_network()
        for machine in self.vms:
            if machine.ip is None:
                log.warning(f"Can't get an IP for {machine}, skipping...")
                continue
            if machine.resultserver_ip is None:
                log.warning(f"Can't get a result server IP for {machine}, skipping...")
                continue
            if machine.sniff and machine.interface is None:
                log.warning(f"Can't get an interface for {machine}, cannot perform dump...")
                machine.sniff = False
            self.db.add_machine(
                name=machine.group,
                label=machine.label,
                arch=machine.arch,
                ip=machine.ip,
                platform=machine.platform,
                tags=machine.tags,
                interface=machine.interface,
                snapshot=machine.snapshot,
                resultserver_ip=machine.resultserver_ip,
                resultserver_port=machine.resultserver_port,
                reserved=machine.reserved,
            )

    def retry_task(self, func, *args, **kwargs):
        status = ''
        for i in range(5):
            return_values = func(*args, **kwargs)
            taskid = return_values[0]
            task = Tasks.blocking_status(self.pm, taskid, timeout=self.timeout, polling_interval=1)
            if not task:
                raise CuckooMachineError(f"Timeout while trying task {func.__name__}({args},{kwargs}): {taskid}")
            status = task["exitstatus"]
            if status == "OK":
                return return_values[1:]
            elif status == "timeout waiting on systemd":
                time.sleep(5)
            else:
                raise CuckooMachineError(f"Task {func.__name__}({args},{kwargs}) attempt #{i} failed: {status}")
        raise CuckooMachineError(
            f"Task {func.__name__}({args},{kwargs}) failed: {status} - proxmox might be overwhelmed")

    def find_snapshot(self, vm):
        snapshots = self._get(vm.api.snapshot)
        snaptime = 0
        chosen_snapshot = None
        for snapshot in snapshots:
            if snapshot["name"] == "current":
                continue
            if vm.snapshot is None or snapshot["name"] == vm.snapshot:
                if snapshot["snaptime"] > snaptime:
                    snaptime = snapshot["snaptime"]
                    chosen_snapshot = snapshot["name"]
        if chosen_snapshot is not None:
            return vm.api.snapshot(chosen_snapshot)
        return None

    def make_snapshot(self, vm):
        name = 'autosnap'
        if vm.snapshot is not None:
            name = vm.snapshot
        try:
            taskid = vm.api.snapshot.post(snapname=name)
        except ResourceException as e:
            raise CuckooMachineError(f"Error creating snapshot {name} for vm {vm.label}: {e}")
        return taskid, vm.api.snapshot(name)

    def rollback(self, vm, snapshot):
        try:
            taskid = snapshot.rollback.post()
        except ResourceException as e:
            raise CuckooMachineError(f"Error rolling back snapshot for vm {vm.label}: {e}")
        return taskid,

    def start_machine(self, vm):
        return vm.api.status.start.post(),

    def stop_machine(self, vm):
        return vm.api.status.stop.post(),

    def reset_machine(self, vm):
        snapshot = self.find_snapshot(vm)
        if snapshot is None:
            if vm.autosnap:
                log.debug(f"Snapshot {vm.snapshot} not found, creating a snapshot of the current machine state")
                snapshot, = self.retry_task(vm, self.make_snapshot, vm)
            else:
                raise CuckooMachineError(f"Cannot find snapshot {vm.snapshot} for machine {vm.label}")
        self.retry_task(self.rollback, vm, snapshot)

    def start(self, label):
        vm = self.vms[label]
        self.reset_machine(vm)
        status = self._get(vm.api.status.current)
        if status["status"] == "running":
            log.debug(f"{label} is already running after rollback, no need to start it")
            return

        self.retry_task(self.start_machine, vm)

    def stop(self, label):
        vm = self.vms[label]
        self.retry_task(self.stop_machine, vm)
