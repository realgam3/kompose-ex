import os
import re
import sys
import yaml
import json
import atexit
import logging
import argparse
import tempfile
import subprocess
from os import path
from glob import glob
from kubernetes import config, client
from jsonpath_ng import ext as jsonpath_ext
from distutils.version import StrictVersion

from . import __version__
from . import models, api, utils


class KomposeEx(object):
    def __init__(self, args=None, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        cmd = "kompose-ex" if args else sys.argv[0]
        sys_args = args or sys.argv[1:]
        self.cmd = " ".join([cmd, *sys_args])
        self.args, self.args_unknown = self.parse_args(args=sys_args)
        self.version = __version__.__version__
        self.annotations = {
            "kompose-ex.cmd": self.cmd,
            "kompose-ex.version": self.version
        }
        self.compose = {}

    def recreate_compose(self):
        for service_name, service in self.compose.get("services", {}).items():
            labels = service.get("labels", {})
            labels.update(self.annotations)
            service["labels"] = labels
            service_ex_type = labels.get("kompose-ex.service.type", "").lower()

            ports = service.get("ports", []) or service.get("expose", [])
            if service_ex_type == "ingress-nginx" and not ports:
                raise Exception(
                    "kompose-ex.controller.type 'ingress-nginx' was specified without expose or ports"
                )

            udp_ports = False
            for port in ports:
                if port.split("/", 1)[-1].lower() == "udp":
                    udp_ports = True
                    break

            if service_ex_type == "ingress-nginx" and udp_ports:
                raise Exception(
                    "kompose-ex.controller.type 'ingress' was does not support udp ports"
                )

        # Recreate compose
        compose_path = tempfile.mktemp(prefix="docker-compose.", suffix=".yml", dir=".")
        with open(compose_path, "w", encoding="UTF-8") as fw:
            yaml.safe_dump(self.compose, stream=fw, indent=self.args.indent, width=0x7fffffff)

        # Delete compose file on exit
        atexit.register(self.destroy, compose_path)
        return compose_path

    def destroy(self, compose_path):
        try:
            os.remove(compose_path)
        except Exception as ex:
            self.logger.error(ex.args[-1])

    @staticmethod
    def parse_args(args=None):
        sys_args = args or sys.argv[1:]
        parser = argparse.ArgumentParser(prog=__version__.__title__)
        parser.add_argument("command", choices=[
            "convert", "deploy", "update-records", "patch-ingress",
            "rollout-restart", "version", "install"
        ])
        parser.add_argument("-f", "--file", dest="file", default="docker-compose.yml")
        parser.add_argument("-o", "--out", dest="out", default="")
        parser.add_argument("-c", "--chart", action="store_true", dest="chart")
        parser.add_argument("-j", "--json", action="store_true", dest="json")
        parser.add_argument("-n", "--namespace", dest="namespace", default="default")
        parser.add_argument("-v", "--verbose", action="count", dest="verbose", default=0)
        parser.add_argument("--indent", dest="indent", type=int, default=2)
        group = parser.add_mutually_exclusive_group()
        group.add_argument("-s", "--skip", action="store_true", dest="skip")
        group.add_argument("-d", "--clean", action="count", dest="clean", default=0)
        parser.add_argument("--deny-ingress", action="store_true", dest="deny_ingress")
        group = parser.add_mutually_exclusive_group()
        group.add_argument("--deny-egress", action="store_true", dest="deny_egress")
        group.add_argument("--deny-egress-cidr", action="extend", nargs="+", metavar="CIDR", dest="deny_egress_cidr")
        parser.add_argument("--create-namespace", action="store_true", dest="create_namespace")
        parser.add_argument("--delete-namespace", action="store_true", dest="delete_namespace")
        parser.add_argument("--eks-kubeconfig", dest="eks_kubeconfig")
        parser.add_argument("--rollout-restart", action="store_true", dest="rollout_restart")
        group = parser.add_mutually_exclusive_group()
        group.add_argument("--route53-hostedzone", dest="route53_hostedzone")
        group.add_argument("--route53-hostedzone-id", dest="route53_hostedzone_id")
        parser.add_argument("--version", dest="version", default="latest")
        parser.add_argument("--patch-ingress", action="store_true", dest="patch_ingress")
        parser.add_argument("--tcp-services-configmap", dest="tcp_services_configmap",
                            default="ingress-nginx/tcp-services")
        parser.add_argument("--ingress-service", dest="ingress_service",
                            default="ingress-nginx/ingress-nginx-controller")
        args_known, args_unknown = parser.parse_known_args(args=sys_args)

        namespace = args_known.namespace
        command = args_known.command
        if command not in ["convert", "deploy", "update-records", "rollout-restart"]:
            return args_known, args_unknown

        if not path.exists(args_known.file):
            parser.error(f"file {args_known.file} is not exist")

        if command == "update-records" and \
                not any([args_known.route53_hostedzone, args_known.route53_hostedzone_id]):
            parser.error(f"update-records argument --route53-hostedzone/--route53-hostedzone-id is not set")

        if command == "deploy" and not re.match(r"^[a-z\d]([-a-z\d]*[a-z\d])?$", namespace):
            parser.error(
                f"The Namespace {json.dumps(namespace)} is invalid: "
                f"metadata.name: Invalid value: {json.dumps(namespace)}: "
                "a lowercase RFC 1123 label must consist of lower case alphanumeric characters or '-', "
                "and must start and end with an alphanumeric character (e.g. 'my-name',  or '123-abc', "
                "regex used for validation is '[a-z0-9]([-a-z0-9]*[a-z0-9])?')"
            )

        return args_known, args_unknown

    @staticmethod
    def parse_records(labels):
        records = []
        kompose_expose = labels.get("kompose.service.expose")
        if kompose_expose:
            records.extend(map(str.strip, kompose_expose.split(",")))

        kompose_ex_expose = labels.get("kompose-ex.service.expose")
        if kompose_ex_expose:
            records.extend(map(str.strip, kompose_ex_expose.split(",")))

        return records

    def kompose_version(self, kompose_path=None):
        kompose_path = kompose_path or self.kompose_path
        return_code, output = utils.process_output(
            args=[
                kompose_path, "version",
            ],
            stderr=subprocess.STDOUT,
        )

        if return_code != 0:
            raise Exception(f"kompose version failed: exit code {return_code}")

        res_re = re.search(r"(?P<version>\d+\.\d+\.\d+)", output.decode("utf-8"))
        if not res_re:
            raise Exception(f"kompose version failed: {output}")

        return res_re.group("version")

    def kompose_convert(self, kompose_path=None, compose_path=None):
        kompose_path = kompose_path or self.kompose_path
        args = [
            "-n", self.args.namespace,
        ]
        if self.args.chart:
            args.append("-c")
            if not self.args.out:
                self.args.out = path.splitext(self.args.file)[0]
        if self.args.json:
            args.append("-j")
        if self.args.verbose > 1:
            args.append("-v")
        if self.args.out:
            args.extend(["-o", self.args.out])
        if self.args.indent != 2:
            args.extend(["--indent", str(self.args.indent)])

        return_code, _output = utils.process_output(
            args=[
                kompose_path, "convert",
                "-f", compose_path or self.args.file,
                *args,
                *self.args_unknown
            ],
            stderr=subprocess.STDOUT,
            logger=self.logger
        )

        return return_code

    @staticmethod
    def pop_kompose_kubernetes_object(kind, service_name, yaml_object=None, yaml_path=None, file_ext="yaml"):
        if not any([yaml_object, yaml_path]):
            raise Exception("parameter yaml_object/yaml_path is not set")

        if yaml_object:
            jsonpath_expr = jsonpath_ext.parser.parse(
                f"$.items[?(@.kind == '{kind}' & @.metadata.name== {repr(service_name)})]"
            )
            res = jsonpath_expr.find(yaml_object)[0].value
            yaml_object["items"].remove(res)
        else:
            f_path = path.join(yaml_path, f"{service_name}-{kind.lower()}.{file_ext}")
            with open(f_path) as fr:
                res = yaml.safe_load(fr)
            os.remove(f_path)
        return res

    def kompose_ex_convert(self, services):
        file_ext = "json" if self.args.json else "yaml"
        is_file = path.isfile(self.args.out)
        out_path = self.args.out
        if self.args.chart:
            out_path = path.join(out_path, "templates")
        output = {}
        kompose_items = []
        if is_file:
            with open(self.args.out, "r", encoding="UTF-8") as fr:
                output = yaml.safe_load(fr)
                kompose_items = output["items"]

        items = {}
        network_policy_api_version = "networking.k8s.io/v1"

        # Deny ingress
        if self.args.deny_ingress:
            items["deny-ingress-network-policy"] = models.V1NetworkPolicy(
                api_version=network_policy_api_version,
                metadata=models.V1ObjectMeta(
                    name="deny-ingress",
                    annotations=self.annotations,
                    namespace=self.args.namespace,
                ),
                spec=models.V1NetworkPolicySpec(
                    ingress=[{
                        "from": [{
                            "podSelector": {}
                        }]
                    }],
                    pod_selector={},
                    policy_types=["Ingress"]
                )
            ).to_dict()

        # Deny egress
        if self.args.deny_egress:
            items["deny-egress-network-policy"] = models.V1NetworkPolicy(
                api_version=network_policy_api_version,
                metadata=models.V1ObjectMeta(
                    name="deny-egress",
                    annotations=self.annotations,
                    namespace=self.args.namespace,
                ),
                spec=models.V1NetworkPolicySpec(
                    egress=[{
                        "to": [{
                            "podSelector": {}
                        }]
                    }],
                    pod_selector={},
                    policy_types=["Egress"]
                )
            ).to_dict()

        # Deny egress to cidr list
        if self.args.deny_egress_cidr:
            items["deny-egress-cidr-network-policy"] = models.V1NetworkPolicy(
                api_version=network_policy_api_version,
                metadata=models.V1ObjectMeta(
                    name="deny-egress-cidr",
                    annotations=self.annotations,
                    namespace=self.args.namespace,
                ),
                spec=models.V1NetworkPolicySpec(
                    egress=[{
                        "to": [{
                            "ipBlock": {
                                "cidr": "0.0.0.0/0",
                                "except": self.args.deny_egress_cidr
                            }
                        }]
                    }],
                    pod_selector={},
                    policy_types=["Egress"]
                )
            ).to_dict()

        cron_restart_services = {}
        for service_name, service in services.items():
            allow_egress = service.get("allow_egress", False)
            allow_ingress = (service["public"] and self.args.deny_ingress) or service.get("allow_ingress", False)

            if service["rollout-restart-cronjob-schedule"]:
                cron_restart_services[service_name] = service

            # Fix ReadOnly
            if service["service"].get("read_only", False):
                manifest = self.pop_kompose_kubernetes_object(
                    kind=service["controller"],
                    service_name=service_name,
                    yaml_object=output if output else None,
                    yaml_path=None if output else out_path
                )
                containers = manifest["spec"]["template"]["spec"]["containers"]
                for container in containers:
                    if container.get("name") != service_name:
                        continue

                    container["securityContext"] = container.get("securityContext", {})
                    container["securityContext"].update({
                        "readOnlyRootFilesystem": True
                    })
                manifest["metadata"]["annotations"]["kompose-ex.updated"] = "true"
                items[f"{service_name}-{service['controller']}"] = manifest

            # Allow ingress to service
            if allow_ingress:
                items[f"allow-ingress-{service_name}-network-policy"] = models.V1NetworkPolicy(
                    api_version=network_policy_api_version,
                    metadata=models.V1ObjectMeta(
                        name=f"allow-ingress-{service_name}",
                        annotations=service["labels"],
                        namespace=self.args.namespace,
                    ),
                    spec=models.V1NetworkPolicySpec(
                        ingress=[{}],
                        pod_selector={
                            "matchLabels": {
                                "io.kompose.service": service_name
                            }
                        },
                        policy_types=["Ingress"]
                    )
                ).to_dict()

            # Allow Egress from service
            if allow_egress:
                items[f"allow-egress-{service_name}-network-policy"] = models.V1NetworkPolicy(
                    api_version=network_policy_api_version,
                    metadata=models.V1ObjectMeta(
                        name=f"allow-egress-{service_name}",
                        annotations=service["labels"],
                        namespace=self.args.namespace,
                    ),
                    spec=models.V1NetworkPolicySpec(
                        egress=[{}],
                        pod_selector={
                            "matchLabels": {
                                "io.kompose.service": service_name
                            }
                        },
                        policy_types=["Egress"]
                    )
                ).to_dict()

        if cron_restart_services:
            # Create service account
            items["rollout-restart-service-account"] = models.V1ServiceAccount(
                metadata=models.V1ObjectMeta(
                    name="rollout-restart",
                    annotations=self.annotations,
                    namespace=self.args.namespace,
                ),
            ).to_dict()

            # Create role
            items["rollout-restart-role"] = models.V1Role(
                api_version="rbac.authorization.k8s.io/v1",
                metadata=models.V1ObjectMeta(
                    name="rollout-restart",
                    annotations=self.annotations,
                    namespace=self.args.namespace,
                ),
                rules=[{
                    "apiGroups": [
                        "apps",
                        "extensions"
                    ],
                    "resources": [
                        "deployments",
                        "daemonsets",
                        "statefulsets"
                    ],
                    "resourceNames": [
                        *cron_restart_services
                    ],
                    "verbs": [
                        "get",
                        "patch"
                    ]
                }]
            ).to_dict()

            # Create role binding for service account
            items["rollout-restart-role-binding"] = models.V1RoleBinding(
                api_version="rbac.authorization.k8s.io/v1",
                metadata=models.V1ObjectMeta(
                    name="rollout-restart",
                    annotations=self.annotations,
                    namespace=self.args.namespace,
                ),
                role_ref={
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "Role",
                    "name": "rollout-restart"
                },
                subjects=[{
                    "kind": "ServiceAccount",
                    "name": "rollout-restart",
                }]
            ).to_dict()

            # Create restart cronjobs
            for service_name, service in cron_restart_services.items():
                items[f"{service_name}-rollout-restart-cronjob"] = models.V1CronJob(
                    api_version="batch/v1",
                    metadata=models.V1ObjectMeta(
                        name=f"rollout-restart-{service_name}",
                        annotations=service["labels"],
                        namespace=self.args.namespace,
                    ),
                    spec=models.V1CronJobSpec(
                        concurrency_policy="Forbid",
                        schedule=service["rollout-restart-cronjob-schedule"],
                        job_template=models.V1JobTemplateSpec(
                            spec=models.V1JobSpec(
                                template=models.V1PodTemplateSpec(
                                    spec={
                                        "serviceAccountName": "rollout-restart",
                                        "restartPolicy": "Never",
                                        "containers": [{
                                            "name": "kubectl",
                                            "image": "bitnami/kubectl",
                                            "command": [
                                                "kubectl",
                                                "rollout",
                                                "restart",
                                                f"{service['controller']}/{service_name}"
                                            ]
                                        }]
                                    }
                                )
                            )
                        )
                    )
                ).to_dict()

        if not items:
            return

        # If output is file
        if is_file:
            with open(out_path, "w", encoding="UTF-8") as fw:
                kompose_items.extend(items.values())
                if self.args.json:
                    json.dump(output, fw, indent=self.args.indent)
                else:
                    yaml.safe_dump(output, stream=fw, indent=self.args.indent, width=0x7fffffff)
            self.logger.info(f"Kubernetes file {json.dumps(out_path)} updated")
            return

        # If output is directory
        for item_name, item in items.items():
            updated = item["metadata"]["annotations"].get("kompose-ex.updated")
            f_path = path.normpath(path.join(out_path, f"{item_name}.{file_ext}"))
            with open(f_path, "w") as fw:
                if self.args.json:
                    json.dump(item, fw, indent=self.args.indent)
                else:
                    yaml.safe_dump(item, stream=fw, indent=self.args.indent, width=0x7fffffff)

            self.logger.info(f"Kubernetes file {json.dumps(f_path)} {'updated' if updated else 'created'}")

    def get_services(self):
        services = {}
        _services = self.compose.get("services", [])
        for name, service in _services.items():
            public = True
            labels = service.get("labels", {})
            service_type = (
                    labels.get("kompose-ex.service.type", "").lower() or
                    labels.get("kompose.service.type", "").lower()
            )
            if "kompose.service.expose" in labels:
                service_type = "ingress"

            if service_type not in ["loadbalancer", "nodeport", "ingress", "ingress-nginx"]:
                public = False

            services[name] = {
                "type": service_type,
                "public": public,
                "labels": labels,
                "service": service,
                "build": "build" in service,
                "image-pull-policy": labels.get("kompose.image-pull-policy", "Never").lower(),
                "ingress": {
                    "tls": (
                            labels.get("kompose-ex.service.expose.tls", "false").lower() == "true" and
                            labels.get("kompose.service.expose.tls-secret", "").lower() == "null"
                    ),
                    "class": (
                            labels.get("kompose.service.expose.ingress-class-name", "") or
                            labels.get("kompose-ex.service.expose.ingress-class-name", "")
                    ).lower()
                },
                "records": self.parse_records(labels=labels),
                "controller": (
                        labels.get("kompose-ex.controller.type", "").lower() or
                        labels.get("kompose.controller.type", "deployment").lower()
                ),
                "allow_egress": labels.get("kompose-ex.egress.allow", "false").lower() == "true",
                "allow_ingress": labels.get("kompose-ex.ingress.allow", "false").lower() == "true",
                "cronjob": labels.get("kompose-ex.controller.type", "").lower() == "cronjob",
                "cronjob-schedule": labels.get("kompose-ex.cronjob.schedule"),
                "cronjob-concurrency-policy": labels.get("kompose-ex.cronjob.concurrency_policy", "Allow"),
                "rollout-restart-cronjob-schedule": labels.get("kompose-ex.rollout-restart.cronjob.schedule"),
            }

        return services

    @property
    def directory(self):
        homedir = path.expanduser('~')
        return path.join(homedir, ".kompose-ex")

    @property
    def kompose_path(self):
        files = glob(path.join(self.directory, "bin", "kompose*"))
        if files:
            return files[0]
        return "kompose"

    def install(self, version="latest"):
        install_directory = path.join(self.directory, "bin")
        os.makedirs(install_directory, exist_ok=True)
        kompose_version = utils.install_kompose(install_directory, version=version)
        self.logger.info(f"kompose {kompose_version} installed")

    def convert(self, services, compose_path):
        # Skip conversion (Only deploy)
        skip = self.args.skip and self.args.command == "deploy"
        if skip:
            return 0

        # Clean files
        if self.args.clean:
            utils.clean(self.args.out)

        # Check kompose version
        try:
            kompose_version = self.kompose_version()
        except Exception as e:
            self.logger.error(e)
            return 1

        tested_kompose_version = __version__.__kompose_version__
        if StrictVersion(kompose_version) < StrictVersion(tested_kompose_version):
            self.logger.fatal(
                f"kompose version is lower than the tested kompose version {tested_kompose_version}, "
                f"please upgrade with `kompose-ex install --version {tested_kompose_version}` or `kompose-ex install`"
            )
            return 1

        elif StrictVersion(kompose_version) > StrictVersion(tested_kompose_version):
            self.logger.warning(
                f"kompose version is higher than the tested kompose version {tested_kompose_version}, "
                f"if you experience abnormal behavior, "
                f"you can downgrade with `kompose-ex install --version {tested_kompose_version}`"
            )

        # Convert docker compose yaml using kompose
        return_code = self.kompose_convert(compose_path=compose_path)
        if return_code:
            raise Exception("kompose conversion failed")

        # Convert with kompose-ex
        self.kompose_ex_convert(services)

        return 0

    def deploy(self):
        # Delete namespace
        if self.args.delete_namespace:
            api.delete_namespace(self.args.namespace)

        # Create namespace
        if self.args.create_namespace or self.args.delete_namespace:
            api.create_namespace(self.args.namespace)

        # Apply kubernetes files
        out_path = self.args.out
        if self.args.chart:
            out_path = path.join(out_path, "templates")
        api.apply(out_path, namespace=self.args.namespace, verbose=self.args.verbose > 1)

        # Clean files
        if self.args.clean > 1:
            utils.clean(self.args.out)

    def update_records(self, services):
        # Update Rout53 DNS Records
        provider = None
        provider_kwargs = {}
        if any([self.args.route53_hostedzone, self.args.route53_hostedzone_id]):
            from .dns import route53

            route53_hostedzone_id = self.args.route53_hostedzone_id
            if not route53_hostedzone_id:
                route53_hostedzone_id = route53.get_hosted_zones_by_name(self.args.route53_hostedzone)
            provider = route53
            provider_kwargs = dict(zone_id=route53_hostedzone_id)

        if not provider:
            return

        for service_name, service in services.items():
            records = service.get("records", [])
            if not records or not service.get("public"):
                return

            name = service_name
            namespace = self.args.namespace
            if service["type"] == "ingress-nginx":
                namespace, _, name = self.args.ingress_service.partition("/")
                if not name:
                    namespace, name = "default", name

            balancer_address = api.load_balancer_address(
                name=name,
                namespace=namespace,
                ingress=service.get("type", "") == "ingress"
            )
            for record in records:
                provider.update_cname_record(name=record, record=balancer_address, **provider_kwargs)
                self.logger.info(f"Route53 record {record} is set to {balancer_address}")

    def update_kubeconfig(self, name=None):
        name = name or self.args.eks_kubeconfig
        args = [
            "aws", "eks",
            "update-kubeconfig",
            "--name", name
        ]
        if self.args.verbose > 1:
            args.append("--verbose")

        return_code, _output = utils.process_output(
            args=args,
            stderr=subprocess.STDOUT,
            logger=self.logger
        )
        if return_code:
            raise Exception("eks kubeconfig creation failed")

    def rollout_restart(self, services):
        for service_name, service in services.items():
            if service["image-pull-policy"] != "always":
                continue

            res = api.rollout_restart(
                service_name,
                namespace=self.args.namespace,
                controller=service["controller"]
            )
            object_name = api.get_object_name(res)
            self.logger.info(f"{object_name} restarted")

    def patch_ingress(self, services):
        core_api = client.CoreV1Api()

        patched = False
        for service_name, service in services.items():
            if service["type"] != "ingress-nginx":
                continue

            _service = service.get("service")
            ports = _service.get("ports", []) or _service.get("expose", [])
            if not ports:
                continue

            configmap_data = {}
            service_ports = []
            for port in ports:
                port = int(port.split(":")[0])
                configmap_data[port] = f"{self.args.namespace}/{service_name}:{port}"
                service_ports.append({
                    "name": f"{port}",
                    "port": port,
                    "protocol": "TCP",
                    "targetPort": port,
                })

            namespace, _, name = self.args.tcp_services_configmap.partition("/")
            if not namespace:
                namespace, name = "default", namespace

            res = core_api.patch_namespaced_config_map(
                name=name,
                namespace=namespace,
                body={
                    "data": configmap_data
                }
            )
            if not patched:
                self.logger.info(f"{api.get_object_name(res)} patched")

            namespace, _, name = self.args.ingress_service.partition("/")
            if not namespace:
                namespace, name = "default", namespace

            res = core_api.patch_namespaced_service(
                name=name,
                namespace=namespace,
                body={
                    "spec": {
                        "ports": service_ports
                    }
                }
            )
            if not patched:
                self.logger.info(f"{api.get_object_name(res)} patched")

            patched = True
            self.logger.info(f"{service['controller']}.apps/{service_name} exposed")

    def run(self):
        # Print version
        if self.args.command == "version":
            print(self.version)
            return 0

        # Install requirements
        if self.args.command == "install":
            self.install(version=self.args.version)
            return 0

        # Load compose yaml
        with open(self.args.file, "r", encoding="UTF-8") as fr:
            self.compose = yaml.safe_load(fr.read())

        # Recreate compose yaml
        compose_path = self.recreate_compose()
        if not compose_path:
            return 1

        # Get compose services
        services = self.get_services()

        # Convert docker-compose to kubernetes objects
        if self.args.command in ["convert", "deploy"]:
            self.convert(services, compose_path)

        if self.args.command == "convert":
            return 0

        # Load kubernetes config
        if self.args.eks_kubeconfig:
            self.update_kubeconfig()
        config.load_config()

        # Deploy kubernetes objects
        if self.args.command == "deploy":
            self.deploy()

        # Patch ingress controller
        patch_ingress = self.args.command == "deploy" and self.args.patch_ingress
        if patch_ingress or self.args.command == "patch-ingress":
            self.patch_ingress(services)

        #  Restart kubernetes objects
        rollout_restart = self.args.command == "deploy" and self.args.rollout_restart
        if rollout_restart or self.args.command == "rollout-restart":
            self.rollout_restart(services)

        #  Update DNS cname records
        if self.args.command in ["deploy", "update-records"]:
            self.update_records(services)

        return 0

    def start(self):
        try:
            return self.run()
        except Exception as ex:
            self.logger.fatal(ex)
        return 1

    @classmethod
    def main(cls, args=None):
        kompose = cls(args=args)

        # Configure basic logger
        logging.basicConfig(
            level=logging.INFO if not kompose.args.verbose else logging.DEBUG,
            format="%(asctime)s %(levelname)s %(message)s",
            datefmt="%d-%m-%y %H:%M:%S"
        )

        return kompose.start()


def main(args=None):
    return KomposeEx.main(args=args)
