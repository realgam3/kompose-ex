import os
import sys
import yaml
import json
import atexit
import logging
import argparse
import tempfile
import subprocess
from os import path
from jsonpath_ng.ext import parser

from kompose_ex import __version__, models


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

    def process_output(self, *args, **kwargs):
        command = kwargs.get("args", args)[0]
        code = 0
        try:
            output = subprocess.check_output(*args, **kwargs)
            for line in output.decode().splitlines():
                self.logger.info(f"[{command}] {line}")
        except subprocess.CalledProcessError as ex:
            output = ex.output
            for line in ex.output.decode().splitlines():
                self.logger.error(f"[{command}] {line}")
            self.logger.error(f"[{command}] exit {ex.returncode}")
            code = ex.returncode,
        return code, output

    def recreate_compose(self):
        for service_name, service in self.compose.get("services", {}).items():
            labels = service.get("labels", {})
            labels.update(self.annotations)
            service["labels"] = labels
            controller_type = labels.get("kompose.controller.type", "").lower()
            controller_ex_type = labels.get("kompose-ex.controller.type", "").lower()
            if controller_type and controller_ex_type:
                raise Exception("kompose-ex.controller.type was specified with kompose.controller.type")

            if controller_ex_type == "cronjob" and not labels.get("kompose-ex.cronjob.schedule"):
                raise Exception(
                    "kompose-ex.controller.type 'cronjob' was specified without kompose-ex.cronjob.schedule"
                )

            if controller_ex_type == "cronjob":
                restart = service.get("restart", "no")
                if service.get("restart", "no") not in ["no", "on-failure"]:
                    service["restart"] = "on-failure"
                    self.logger.warning(
                        f"Restart policy '{restart}' in service challenge is not supported, convert it to 'on-failure'"
                    )
                if service.pop("expose", []) + service.pop("ports", []):
                    self.logger.warning(
                        f"Service \"{service_name}\" won't be created because kompose-ex.controller.type is 'cronjob'"
                    )

        # Recreate compose
        compose_path = tempfile.mktemp(prefix="docker-compose.", suffix=".yml")
        with open(compose_path, "w", encoding="UTF-8") as fw:
            yaml.safe_dump(self.compose, stream=fw, indent=2)

        # Delete compose file on exit
        atexit.register(self.destroy, compose_path)
        return compose_path

    def destroy(self, compose_path):
        try:
            os.remove(compose_path)
        except Exception as ex:
            self.logger.error(ex.args[-1])

    @staticmethod
    def configure_logger():
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(message)s",
            datefmt="%d-%m-%y %H:%M:%S"
        )

    @staticmethod
    def parse_args(args=None):
        sys_args = args or sys.argv[1:]
        parser = argparse.ArgumentParser()
        parser.add_argument("command", choices=["convert", "version"])
        parser.add_argument("-f", "--file", dest="file", default="docker-compose.yml")
        parser.add_argument("-o", "--out", dest="out", default="k8s")
        parser.add_argument("-c", "--chart", action="store_true", dest="chart")
        parser.add_argument("-j", "--json", action="store_true", dest="json")
        parser.add_argument("--indent", dest="indent", type=int, default=2)
        parser.add_argument("--clean", action="store_true", dest="clean")
        parser.add_argument("--namespace", dest="namespace")
        parser.add_argument("--deny-ingress", action="store_true", dest="deny_ingress")
        group = parser.add_mutually_exclusive_group()
        group.add_argument("--deny-egress", action="store_true", dest="deny_egress")
        group.add_argument("--deny-egress-cidr", action="extend", nargs="+", metavar="CIDR", dest="deny_egress_cidr")
        args_known, args_unknown = parser.parse_known_args(args=sys_args)

        if args_known.command == "version":
            return args_known, args_unknown

        if not path.exists(args_known.file):
            parser.error(f"file {args_known.file} is not exist.")

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

    def kompose_convert(self, compose_path=None):
        args = [
            "kompose", self.args.command,
            "-f", compose_path or self.args.file,
            "-o", self.args.out,
            "--indent", str(self.args.indent),
            *self.args_unknown
        ]
        if self.args.chart:
            args.append("-c")
        if self.args.json:
            args.append("-j")
        return_code, _output = self.process_output(
            args=args,
            stderr=subprocess.STDOUT
        )
        return return_code

    def kompose_ex_convert(self, services):
        file_ext = "json" if self.args.json else "yaml"
        is_file = path.isfile(self.args.out)
        out_path = self.args.out
        if self.args.chart:
            out_path = path.join(out_path, "templates")
        kompose_items = []
        if is_file:
            with open(self.args.out, "r", encoding="UTF-8") as fr:
                output = yaml.safe_load(fr)
                kompose_items = output["items"]

        items = {}
        network_policy_api_version = "networking.k8s.io/v1"

        # Deny Ingress
        if self.args.deny_ingress:
            items["deny-ingress-network-policy"] = models.V1NetworkPolicy(
                api_version=network_policy_api_version,
                metadata=models.V1ObjectMeta(
                    name="deny-ingress",
                    annotations=self.annotations,
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
            allow_ingress = service["public"] or service.get("allow_ingress", False)

            if service["rollout-restart-cronjob-schedule"]:
                cron_restart_services[service_name] = service

            # Fix DaemonSet
            if service["controller"] == "daemonset":
                if is_file:
                    jsonpath_expr = parser.parse(
                        f"$.items[?(@.kind == 'DaemonSet' & @.metadata.name== {repr(service_name)})]"
                    )
                    daemonset = jsonpath_expr.find(output)[0].value
                    output["items"].remove(daemonset)

                else:
                    f_path = path.join(out_path, f"{service_name}-daemonset.{file_ext}")
                    with open(f_path) as fr:
                        daemonset = yaml.safe_load(fr)

                daemonset["spec"]["selector"] = {
                    "matchLabels": {
                        "io.kompose.service": service_name
                    }
                }
                daemonset["updated"] = True
                items[f"{service_name}-daemonset"] = daemonset

            # Allow ingress to service
            if allow_ingress:
                items[f"allow-ingress-{service_name}-network-policy"] = models.V1NetworkPolicy(
                    api_version=network_policy_api_version,
                    metadata=models.V1ObjectMeta(
                        name=f"allow-ingress-{service_name}",
                        annotations=service["labels"],
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

            # Create CronJob
            if service["cronjob"]:
                if is_file:
                    # print(json.dumps(output, indent=2))
                    jsonpath_expr = parser.parse(
                        f"$.items[?(@.kind == 'Pod' & @.metadata.name== {repr(service_name)})]"
                    )
                    pod = jsonpath_expr.find(output)[0].value
                    output["items"].remove(pod)
                else:
                    f_path = path.join(self.args.out, f"{service_name}-pod.{file_ext}")
                    with open(f_path) as fr:
                        pod = yaml.safe_load(fr)
                    os.remove(f_path)
                    self.logger.info(f"Kubernetes file {json.dumps(f_path)} removed'")

                items[f"{service_name}-cronjob"] = models.V1CronJob(
                    api_version="batch/v1",
                    metadata=models.V1ObjectMeta(
                        name=service_name,
                        annotations=pod["metadata"]["annotations"],
                        labels=pod["metadata"]["labels"],
                    ),
                    spec=models.V1CronJobSpec(
                        schedule=service["cronjob-schedule"],
                        concurrency_policy=service["cronjob-concurrency-policy"],
                        job_template=models.V1JobTemplateSpec(
                            spec=models.V1JobSpec(
                                template=models.V1PodTemplateSpec(
                                    spec=pod["spec"]
                                )
                            )
                        )
                    )
                ).to_dict()

        if cron_restart_services:
            # Create service account
            items["rollout-restart-service-account"] = models.V1ServiceAccount(
                metadata=models.V1ObjectMeta(
                    name="rollout-restart",
                    annotations=self.annotations,
                ),
            ).to_dict()

            # Create role
            items["rollout-restart-role"] = models.V1Role(
                api_version="rbac.authorization.k8s.io/v1",
                metadata=models.V1ObjectMeta(
                    name="rollout-restart",
                    annotations=self.annotations,
                ),
                rules=[{
                    "apiGroups": [
                        "apps",
                        "extensions"
                    ],
                    "resources": [
                        "deployments",
                        "daemonsets"
                    ],
                    "resourceNames": [
                        *cron_restart_services.keys()
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
            with open(self.args.out, "w", encoding="UTF-8") as fw:
                kompose_items.extend(items.values())
                if self.args.json:
                    json.dump(output, fw, indent=self.args.indent)
                else:
                    yaml.safe_dump(output, stream=fw, indent=self.args.indent, width=0x7fffffff)
            self.logger.info(f"Kubernetes file \"{self.args.out}\" updated")
            return

        # If output is directory
        for item_name, item in items.items():
            updated = item.pop("updated", False)
            f_path = path.join(out_path, f"{item_name}.{file_ext}")
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
            service_type = labels.get("kompose.service.type", "").lower()

            if "kompose.service.expose" in labels:
                service_type = "ingress"
            elif service_type not in ["loadbalancer", "nodeport"]:
                public = False

            services[name] = {
                "type": service_type,
                "public": public,
                "labels": labels,
                "service": service,
                "build": "build" in service,
                "records": self.parse_records(labels=labels),
                "controller": labels.get("kompose.controller.type", "deployment").lower(),
                "allow_egress": labels.get("kompose-ex.egress.allow", "false").lower() == "true",
                "allow_ingress": labels.get("kompose-ex.ingress.allow", "false").lower() == "true",
                "cronjob": labels.get("kompose-ex.controller.type", "").lower() == "cronjob",
                "cronjob-schedule": labels.get("kompose-ex.cronjob.schedule"),
                "cronjob-concurrency-policy": labels.get("kompose-ex.cronjob.concurrency_policy", "Allow"),
                "rollout-restart-cronjob-schedule": labels.get("kompose-ex.rollout-restart.cronjob.schedule"),
            }

        return services

    def run(self, configure_logger=True):
        # Configure basic logger
        if configure_logger:
            self.configure_logger()

        if self.args.command == "version":
            print(self.version)
            return 0

        # Load compose yaml
        with open(self.args.file, "r", encoding="UTF-8") as fr:
            self.compose = yaml.safe_load(fr.read())

        # Recreate compose yaml
        compose_path = self.recreate_compose()
        if not compose_path:
            return 1

        # Convert docker compose yaml using kompose
        # self.logger.info(f"Converting {path.basename(self.args.file)} to {self.args.out}")
        return_code = self.kompose_convert(compose_path=compose_path)
        if return_code:
            return return_code

        # Get compose services
        services = self.get_services()
        self.kompose_ex_convert(services)

        return 0

    def start(self):
        try:
            return self.run()
        except Exception as ex:
            self.logger.fatal(ex)
        return 1


6


def main(args=None):
    kompose = KomposeEx(args=args)
    return kompose.start()
