import json
import time
import logging
from os import path
from glob import glob

import yaml
from kubernetes import client
from kubernetes.utils import create_from_yaml, FailToCreateError
from kubernetes.utils.create_from_yaml import UPPER_FOLLOWED_BY_LOWER_RE, LOWER_OR_NUM_FOLLOWED_BY_UPPER_RE

from . import utils


@utils.retries(2)
def delete_namespace(name, logger=None):
    logger = logger or logging.getLogger(__name__)

    core_api = client.CoreV1Api()
    try:
        core_api.delete_namespace(name)
        logger.info(f"namespace \"{name}\" deleted")
    except client.ApiException as ex:
        body = json.loads(ex.body)
        if "not found" not in body["message"]:
            raise ex
        logger.warning(body["message"])

    # Wait for namespace deletion
    while True:
        try:
            core_api.read_namespace(name)
            time.sleep(1)
        except client.ApiException as ex:
            body = json.loads(ex.body)
            if "not found" in body["message"]:
                break
            raise ex


@utils.retries(2)
def create_namespace(name, logger=None):
    logger = logger or logging.getLogger(__name__)

    core_api = client.CoreV1Api()
    try:
        core_api.create_namespace(
            client.V1Namespace(
                metadata=client.V1ObjectMeta(
                    name=name
                )
            )
        )
        logger.info(f"namespace \"{name}\" created")
    except client.ApiException as ex:
        body = json.loads(ex.body)
        logger.error(body["message"])

    # Wait for namespace creation
    while True:
        try:
            res = core_api.read_namespace(name).to_dict()
            status = res.get("status", {}).get("phase", "").lower()
            if status == "active":
                break
            time.sleep(1)
        except client.ApiException as ex:
            body = json.loads(ex.body)
            if "not found" in body["message"]:
                time.sleep(1)
                continue
            raise ex


@utils.retries(2)
def apply(files_path, namespace="default", verbose=False, logger=None, **kwargs):
    logger = logger or logging.getLogger(__name__)

    api_client = client.ApiClient()
    files = [files_path]
    if path.isdir(files_path):
        files = glob(path.join(files_path, "*"))
    for file_path in files:
        try:
            create_from_yaml(
                api_client,
                file_path,
                verbose=verbose,
                namespace=namespace,
                **kwargs
            )
            logger.info(f"Kubernetes file \"{file_path}\" deployed")
        except FailToCreateError as ex:
            body = json.loads(ex.api_exceptions[0].body)
            raise Exception(f"Kubernetes file \"{file_path}\" failed ({body['message']})")


def patch_from_yaml(k8s_client, yml_object, verbose=False, **kwargs):
    group, _, version = yml_object["apiVersion"].partition("/")
    if version == "":
        version = group
        group = "core"
    group = "".join(group.rsplit(".k8s.io", 1))
    group = "".join(word.capitalize() for word in group.split('.'))
    fcn_to_call = "{0}{1}Api".format(group, version.capitalize())
    k8s_api = getattr(client, fcn_to_call)(k8s_client)
    kind = yml_object["kind"]
    kind = UPPER_FOLLOWED_BY_LOWER_RE.sub(r'\1_\2', kind)
    kind = LOWER_OR_NUM_FOLLOWED_BY_UPPER_RE.sub(r'\1_\2', kind).lower()
    if "name" in yml_object["metadata"]:
        name = yml_object["metadata"]["name"]
        kwargs['name'] = name

    # Expect the user to patch namespaced objects more often
    if hasattr(k8s_api, "patch_namespaced_{0}".format(kind)):
        # Decide which namespace we are going to put the object in,
        # if any
        if "namespace" in yml_object["metadata"]:
            namespace = yml_object["metadata"]["namespace"]
            kwargs['namespace'] = namespace
        resp = getattr(k8s_api, "patch_namespaced_{0}".format(kind))(
            body=yml_object, **kwargs)
    else:
        kwargs.pop('namespace', None)
        resp = getattr(k8s_api, "patch_{0}".format(kind))(
            body=yml_object, **kwargs)
    if verbose:
        msg = "{0} patched.".format(kind)
        if hasattr(resp, 'status'):
            msg += " status='{0}'".format(str(resp.status))
        print(msg)
    return resp


@utils.retries(2)
def patch(files_path, verbose=False, logger=None, **kwargs):
    logger = logger or logging.getLogger(__name__)

    api_client = client.ApiClient()
    files = [files_path]
    if path.isdir(files_path):
        files = glob(path.join(files_path, "*"))
    for file_path in files:
        try:
            with open(file_path, "r", encoding="UTF-8") as fr:
                yaml_obj = yaml.safe_load(fr)
                patch_from_yaml(
                    api_client,
                    yaml_obj,
                    verbose=verbose,
                    **kwargs
                )
            logger.info(f"Kubernetes file \"{file_path}\" patched")
        except FailToCreateError as ex:
            body = json.loads(ex.api_exceptions[0].body)
            raise Exception(f"Kubernetes file \"{file_path}\" failed ({body['message']})")


@utils.retries(10, delay=2)
def load_balancer_address(name, namespace="default", ingress=False):
    core_api = client.CoreV1Api()
    read_namespaced_func = core_api.read_namespaced_service
    if ingress:
        network_api = client.NetworkingV1Api()
        read_namespaced_func = network_api.read_namespaced_ingress

    status = read_namespaced_func(
        name=name,
        namespace=namespace
    ).status
    return status.load_balancer.ingress[0].hostname
