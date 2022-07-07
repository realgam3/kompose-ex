import os
import json
import time
import logging
from os import path
from glob import glob
from kubernetes import client
from kubernetes.utils import create_from_yaml, FailToCreateError


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
