import re
from kubernetes.client import models
from kubernetes.client.models import *


def convert(k8s_object: dict):
    k8s_obj = {}
    for _key, obj in k8s_object.items():
        if obj is None:
            continue

        key = _key
        if key.count("_"):
            _key = _key.split("_")
            for i in range(1, len(_key)):
                _key[i] = _key[i].title()
            key = "".join(_key)

        k8s_obj[key] = obj
    return k8s_obj


def patch_modes():
    for key, obj in vars(models).items():
        if not re.match(r"^V\d+\w+$", key):
            continue
        kind = re.sub(r"V\d+(?:beta)*\d*", "", key, flags=re.IGNORECASE)
        version = re.search(r"^(?P<version>V\d+(?:beta)*\d*)", key, flags=re.IGNORECASE).group("version").lower()
        obj._to_dict = obj.to_dict
        obj.to_dict = lambda self: convert(self._to_dict())
        if hasattr(obj, "kind") and hasattr(obj, "api_version"):
            obj.kind = kind
            obj.api_version = version


patch_modes()
