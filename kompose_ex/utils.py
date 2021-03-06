import os
import time
import shutil
import logging
import tarfile
import platform
import requests
import functools
import subprocess
from os import path
from urllib.parse import urlparse
from jsonpath_ng.ext import parser

machine = platform.machine().lower()
if machine == "x86_64":
    machine = "amd64"
system = platform.system().lower()


# Retries Decorator
def retries(number_of_retries=15, delay=1, reraise=True, logger=None):
    logger = logger or logging.getLogger(__name__)

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            for i in range(number_of_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as ex:
                    if logger:
                        logger.error(f"Function {func.__name__} call [{i + 1}/{number_of_retries}] failed ({ex})")
                    time.sleep(delay)
            if reraise:
                raise Exception(f"Function {func.__name__} failed too many times")

        return wrapper

    return decorator


def process_output(*args, **kwargs):
    logger = kwargs.pop("logger", logging.getLogger(__name__))
    command = path.splitext(path.basename(kwargs.get("args", args)[0]))[0].lower()
    code = 0
    try:
        output = subprocess.check_output(*args, **kwargs)
        for line in output.decode().splitlines():
            logger.info(f"[{command}] {line}")
    except subprocess.CalledProcessError as ex:
        output = ex.output
        for line in ex.output.decode().splitlines():
            logger.error(f"[{command}] {line}")
        logger.error(f"[{command}] exit {ex.returncode}")
        code = ex.returncode,
    return code, output


@retries(number_of_retries=2)
def download_file(url, download_path=None):
    download_path = download_path or path.basename(urlparse(url).path)
    with requests.get(url, stream=True) as r:
        r.raise_for_status()
        with open(download_path, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
    return download_path


@retries(number_of_retries=2)
def install_kompose(download_path=None, version="latest"):
    download_path = download_path or os.getcwd()

    # Find kompose tar.gz file
    version = version.lower()
    res = requests.get(f"https://api.github.com/repos/kubernetes/kompose/releases/{version}")
    if version != "latest":
        res = requests.get(f"https://api.github.com/repos/kubernetes/kompose/releases/tags/v{version.lstrip('v')}")
    res_json = res.json()
    jsonpath_expr = parser.parse(
        f"$.assets[?(@.name =~ 'kompose-{system}-{machine}.*.tar.gz')]['browser_download_url']"
    )
    res_jsonpath = jsonpath_expr.find(res_json)
    if not res_jsonpath:
        raise Exception(f"could not find version for kompose-{system}-{machine}")

    # Download kompose tar.gz file
    browser_download_url = res_jsonpath[0].value
    local_filename = path.join(download_path, path.basename(browser_download_url))
    download_file(browser_download_url, local_filename)

    # Extract kompose tar.gz file
    with tarfile.open(local_filename) as tf:
        filename = tf.getnames()[0]
        short_filename = f"kompose"
        path_ext = path.splitext(filename)
        if path_ext:
            short_filename += path_ext[-1]
        tf.extract(filename, download_path)
        os.replace(path.join(download_path, filename), path.join(download_path, short_filename))
    os.remove(local_filename)

    # Return version
    return res_json['tag_name']


@retries(number_of_retries=2)
def clean(files_path):
    if not path.exists(files_path):
        return

    is_file = path.isfile(files_path)
    if not is_file:
        shutil.rmtree(files_path, ignore_errors=True)
        return

    os.remove(files_path)
