from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os.path
import re
import tarfile
import tempfile
import threading
import traceback
import queue

from ansible.module_utils.urls import open_url
from ansible.module_utils.common.text.converters import to_bytes, to_text
from ansible.module_utils.six.moves.urllib.error import HTTPError


class Worker(threading.Thread):

    def __init__(self, tasks):
        super(Worker, self).__init__()
        self.tasks = tasks
        self.daemon = True
        self.start()

    def run(self):
        while True:
            func, args, kwargs = self.tasks.get()
            try:
                func(*args, **kwargs)

            except:
                traceback.print_exc()

            finally:
                self.tasks.task_done()


class ThreadPool:

    def __init__(self, workers):
        self.tasks = queue.Queue()
        self._worker_count = workers
        for dummy in range(self._worker_count):
            Worker(self.tasks)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.wait()
        return

    def submit(self, func, *args, **kwargs):
        self.tasks.put((func, args, kwargs))

    def wait(self):
        # for dummy in range(self._worker_count):
        #     self.tasks.put(None)
        self.tasks.join()


def process_collection(collection_name, download_url, collection_cache):
    print("Processing collection %s" % collection_name)
    bufsize = 65536

    with tempfile.NamedTemporaryFile() as temp_archive:
        resp = open_url(download_url)

        data = resp.read(bufsize)
        while data:
            temp_archive.write(data)
            temp_archive.flush()
            data = resp.read(bufsize)

        try:
            with tarfile.open(temp_archive.name, mode='r') as c_tar, c_tar.extractfile('FILES.json') as files_fd:
                collection_files = json.loads(to_text(files_fd.read(), errors='surrogate_or_strict'))
        except Exception as e:
            raise Exception("Failed to open collection %s: %s" % (collection_name, e)) from e

    plugin_path_pattern = re.compile('plugins/([\\w\\d_]+)/(.*)')
    for file_info in collection_files['files']:
        matches = plugin_path_pattern.match(file_info['name'])
        if not matches:
            continue

        plugin_type = matches.group(1)
        plugin_name = matches.group(2)

        if plugin_name in ['__init__.py', '.keep']:
            continue

        if plugin_type not in collection_cache:
            collection_cache[plugin_type] = []

        collection_cache[plugin_type].append(os.path.splitext(plugin_name)[0])


def get_collection_download(collection_info, pool, collection_cache):
    collection_name = '%s.%s' % (collection_info['namespace']['name'], collection_info['name'])

    error = False
    while True:
        try:
            resp = open_url(collection_info['latest_version']['href'])
        except HTTPError as e:
            if not e.code == 520:
                raise
            print("520 error for %s" % collection_name)
            error = True
        else:
            break

    if error:
        print("Error resolved for %s" % collection_name)

    resp_data = to_text(resp.read(), errors='surrogate_or_strict')
    collection_info = json.loads(resp_data)
    download_url = collection_info['download_url']

    collection_cache[collection_name] = {}
    pool.submit(process_collection, collection_name, download_url, collection_cache[collection_name])


def get_collection_list(endpoint, collection_queue):
    collections = {
        'next': '/api/v2/collections/?page_size=100'
    }

    while True:
        if not collections['next']:
            collection_queue.put(None)
            break

        collection_url = '%s%s' % (endpoint, collections['next'])
        resp = open_url(collection_url)
        resp_data = to_text(resp.read(), errors='surrogate_or_strict')
        collections = json.loads(resp_data)
        for collection_info in collections['results']:
            collection_queue.put(collection_info)

        #collections['next'] = None


def build_cache(max_workers):
    endpoint = 'https://galaxy.ansible.com'
    collection_queue = queue.Queue()
    collection_cache = {}

    with ThreadPool(max_workers) as pool:
        pool.submit(get_collection_list, endpoint, collection_queue)
        while True:
            collection_info = collection_queue.get()
            if not collection_info:
                break

            pool.submit(get_collection_download, collection_info, pool, collection_cache)

    print("Done thread pool")

    return collection_cache


def convert_to_plugin_lookup(collection_cache):
    plugin_lookup = {}
    for collection, plugin_info in collection_cache.items():
        for plugin_type, plugin_names in plugin_info.items():
            for name in plugin_names:
                name_lookup = plugin_lookup.setdefault(name, {})
                type_lookup = name_lookup.setdefault(plugin_type, [])
                type_lookup.append(collection)

    return plugin_lookup


def main():
    cache_path = os.path.expanduser(os.path.expandvars('~/.ansible/collection.cache'))
    reset_cache = False
    if not os.path.exists(cache_path) or reset_cache:
        collection_cache = build_cache(8)
        with open(cache_path, mode='wb') as fd:
            fd.write(to_bytes(json.dumps(collection_cache), errors='surrogate_or_strict'))

    else:
        with open(cache_path, mode='rb') as fd:
            collection_cache = json.loads(to_text(fd.read(), errors='surrogiate_or_strict'))

    plugin_name = 'ping'
    plugin_info = convert_to_plugin_lookup(collection_cache)

    if plugin_name in plugin_info:
        print("Found the following '%s' plugins" % plugin_name)
        for plugin_type, collections in plugin_info[plugin_name].items():
            print("\n%s" % plugin_type)
            for collection in collections:
                print("    %s" % collection)

    else:
        print("No collections found")


if __name__ == '__main__':
    import time
    start = time.time()
    main()
    total = time.time() - start
    #print(total)
