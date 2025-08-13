# Copyright 2022 rev1si0n (lamda.devel@gmail.com). All rights reserved.
#
# Distributed under MIT license.
# See file LICENSE for detail or copy at https://opensource.org/licenses/MIT
# encoding=utf-8
import os
import re
import io
import csv
import time
import json
import random
import shutil
import logging
import platform
import socket
import ipaddress
import psutil
import asyncio
import uvloop
import importlib
import tornado.web
import tornado.ioloop
import cachetools.func
import requests
import redis

from hashlib import sha256
from base64 import b64encode
from collections import OrderedDict
from lamda.client import Device as GrpcDevice
from urllib.parse import urlparse
from collections import Counter
from pathlib import Path

from tornado.ioloop import IOLoop
from tornado.options import define, options
from tornado.web import Application, HTTPError
from tornado.websocket import WebSocketHandler
from tornado.netutil import bind_unix_socket
from tornado.httpserver import HTTPServer

from . import __version__
from .models import *
from .utils import *

errors = {}
# platform
errors["E40101"] = "Unauthorized group"
errors["E40102"] = "Not a platform administrator group"
errors["E40103"] = "Not the device owner"
errors["E40005"] = "Target group cannot be an administrator"
errors["E40105"] = "Only administrators or owners can operate"
errors["E40401"] = "Group does not exist"
errors["E40402"] = "Device does not exist"
errors["E40405"] = "No translation file for this language"
errors["E40001"] = "Invalid groupname or password"
errors["E40002"] = "The group already owns the device"
errors["E40003"] = "Group already exists"
errors["E40004"] = "Unable to operate this group"
errors["E40017"] = "Invalid groupname"
errors["E50000"] = "Internal server error"
errors["E40000"] = "Bad request"
errors["E41000"] = "Can not connect to device"
# bridger
errors["E40403"] = "No such service token"
errors["E40404"] = "No such node token"
errors["E40006"] = "This token is bounded to another client"
errors["E40007"] = "Duplicate ip address"
errors["E40008"] = "The network address for this token is not set"
errors["E40009"] = "Maximum allowed nodes exceeded"
errors["E40010"] = "Network is not configured"
errors["E40011"] = "Invalid ip address"
errors["E40012"] = "Exceed max node config entries"
errors["E40013"] = "Unable to set configuration for attached node"
errors["E40014"] = "Value cannot contain spaces"
errors["E40015"] = "Network is already configured"
errors["E40016"] = "Network too small or invalid"
errors["E40018"] = "Network is disabled"

db = redis.StrictRedis.from_url("unix:///run/redis.sock")
certdir = Path("/user/certificates")


class HttpServiceManager(object):
    def __init__(self, bind="/run/server.sock"):
        self.handlers = OrderedDict()
        pkg_dir = os.path.dirname(__file__)
        self.static = os.path.join(pkg_dir, "static")
        self.template = os.path.join(pkg_dir, "html")
        self.bind = bind

    def add_handler(self, route, name, *args,
                    handler="Handler"):
        handle = getattr(importlib.import_module(name),
                         handler)
        self.handlers[route] = (route, handle, *args)

    def start_server(self, **settings):
        loop = uvloop.new_event_loop()
        asyncio.set_event_loop(loop)
        self.ioloop = IOLoop.current()
        kwargs = {}
        kwargs["debug"] = False
        kwargs["template_path"] = self.template
        kwargs["compiled_template_cache"] = True
        kwargs["default_handler_class"] = DefaultHttpService
        kwargs["static_path"] = self.static
        kwargs.update(settings)
        http = Application(self.handlers.values(),
                           **kwargs)

        kwargs = {}
        kwargs["max_buffer_size"] = 33554432
        kwargs["xheaders"] = True
        server = HTTPServer(http, **kwargs)
        socket = bind_unix_socket(self.bind, mode=0o700)
        server.add_socket(socket)
        self.ioloop.start()


class BaseHttpService(tornado.web.RequestHandler):
    def get_login_group(self):
        cname = self.get_secure_cookie("token")
        xname = self.request.headers.get("X-Group", "")
        xauth = self.request.headers.get("X-Auth", "")

        group = Group.get_or_none(Group.name == cname)
        group = group or Group.get_or_none((Group.name == xname)
                                           & (Group.token == xauth))
        group or self.throw(401, "E40101")
        return group

    def get_login_group_by_token(self):
        token = self.get_argument("token")
        group = Group.get_or_none(Group.token == token)
        group or self.throw(401, "E40101")
        return group

    def get_group_with_password(self, name,
                                password):
        group = Group.get_or_none((Group.name == name)
                                  & (Group.password == password))
        group or self.throw(400, "E40001")
        return group

    def get_login_group_device(self, domain,
                               group=None):
        _ = self.get_device_by_domain(domain)
        group = group or self.get_login_group()
        device = Device.select().join(GroupDevice).where((GroupDevice.group == group)
                                                         & (Device.domain == domain)
                                                         ).get_or_none()
        device or self.throw(401, "E40103")
        return group, device

    def get_login_group_admin(self):
        group = self.get_login_group()
        group.admin or self.throw(401, "E40102")
        return group

    def get_group_admin_or_self(self, uid):
        group = self.get_group_by_id(uid)
        c = self.get_login_group()
        check = (group.id != c.id and not c.admin)
        check and self.throw(401, "E40105")
        return group

    def remove_device_from_group(self, domain, group):
        group, device = self.get_login_group_device(domain, group=group)
        query = GroupDevice.delete().where((GroupDevice.group_id == group.id)
                                           & (GroupDevice.device_id == device.id))
        return query.execute()

    def get_group_by_id(self, uid):
        group = Group.get_or_none((Group.id == uid) | (Group.name == uid))
        group or self.throw(404, "E40401")
        return group

    def get_normal_group_by_id(self, uid):
        group = self.get_group_by_id(uid)
        group.admin and self.throw(401, "E40005")
        return group

    def get_device_by_domain(self, domain):
        device = Device.get_or_none(Device.domain == domain)
        device or self.throw(404, "E40402")
        return device

    def alloc_device_to_group(self, domain, group):
        device = self.get_device_by_domain(domain)
        gd, created = GroupDevice.get_or_create(group=group,
                                                device=device)
        created or self.throw(400, "E40002")
        return gd

    def create_group(self, name, contact, **kwargs):
        re.match("^[a-zA-Z0-9_]{2,32}$", name) or self.throw(400,
                                                             "E40017")
        meta = kwargs.copy()
        meta["last_login_from"] = "0.0.0.0"
        meta["contact"] = contact
        meta["name"] = name
        group, created = Group.get_or_create(name=name,
                                             defaults=meta)
        created or self.throw(400, "E40003")
        return group

    def write_error(self, status, exc_info=None,
                    **kwargs):
        if status == 500:
            self._reason = "E50000"
        if status == 400 and not self._reason.startswith("E40"):
            self._reason = "E40000"
        self.finish({"status": status, "error": self._reason,
                     "message": exc_info[1].log_message})

    def __init__(self, *args, **kwargs):
        super(BaseHttpService, self).__init__(*args, **kwargs)
        self.ioloop = tornado.ioloop.IOLoop.current()

    async def call_sync_async(self, func, *args):
        return await self.ioloop.run_in_executor(None,
                                                 func, *args)

    def timestamp(self):
        return int(time.time())

    def tell(self, response):
        data = dict(status=0, message=None)
        data.update(response)
        self.write(data)

    def throw(self, status, error=None,
              message=None):
        message = message or errors.get(error)
        raise HTTPError(status, reason=error,
                        log_message=message)


class DefaultHttpService(BaseHttpService):
    def prepare(self, *args, **kwargs):
        raise HTTPError(400)


class PlatformValidateHandler(BaseHttpService):
    def head_default(self, domain):
        u, _ = self.get_login_group_device(domain)
        self.set_header("X-ClientId", u.name)

    def head_novnc(self, _):
        u = self.get_login_group_admin()
        self.set_header("X-ClientId", u.name)

    def head(self, domain):
        func = getattr(self, f"head_{domain}",
                       self.head_default)
        func(domain)


class PlatformInfoHandler(BaseHttpService):
    @cachetools.func.ttl_cache(ttl=5*60)
    def get_top_info(self):
        data = {}
        data["expire"] = 0
        data["limit"] = 2147483647
        return data

    @cachetools.func.ttl_cache(ttl=5)
    def get_info(self, *args):
        group = self.get_login_group()
        sel = Device.select().join(GroupDevice).where(
            GroupDevice.group == group)
        total = sel.count()
        usable = sel.where((Device.state == STATE_ONLINE)
                           & (Device.locked == False)).count()
        working = sel.where((Device.state == STATE_ONLINE)
                            & (Device.locked == True)).count()
        offline = sel.where((Device.state == STATE_OFFLINE)
                            ).count()
        res = {}
        res["node"] = platform.node()
        res["version"] = __version__
        res["uptime"] = int(psutil.Process().create_time())
        res["lic_type"] = self.application.settings["license_type"]
        res["lic_to"] = self.application.settings["license_to"]
        res["usable"] = usable
        res["offline"] = offline
        res["working"] = working
        res["total"] = total
        res.update(self.get_top_info())
        return dict(data=res)

    async def get(self, *args):
        res = await self.call_sync_async(self.get_info)
        self.tell(res)


class PlatformI18NTranslateHandler(BaseHttpService):
    def get(self, language):
        code = language.lower().replace("-", "_")
        lang = os.path.join(current, "i18n",
                            f"{code}.csv")
        os.path.isfile(lang) or self.throw(404, "E40405")
        fd = open(lang, "r", encoding="utf-8")
        rdr = csv.DictReader(filter(lambda row: row[0] != "#", fd))
        data = {item["key"]: item["value"] for item in rdr}
        fd.close()
        self.finish(data)


class PlatformI18NTranslateListHandler(BaseHttpService):
    def get(self, *args):
        config = os.path.join(current, "i18n",
                              "config.json")
        fd = open(config, "r", encoding="utf-8")
        data = json.loads(fd.read())
        fd.close()
        self.tell(dict(data=data))


class PlatformSpecificDeviceHandler(BaseHttpService):
    """
    查看和删除指定设备信息
    """

    def to_dict(self, r):
        d = r.to_dict(exclude=[Device.id,
                               Device.lock,
                               Device.frida,
                               Device.auth])
        d["gateway_port"] = int(os.environ["API_PORT"])
        return d

    def get(self, domain):
        _, d = self.get_login_group_device(domain)
        self.tell({"data": self.to_dict(d)})

    @ignore_exception(False)
    def reset_device(self, ip, domain):
        certfile = str(certdir.joinpath(f"{domain}.pem"))
        d = GrpcDevice(ip, certificate=certfile)
        d.delete_file("/data/usr/.config/remote.cfg")
        d.reload(True)
        return True

    def remove(self, domain):
        group = self.get_login_group_admin()
        _, d = self.get_login_group_device(domain, group=group)
        status = self.reset_device(d.default_ip, domain)
        remove_cert(certdir, domain)
        d.delete_instance(recursive=True)
        return dict(sync=status)

    async def delete(self, domain):
        res = await self.call_sync_async(self.remove,
                                         domain)
        self.tell(res)


class PlatformSpecificDeviceCommentHandler(BaseHttpService):
    def put(self, domain):
        group = self.get_login_group_admin()
        _, d = self.get_login_group_device(domain, group=group)
        comment = self.get_argument("comment")
        d.comment = comment
        d.save()
        self.tell(dict(status=0))


class PlatformDeviceStatsHandler(BaseHttpService):
    def to_dict(self, r):
        return r.to_dict(exclude=[DeviceStatus.device,
                                  DeviceStatus.id,])

    def get(self, domain):
        _, d = self.get_login_group_device(domain)
        limit = int(self.get_argument("limit", 60))
        items = d.status.select().order_by(DeviceStatus.timestamp.desc()
                                           ).limit(limit)
        data = {}
        res = [self.to_dict(i) for i in items]
        data["total"] = len(res)
        data["data"] = res
        self.tell(data)


class PlatformDeviceAllocHandler(BaseHttpService):
    def to_dict(self, group):
        return group.to_dict(exclude=[Group.password,
                                      Group.token])

    def get(self, domain):
        sort = getattr(Group,
                       self.get_argument("sort", "id"),
                       Group.id)
        sort = getattr(sort,
                       self.get_argument("order", "asc"),
                       sort.asc)()
        page = int(self.get_argument("page", 0))
        size = int(self.get_argument("size", 20))
        _, device = self.get_login_group_device(domain)
        sel = Group.select().join(GroupDevice).where(
            GroupDevice.device == device)
        items = sel.order_by(sort
                             ).paginate(page, size)
        data = {}
        data["page"] = page
        data["size"] = size
        groups = [self.to_dict(i) for i in items]
        data["total"] = sel.count()
        data["data"] = groups
        self.tell(data)

    def delete(self, domain):
        uid = self.get_argument("id")
        _ = self.get_login_group_admin()
        group = self.get_normal_group_by_id(uid)
        r = self.remove_device_from_group(domain, group)
        data = dict(status=int(not r))
        self.tell(data)

    def post(self, domain):
        uid = self.get_argument("id")
        _ = self.get_login_group_admin()
        group = self.get_normal_group_by_id(uid)
        self.alloc_device_to_group(domain, group)
        data = dict(status=0)
        self.tell(data)


class PlatformDeviceHandler(BaseHttpService):
    """
    添加设备和返回设备列表
    """

    def to_dict(self, r):
        return r.to_dict(only=[Device.domain,
                               Device.comment,
                               Device.boot_time,
                               Device.disk_total,
                               Device.mem_total,
                               Device.cpu_count,
                               Device.batt_charging,
                               Device.api_available,
                               Device.locked,
                               Device.controlling,
                               Device.brand,
                               Device.device,
                               Device.model,
                               Device.abi,
                               Device.version,
                               Device.sdk,
                               Device.hardware,
                               Device.board,
                               Device.reg_time,
                               Device.state,])

    @ignore_exception(None)
    def install_device(self, ip, config):
        d = GrpcDevice(ip)
        unique_id = d.server_info().uniqueId
        d.upload_fd(io.BytesIO(config.encode()),
                    "/data/usr/.config/remote.cfg")
        d.reload(True)
        return unique_id

    def new(self):
        domain = r_string(16)
        group = self.get_login_group_admin()
        ip = self.get_argument("ip", None)
        addr = self.application.settings["addr"]
        port = self.application.settings["port"]

        cfg = dict()
        cfg["properties.remote"] = f"http://{addr}:{port}/api/v1/{domain}/config"
        cfg["properties.tries"] = "60"
        cfg = "\n".join(["%s=%s" % (k, v) for k, v in cfg.items()])
        dev_id = self.install_device(ip, cfg)
        dev_id or self.throw(410, "E41000")

        res = {}
        res["domain"] = domain
        res["dev_id"] = dev_id

        # 生成客户端证书
        disable_mtls = self.application.settings["disable-mtls"]
        if not disable_mtls:
            logging.info("mtls enabled, generate client certificate")
            auth, cert = generate_client_pem(domain)
            res["cert"] = cert.decode()
            res["auth"] = auth

        device = Device.create(**res)
        if not disable_mtls:
            logging.info("mtls enabled, save client certificate")

            save_cert(certdir, domain, res["cert"])
        self.alloc_device_to_group(domain, group)
        return dict(data=self.to_dict(device))

    async def post(self):
        res = await self.call_sync_async(self.new)
        self.tell(res)

    def get(self, *args):
        sort = getattr(Device,
                       self.get_argument("sort", "id"),
                       Device.id)
        sort = getattr(sort,
                       self.get_argument("order", "asc"),
                       sort.asc)()
        page = int(self.get_argument("page", 0))
        size = int(self.get_argument("size", 20))
        group = self.get_login_group()
        sel = Device.select().join(GroupDevice).where(
            GroupDevice.group == group)
        items = sel.order_by(sort
                             ).paginate(page, size)
        data = {}
        data["page"] = page
        data["size"] = size
        devices = [self.to_dict(i) for i in items]
        data["total"] = sel.count()
        data["data"] = devices
        self.tell(data)


class PlatformDeviceDistributeHandler(BaseHttpService):
    def get(self, *args):
        group = self.get_login_group()
        sel = Device.select(Device.ip_country).join(GroupDevice).where(
            GroupDevice.group == group)
        data = {}
        data["total"] = sel.count()
        item = [item.ip_country for item in sel if item.ip_country]
        info = [dict(name=n, value=v) for n, v in Counter(item).items()]
        data["data"] = info
        self.tell(data)


class PlatformDeviceDistributeCountryHandler(BaseHttpService):
    def get(self, country):
        group = self.get_login_group()
        sel = Device.select(Device.ip_region).join(GroupDevice).where(
            (Device.ip_country == country) &
            (GroupDevice.group == group))
        data = {}
        data["total"] = sel.count()
        data["country"] = country
        item = [item.ip_region for item in sel if item.ip_region]
        info = [dict(name=n, value=v) for n, v in Counter(item).items()]
        data["data"] = info
        self.tell(data)


class PlatformDeviceDistributeRegionHandler(BaseHttpService):
    def get(self, country, region):
        group = self.get_login_group()
        sel = Device.select(Device.ip_city).join(GroupDevice).where(
            (Device.ip_country == country) &
            (Device.ip_region == region) &
            (GroupDevice.group == group))
        data = {}
        data["total"] = sel.count()
        data["country"] = country
        data["region"] = region
        item = [item.ip_city for item in sel if item.ip_city]
        info = [dict(name=n, value=v) for n, v in Counter(item).items()]
        data["data"] = info
        self.tell(data)


class PropertiesConfigHandler(BaseHttpService):
    """
    设备定时拉取设备的配置信息
    """
    def prepare(self):
        return None

    def get(self, domain):
        device = self.get_device_by_domain(domain)
        cfg = dict()
        cfg["event"] = self.application.settings["event"]
        cfg["ssl-web-credential"] = "firerpa.2025"  # the fixed device auth
        disable_mtls = self.application.settings["disable-mtls"]
        if not disable_mtls:
            logging.info("mtls enabled, b64encode client certificate")
            print("mtls enabled, b64encode client certificate")
            cfg["cert"] = b64encode(device.cert.encode()).decode()
        cfg = "\n".join(["%s=%s" % (k, v) for k, v in cfg.items()])
        self.finish(cfg)


class PlatformIndexHandler(BaseHttpService):
    def get(self, **kwargs):
        self.render("index.html",
                    **kwargs)


class PlatformGroupLoginHandler(BaseHttpService):
    def to_dict(self, group):
        res = group.to_dict(exclude=[Group.password])
        return dict(data=res)

    def get(self):
        u = self.get_login_group()
        self.tell(self.to_dict(u))

    def post(self):
        name = self.get_argument("name")
        passwd = self.get_argument("password")
        u = self.get_group_with_password(name, passwd)
        u.last_login_from = self.request.remote_ip
        u.login_time = time.time()
        u.save()
        self.set_secure_cookie("token", u.name)
        self.tell(self.to_dict(u))

    def delete(self):
        self.clear_cookie("token")
        self.tell({})


class PlatformGroupHandler(BaseHttpService):
    def to_dict(self, group):
        return group.to_dict(exclude=[Group.password,
                                      Group.token])

    def get(self):
        sort = getattr(Group,
                       self.get_argument("sort", "id"),
                       Group.id)
        sort = getattr(sort,
                       self.get_argument("order", "asc"),
                       sort.asc)()
        page = int(self.get_argument("page", 0))
        size = int(self.get_argument("size", 20))
        u = self.get_login_group_admin()
        items = Group.select().order_by(sort).paginate(
            page, size)
        data = {}
        data["page"] = page
        data["size"] = size
        groups = [self.to_dict(i) for i in items]
        data["total"] = Group.select().count()
        data["data"] = groups
        self.tell(data)

    def post(self):
        u = self.get_login_group_admin()
        name = self.get_argument("name")
        password = self.get_argument("password")
        contact = self.get_argument("contact", None)
        u = self.create_group(name, contact, password=password)
        self.tell(dict(data=self.to_dict(u)))


class PlatformSpecificGroupHandler(BaseHttpService):
    def to_dict(self, group):
        return group.to_dict(exclude=[Group.password,
                                      Group.token])

    def get(self, uid):
        u = self.get_group_admin_or_self(uid)
        self.tell(dict(data=self.to_dict(u)))

    def delete(self, uid):
        m = self.get_login_group()
        u = self.get_group_admin_or_self(uid)
        u.id == m.id and self.throw(400, "E40004")
        u.delete_instance(recursive=True)
        self.tell(dict(status=0))


class PlatformSpecificGroupCredHandler(BaseHttpService):
    def to_dict(self, group):
        return group.to_dict(exclude=[Group.password,
                                      Group.token])

    def put(self, uid):
        u = self.get_group_admin_or_self(uid)
        password = self.get_argument("password", None)
        contact = self.get_argument("contact", None)
        u.contact = contact or u.contact
        u.password = password or u.password
        u.save()
        self.tell(dict(data=self.to_dict(u)))


class DeviceEventHandler(BaseHttpService,
                         WebSocketHandler):
    async def on_message(self, data):
        data = json.loads(data)
        func = getattr(self, f"handle_{data['type']}",
                       self.handle_DEFAULT)
        await self.call_sync_async(func, data)

    async def open(self):
        did = self.request.headers.get("X-Did")
        self.d = Device.get(dev_id=did)
        self.domain = self.d.domain
        await self.write_message(
            "CLOUD_HELO")

    def prepare(self):
        return None

    def check_origin(self, origin):
        return True

    @cachetools.func.ttl_cache(ttl=60)
    def expire(self):
        deadline = (time.time() - 3.0*60)
        query = Device.update(state=STATE_OFFLINE).where((Device.heartbeat_time < deadline)
                                                         & (Device.state != STATE_PENDING))
        query.execute()

    def handle_BYE(self, data):
        self.d.controlling_cid = None
        self.d.controlling = False
        self.d.state = STATE_OFFLINE
        self.d.frida = None
        self.d.lock = None
        self.d.batt_charging = False
        self.d.api_available = False
        self.d.locked = False
        db.delete(f"gw:{self.domain}")
        remove_host_entry(self.domain)
        self.d.save()

    def handle_HELO(self, data):
        info = data["data"]
        self.d.dev_id = data["ID"]
        self.d.board = info["board"]
        self.d.hardware = info["hardware"]
        self.d.brand = info["brand"]
        self.d.device = info["device"]
        self.d.model = info["model"]
        self.d.abi = info["abi"]
        self.d.sdk = info["sdk"]
        self.d.boot_time = info["uptime"]
        self.d.version = info["version"]
        self.d.state = STATE_ONLINE
        self.d.heartbeat_time = time.time()
        self.d.save()

    def update_public_ip_info(self, ip):
        info = get_public_ip_info(ip)
        self.d.public_ip = ip
        self.d.ip_lat = info.get("latitude", 0)
        self.d.ip_lng = info.get("longitude", 0)
        self.d.ip_country = info.get("country_long")
        self.d.ip_region = info.get("region")
        self.d.ip_city = info.get("city")

    def handle_CLOUD_HELO(self, data):
        info = data["data"]
        self.d.service_port = info["port"]
        self.update_public_ip_info(info.get("public_ip"))
        self.d.locked = info["locked"]
        self.d.api_available = info["api_available"]
        self.d.frida = info["frida"]
        self.d.lock = info["lock"]
        self.d.controlling = bool(info["controlling"])
        self.d.controlling_cid = info["controlling"]
        self.set_redis_map(info["ip"], info["port"],
                           ttl=2.5*60)
        add_host_entry(info["ip"], self.domain,
                       comment="firerpa")
        self.d.save()

    def handle_CONTROL_ENTER(self, data):
        info = data["data"]
        self.d.controlling = True
        self.d.controlling_cid = info["client"]
        self.d.save()

    def handle_CONTROL_LEAVE(self, data):
        info = data["data"]
        self.d.controlling = False
        self.d.controlling_cid = None
        self.d.save()

    def set_redis_map(self, host, port,
                      ttl=10*60):
        rule = f"{host}:{port},{self.d.auth}"
        db.setex(f"gw:{self.domain}", int(ttl),
                 rule)

    def handle_SYSTEM_STAT(self, data):
        info = data["data"]
        info["default_ip"] = self.request.remote_ip
        self.d.heartbeat_time = time.time()
        self.d.default_ip = info["default_ip"]
        self.update_public_ip_info(info.get("public_ip"))
        self.d.service_port = info["service_port"]
        self.d.mem_total = info["mem_total"]
        self.d.disk_total = info["disk_total"]
        self.d.cpu_count = info["cpu_count"]
        self.d.batt_charging = info["batt_charging"]
        self.d.api_available = info["api_available"]
        self.d.state = STATE_ONLINE
        self.d.locked = info["locked"]
        self.d.save()
        host = info["default_ip"]
        port = info["service_port"]
        add_host_entry(info["default_ip"], self.domain,
                       comment="firerpa")
        self.set_redis_map(host, port)
        r = DeviceStatus.create(device=self.d,
                                **info)
        r.save()
        self.expire()

    def handle_LOCK(self, data):
        info = data["data"]
        self.d.frida = info["frida"]
        self.d.lock = info["lock"]
        self.d.locked = True
        self.d.save()

    def handle_UNLOCK(self, data):
        self.d.lock = None
        self.d.locked = False
        self.d.save()

    def handle_DEFAULT(self, data):
        return None

    def _cleanup(self):
        self.handle_BYE(None)

    def on_close(self):
        self._cleanup()

    def on_connection_close(self):
        self._cleanup()


class Service(object):
    def __init__(self, path="/run/server.sock"):
        http = HttpServiceManager(path)
        http.add_handler("/", "server.service",
                         handler="PlatformIndexHandler")
        http.add_handler("/ws/event", "server.service",
                         handler="DeviceEventHandler")
        # HEAD
        http.add_handler("/validate/([0-9a-z]+)", "server.service",
                         handler="PlatformValidateHandler")
        # GET
        http.add_handler("/api/v1/i18n", "server.service",
                         handler="PlatformI18NTranslateListHandler")
        http.add_handler("/api/v1/i18n/([a-zA-Z-_]+)", "server.service",
                         handler="PlatformI18NTranslateHandler")
        # PUT
        http.add_handler("/api/v1/device/([a-z0-9]+)/comment", "server.service",
                         handler="PlatformSpecificDeviceCommentHandler")
        # GET
        http.add_handler("/api/v1/device/distribute/(.*?)/(.*?)", "server.service",
                         handler="PlatformDeviceDistributeRegionHandler")
        http.add_handler("/api/v1/device/distribute/(.*?)", "server.service",
                         handler="PlatformDeviceDistributeCountryHandler")
        http.add_handler("/api/v1/device/distribute", "server.service",
                         handler="PlatformDeviceDistributeHandler")
        # GET, DELETE
        http.add_handler("/api/v1/device/([a-z0-9]+)", "server.service",
                         handler="PlatformSpecificDeviceHandler")
        # GET
        http.add_handler("/api/v1/device/([a-z0-9]+)/status", "server.service",
                         handler="PlatformDeviceStatsHandler")
        # GET, POST, DELETE
        http.add_handler("/api/v1/device/([a-z0-9]+)/alloc", "server.service",
                         handler="PlatformDeviceAllocHandler")
        # GET, POST
        http.add_handler("/api/v1/device", "server.service",
                         handler="PlatformDeviceHandler")
        # GET
        http.add_handler("/api/v1/info", "server.service",
                         handler="PlatformInfoHandler")
        # GET
        http.add_handler("/api/v1/([a-z0-9]+)/config", "server.service",
                         handler="PropertiesConfigHandler")
        # GET, DELETE
        http.add_handler("/api/v1/group/(\d+)", "server.service",
                         handler="PlatformSpecificGroupHandler")
        # PUT
        http.add_handler("/api/v1/group/(\d+)/credentials", "server.service",
                         handler="PlatformSpecificGroupCredHandler")
        # GET, POST, DELETE
        http.add_handler("/api/v1/group/login", "server.service",
                         handler="PlatformGroupLoginHandler")
        # GET, POST
        http.add_handler("/api/v1/group", "server.service",
                         handler="PlatformGroupHandler")
        self.http = http

    def init(self):
        certdir.mkdir(parents=True, exist_ok=True)
        database = BaseDatabaseModel.__dict__["_meta"].database
        database.init("/user/database.db", pragmas={
            "foreign_keys": "1",
            "locking_mode": "NORMAL",
            "journal_mod": "wal",
            "synchronous": "NORMAL"})
        Device.create_table()
        DeviceStatus.create_table()
        Group.create_table()
        GroupDevice.create_table()
        Config.create_table()
        # set all device to offline status
        query = Device.update(state=STATE_OFFLINE).where(
            Device.state != STATE_PENDING)
        query.execute()
        self.create_default_user()

    def create_default_user(self):
        Group.select().count() != 0 or self.create_admin()

    def create_admin(self):
        meta = dict()
        meta["contact"] = None
        meta["last_login_from"] = "0.0.0.0"
        meta["name"] = "admin"
        meta["password"] = "firerpa"  # default admin password
        meta["admin"] = True
        Group.create(**meta)

    def run(self):
        define("addr", type=str)
        tornado.options.parse_command_line()

        self.cfg = {}
        self.cfg["cookie_secret"] = "secret"
        self.cfg["license_to"] = "COMMUNITY"
        self.cfg["license_type"] = "COMMUNITY"
        self.cfg["event"] = f"ws://{options.addr}:{os.environ['WEB_PORT']}/ws/event"
        self.cfg["port"] = int(os.environ["WEB_PORT"])
        self.cfg["addr"] = options.addr
        # self.cfg["disable-mtls"] = os.environ.get('DISABLE_MTLS', 'false').lower() == 'true'  # 是否禁用双向认证
        self.cfg["disable-mtls"] = True  # 是否禁用双向认证
        self.init()

        logging.getLogger().setLevel(logging.INFO)
        self.http.start_server(**self.cfg)
