import asyncio
from aiohttp import web
import uuid
import os
import sys
import logging
import websockets
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
root = logging.getLogger()
root.setLevel(LOG_LEVEL)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(LOG_LEVEL)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
root.addHandler(handler)

logging.getLogger("didcomm").setLevel(logging.WARN)
logger = logging.getLogger(__name__)

#from didcomm_messaging import quickstart
import quickstart
from didcomm_messaging.resolver.peer import Peer2, Peer4
from didcomm_messaging.resolver.web import DIDWeb
from typing import (
    Optional,
    Dict,
    List,
    Any,
    Union,
    Callable,
    Awaitable,
    Tuple,
)
from did_peer_2 import KeySpec, generate
from aries_askar import Key, KeyAlg
from didcomm_messaging.multiformats import multibase, multicodec
from didcomm_messaging.resolver import PrefixResolver
import json
import subprocess
import time
import re

RELAY_DID = 'did:web:dev.cloudmediator.indiciotech.io'


class SecretsManager:
    """SecretsManager.
    """

    def __init__(self, storage_file: str | None = None):
        """__init__.

        Args:
            storage_file (str | None): storage_file
        """
        self.file = storage_file or "secrets.json"

    def load_secrets(self) -> Dict[str, Any] | None:
        """Load secrets from a JSON file (INSECURE!!!).

        Args:

        Returns:
            Dict[str, Any] | None:
        """
        try:
            file = open(self.file, "rb")
            config = json.loads(file.read())

            secrets = config["secrets"]
            new_secrets = []
            for secret in secrets:
                new_secrets.append(Key.from_jwk(secret))
            config["secrets"] = new_secrets

            return config
        except Exception as e:
            logger.debug("Secrets file doesn't exist")
            logger.error(e)
            return None

    def store_secrets(self, secrets: Dict[str, Any]):
        """Store secrets into a JSON file (INSECURE!!!).

        Args:
            secrets (Dict[str, Any]): secrets
        """
        try:
            file = open(self.file, "wb+")
            did = secrets["did"]
            secrets = secrets["secrets"]
            new_secrets = []
            for secret in secrets:
                new_secrets.append(json.loads(secret.get_jwk_secret()))
            save_data = {
                "did": did,
                "secrets": new_secrets,
            }
            file.write(json.dumps(save_data).encode())
        except Exception as err:
            logger.debug("Failed to write secrets file")
            logger.exception(err)

    def generate_secrets(self) -> Dict[str, Any]:
        """Generate DID & relevant secrets.

        Args:

        Returns:
            Dict[str, Any]:
        """

        from did_peer_2 import KeySpec, generate
        #did, secrets = quickstart.generate_did()
        verkey = Key.generate(KeyAlg.ED25519)
        xkey = Key.generate(KeyAlg.X25519)
        did = generate(
            [
                KeySpec.verification(
                    multibase.encode(
                        multicodec.wrap("ed25519-pub", verkey.get_public_bytes()),
                        "base58btc",
                    )
                ),
                KeySpec.key_agreement(
                    multibase.encode(
                        multicodec.wrap("x25519-pub", xkey.get_public_bytes()), "base58btc"
                    )
                ),
            ],
            [
                {
                    "type": "DIDCommMessaging",
                    "serviceEndpoint": {
                        "uri": "didcomm:transport/queue",
                        "accept": ["didcomm/v2"],
                        "routingKeys": [],
                    },
                },
            ],
        )
        #return did, (verkey, xkey)
        secrets = (verkey, xkey)
        secrets = {
            "secrets": secrets,
            "did": did,
        }

        return secrets

    def generate_and_save(self) -> Dict[str, Any]:
        """Generate and save secrets.

        Args:

        Returns:
            Dict[str, Any]:
        """
        secrets = self.generate_secrets()
        self.store_secrets(secrets)
        return secrets


last_executed = 0

gstate = {}

async def main():
    #did, secrets = quickstart.generate_did()

    logger.info("Starting Name-tag DIDComm service")
    secret_manager = SecretsManager("secrets.json")
    secrets = secret_manager.load_secrets()
    # secrets = None
    if not secrets:
        # secrets = secret_manager.generate_secrets()
        secrets = secret_manager.generate_and_save()

    did = secrets["did"]
    secrets = secrets["secrets"]

    DMP = await quickstart.setup_default(did, secrets)
    resolver = PrefixResolver({
        "did:peer:2": Peer2(),
        "did:peer:4": Peer4(),
        "did:web": DIDWeb(),
    })
    DMP.resolver = resolver
    DMP.packaging.resolver = resolver
    DMP.routing.resolver = resolver
    relayed_did = await quickstart.setup_relay(DMP, did, RELAY_DID, *secrets) or did
    logger.info("My DID: %s" % did)
    logger.info("My relayed DID: %s" % relayed_did)

    async def print_msg(msg):
        global last_executed
        target_did = msg["from"]
        if msg["type"] == "https://didcomm.org/user-profile/1.0/request-profile":
            if "displayName" in msg["body"]["query"]:
                message = {
                    "type": "https://didcomm.org/user-profile/1.0/profile",
                    "id": str(uuid.uuid4()),
                    "body": {
                        "profile": {
                            "displayName": "Colton's Raspberry Pi Zero"
                        }
                    },
                    "from": relayed_did,
                    "to": [target_did],
                }
                await quickstart.send_http_message(DMP, relayed_did, message, target=target_did)
        if msg["type"] == "https://didcomm.org/basicmessage/2.0/message":
            pass
        if msg["type"] == "https://colton.wolkins.net/dev/name-tag/2.0/set-name":
            COOLDOWN_AMOUNT = 30.0  # Give enough time for the nametag to update
            MAX_LENGTH = 116
            new_name = msg["body"]["name"]
            response = ""
            valid_chars =  re.compile(r"^[a-zA-Z0-9 !#\*/\\_-]+$");

            async def send_status_report(status, message, name):
                message = {
                    "type": "https://colton.wolkins.net/dev/name-tag/2.0/status",
                    "id": str(uuid.uuid4()),
                    "body": {
                        "status": status,
                        "description": message,
                        "new-name": name,
                    },
                    "from": relayed_did,
                    "to": [target_did],
                }
                await quickstart.send_http_message(DMP, relayed_did, message, target=target_did)
            async def send_problem_report(code, message):
                message = {
                    "type": "https://didcomm.org/report-problem/2.0/problem-report",
                    "id": str(uuid.uuid4()),
                    "pthid": msg["id"],
                    "body": {
                        "code": code,
                        "comment": message
                    },
                    "from": relayed_did,
                    "to": [target_did],
                }
                await quickstart.send_http_message(DMP, relayed_did, message, target=target_did)

            if len(new_name) > MAX_LENGTH:
                await send_problem_report("e.m.msg.name-too-long", "Name too long, pick a shorter name")
            elif last_executed + COOLDOWN_AMOUNT > time.time():
                await send_problem_report("e.m.req.time.cooldown", f"Nametag Cooldown in effect, please try again in a few minutes. {(last_executed + COOLDOWN_AMOUNT) - time.time()} seconds remaining")
            elif not valid_chars.match(new_name):
                await send_problem_report("e.m.msg.invalid-characters", "Invalid characters detected, try characters from the English alphabet")
            else:
                last_executed = time.time()
                await send_status_report("pending", "Setting name tag to", new_name)
                subprocess.run(["env", "-i", "sudo", "python3", "/home/pi/Pimoroni/inky/examples/name-badge.py", "--name", new_name])
                last_executed = time.time()
                await send_status_report("changing", "Name tag to", new_name)
        print("Received Message: ", msg["body"])

    mediator_websocket = None
    mediator_websocket_proc = None

    async def handle_websocket(mediator_websocket, livedelmsg):
        async with mediator_websocket as websocket:
            await websocket.send(livedelmsg)
            logger.info("connected!")
            while True:
                message = await websocket.recv()
                logger.info("Got message over websocket")
                try:
                    unpacked = await DMP.packaging.unpack(message)
                    msg = unpacked[0].decode()
                    msg = json.loads(msg)
                    logger.info("Received websocket message %s", msg["type"])
                    if msg["from"] != RELAY_DID:
                        gstate["last_did"] = msg["from"]
                        await print_msg(msg)
                except Exception as err:
                    logger.error("Error encountered")
                    logger.exception(err)
                    pass
            await websocket.close()


    async def activate_websocket():
        message = {
            "type": "https://didcomm.org/messagepickup/3.0/live-delivery-change",
            "id": str(uuid.uuid4()),
            "body": {
                "live_delivery": True,
            },
            "from": did,
            "to": [RELAY_DID],
        }
        packy = await DMP.pack(
            message=message,
            to=RELAY_DID,
            frm=did,
        )
        packed = packy.message
        endpoint = packy.get_endpoint("ws")
        logger.info("Relay Websocket Address: %s", endpoint)
        if endpoint:
            logger.info("Found Relay websocket, connecting")
            mediator_websocket = websockets.connect(
                uri=endpoint
            )
            return asyncio.create_task(handle_websocket(mediator_websocket, packed))

    mediator_websocket_proc = await activate_websocket()

    async def message_last_did(message):
        if gstate.get("last_did"):
            message = {
                "type": "https://didcomm.org/basicmessage/2.0/message",
                "id": str(uuid.uuid4()),
                "body": {
                    "content": message,
                },
                "from": relayed_did,
                "to": [gstate["last_did"]],
            }
            await quickstart.send_http_message(DMP, relayed_did, message, target=gstate["last_did"])
        else:
            logger.warning("Action button pressed but no one has messaged us")
    async def message_all_handle(request):
        await message_last_did("\"Power\" button was pressed")
        return web.json_response({})
    async def default_handle(request):
        await message_last_did("Resetting screen to inky logo")
        subprocess.run(["env", "-i", "sudo", "python3", "/home/pi/Pimoroni/inky/examples/logo.py"])
        return web.json_response({})
    app = web.Application()
    app.add_routes([web.get('/message_all', message_all_handle)])
    app.add_routes([web.get('/default_tag', default_handle)])
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", 9000)
    await site.start()

    while True:
        await asyncio.sleep(5)
        #if mediator_websocket_proc and mediator_websocket_proc.done():
        if mediator_websocket_proc.done():
            logger.exception(mediator_websocket_proc.exception())
            try:
                logger.error("Websocket died, re-establishing connection!")
            except Exception:
                pass
            mediator_websocket_proc = await activate_websocket()

    #await quickstart.fetch_relayed_messages(DMP, did, RELAY_DID, print_msg)

loop = asyncio.get_event_loop()
tasks = [loop.create_task(main())]
loop.run_until_complete(asyncio.wait(tasks))
loop.close()
