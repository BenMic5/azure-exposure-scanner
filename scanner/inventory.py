"""Load an Azure inventory (ARM list-API responses) and look resources up by id.

The fixture has one key per ARM list API. In a live integration each key is
filled by the matching read-only call (see README, "Approach"):

    virtualMachines        GET .../providers/Microsoft.Compute/virtualMachines
    networkInterfaces      GET .../providers/Microsoft.Network/networkInterfaces
    publicIPAddresses      GET .../providers/Microsoft.Network/publicIPAddresses
    virtualNetworks        GET .../providers/Microsoft.Network/virtualNetworks  (subnets embedded)
    networkSecurityGroups  GET .../providers/Microsoft.Network/networkSecurityGroups
"""
from __future__ import annotations

import json
from typing import Any, Optional

Resource = dict[str, Any]

_LIST_KEYS = ("virtualMachines", "networkInterfaces", "publicIPAddresses", "virtualNetworks", "networkSecurityGroups")


class Inventory:
    def __init__(self, data: dict[str, Any]):
        self.vms: list[Resource] = data.get("virtualMachines") or []
        self._by_id: dict[str, Resource] = {}
        for key in _LIST_KEYS:
            for resource in data.get(key) or []:
                self._index(resource)
        # Subnets are only returned embedded in their virtual network.
        for vnet in data.get("virtualNetworks") or []:
            for subnet in (vnet.get("properties") or {}).get("subnets") or []:
                self._index(subnet)

    @classmethod
    def load(cls, path: str) -> "Inventory":
        with open(path, encoding="utf-8") as f:
            return cls(json.load(f))

    def _index(self, resource: Resource) -> None:
        self._by_id[resource["id"].lower()] = resource  # ARM ids are case-insensitive

    def get(self, resource_id: str) -> Optional[Resource]:
        return self._by_id.get(resource_id.lower())


def ref_id(obj: Optional[Resource], key: str) -> Optional[str]:
    """Return obj.properties[key].id: how ARM references another resource."""
    ref = ((obj or {}).get("properties") or {}).get(key)
    return ref.get("id") if ref else None


def name_of(resource_id: str) -> str:
    return resource_id.rstrip("/").split("/")[-1]


def subscription_of(resource_id: str) -> str:
    parts = resource_id.split("/")
    return parts[2] if len(parts) > 2 and parts[1].lower() == "subscriptions" else "unknown"


def read_permission(resource_id: str) -> str:
    """The RBAC action needed to read a resource, derived from its id.

    .../providers/Microsoft.Network/virtualNetworks/v/subnets/s
      -> Microsoft.Network/virtualNetworks/subnets/read
    """
    parts = resource_id.strip("/").split("/")
    lowered = [p.lower() for p in parts]
    if "providers" not in lowered:
        return "*/read"
    i = lowered.index("providers")
    namespace, rest = parts[i + 1], parts[i + 2:]
    types = rest[0::2]  # type/name/type/name...
    return "/".join([namespace, *types, "read"])
