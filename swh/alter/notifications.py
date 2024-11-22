# Copyright (C) 2024 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from typing import Any, Dict, List, Optional, Self

import attr

from swh.model.model import Origin
from swh.model.swhids import ExtendedSWHID


@attr.s
class RemovalNotification:
    removal_identifier = attr.ib(type=str)
    reason = attr.ib(type=str)
    requested = attr.ib(type=List[Origin | ExtendedSWHID])
    removed_objects = attr.ib(type=List[ExtendedSWHID])

    def anonymize(self) -> Optional[Self]:
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "removal_identifier": self.removal_identifier,
            "reason": self.reason,
            "requested": [
                (
                    str(swhid_or_origin)
                    if isinstance(swhid_or_origin, ExtendedSWHID)
                    else swhid_or_origin.url
                )
                for swhid_or_origin in self.requested
            ],
            "removed_objects": [str(swhid) for swhid in self.removed_objects],
        }

    @classmethod
    def from_dict(cls: type[Self], d: Dict[str, Any]) -> Self:
        return cls(
            **{
                **d,
                "requested": [
                    (
                        ExtendedSWHID.from_string(s)
                        if s.startswith("swh:1:")
                        else Origin(url=s)
                    )
                    for s in d["requested"]
                ],
                "removed_objects": [
                    ExtendedSWHID.from_string(s) for s in d["removed_objects"]
                ],
            }
        )

    def unique_key(self) -> bytes:
        return self.removal_identifier.encode("utf-8")
