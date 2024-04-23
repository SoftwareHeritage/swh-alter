# Copyright (C) 2024 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from collections.abc import Mapping
import itertools
import operator
from typing import Callable, Dict, Iterable, Optional, TypeVar, cast

from swh.model.swhids import ExtendedObjectType, ExtendedSWHID

T = TypeVar("T")
C = TypeVar("C", covariant=True)


def iter_swhids_grouped_by_type(
    swhids: Iterable[ExtendedSWHID],
    *,
    handlers: Mapping[ExtendedObjectType, Callable[[C], Iterable[T]]],
    collector: Optional[Callable[[Iterable[ExtendedSWHID]], C]] = None,
) -> Iterable[T]:
    """Work on a iterable of SWHIDs grouped by their type, running a different
    handler for each type.

    The object types will be in the same order as in ``handlers``.

    Arguments:
        swhids: an iterable over some SWHIDs
        handlers: a dictionary mapping each object type to an handler, taking
            a collection of swhids and returning an iterable
        collector: an optional function to transform the iterable over the
            grouped SWHIDs into a more convenient collection.

    Returns: an iterable over the handlers’ results
    """

    collector_func: Callable[[Iterable[ExtendedSWHID]], C] = (
        collector if collector is not None else lambda x: cast(C, x)
    )

    # groupby() splits consecutive groups, so we need to order the list first
    ordering: Dict[ExtendedObjectType, int] = {
        object_type: order for order, object_type in enumerate(handlers.keys())
    }

    def key(swhid: ExtendedSWHID) -> int:
        return ordering[swhid.object_type]

    sorted_swhids = sorted(swhids, key=key)

    # Now we can use itertools.groupby()
    for object_type, grouped_swhids in itertools.groupby(
        sorted_swhids, key=operator.attrgetter("object_type")
    ):
        yield from handlers[object_type](collector_func(grouped_swhids))
