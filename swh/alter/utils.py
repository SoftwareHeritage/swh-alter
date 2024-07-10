# Copyright (C) 2024 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from collections.abc import Mapping
from functools import partial
import hashlib
import itertools
import operator
from typing import (
    Callable,
    Collection,
    Dict,
    Iterable,
    List,
    Optional,
    Set,
    TypeVar,
    cast,
)

from swh.model.swhids import ExtendedObjectType, ExtendedSWHID
from swh.storage.interface import StorageInterface

T = TypeVar("T")
C = TypeVar("C", covariant=True)


def iter_swhids_grouped_by_type(
    swhids: Iterable[ExtendedSWHID],
    *,
    handlers: Mapping[ExtendedObjectType, Callable[[C], Iterable[T]]],
    chunker: Optional[Callable[[Collection[ExtendedSWHID]], Iterable[C]]] = None,
) -> Iterable[T]:
    """Work on a iterable of SWHIDs grouped by their type, running a different
    handler for each type.

    The object types will be in the same order as in ``handlers``.

    Arguments:
        swhids: an iterable over some SWHIDs
        handlers: a dictionary mapping each object type to an handler, taking
            a collection of swhids and returning an iterable
        chunker: an optional function to split the SWHIDs of same
            object type into multiple “chunks”. It can also transform
            the iterable into a more convenient collection.

    Returns: an iterable over the handlers’ results
    """

    def _default_chunker(it: Collection[ExtendedSWHID]) -> Iterable[C]:
        yield cast(C, it)

    chunker = chunker or _default_chunker

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
        for chunk in chunker(list(grouped_swhids)):
            yield from handlers[object_type](chunk)


def _filter_missing_contents(
    storage: StorageInterface, requested_object_ids: Set[bytes]
) -> Iterable[ExtendedSWHID]:
    missing_object_ids = set(
        storage.content_missing_per_sha1_git(list(requested_object_ids))
    )
    yield from (
        ExtendedSWHID(object_type=ExtendedObjectType.CONTENT, object_id=object_id)
        for object_id in requested_object_ids - missing_object_ids
    )


def _filter_missing_directories(
    storage: StorageInterface, requested_object_ids: Set[bytes]
) -> Iterable[ExtendedSWHID]:
    missing_object_ids = set(storage.directory_missing(list(requested_object_ids)))
    yield from (
        ExtendedSWHID(object_type=ExtendedObjectType.DIRECTORY, object_id=object_id)
        for object_id in requested_object_ids - missing_object_ids
    )


def _filter_missing_revisions(
    storage: StorageInterface, requested_object_ids: Set[bytes]
) -> Iterable[ExtendedSWHID]:
    missing_object_ids = set(storage.revision_missing(list(requested_object_ids)))
    yield from (
        ExtendedSWHID(object_type=ExtendedObjectType.REVISION, object_id=object_id)
        for object_id in requested_object_ids - missing_object_ids
    )


def _filter_missing_releases(
    storage: StorageInterface, requested_object_ids: Set[bytes]
) -> Iterable[ExtendedSWHID]:
    missing_object_ids = set(storage.release_missing(list(requested_object_ids)))
    yield from (
        ExtendedSWHID(object_type=ExtendedObjectType.RELEASE, object_id=object_id)
        for object_id in requested_object_ids - missing_object_ids
    )


def _filter_missing_snapshots(
    storage: StorageInterface, requested_object_ids: Set[bytes]
) -> Iterable[ExtendedSWHID]:
    missing_object_ids = set(storage.snapshot_missing(list(requested_object_ids)))
    yield from (
        ExtendedSWHID(object_type=ExtendedObjectType.SNAPSHOT, object_id=object_id)
        for object_id in requested_object_ids - missing_object_ids
    )


def _filter_missing_origins(
    storage: StorageInterface, requested_object_ids: Set[bytes]
) -> Iterable[ExtendedSWHID]:
    # XXX: We should add a better method in swh.storage
    yield from (
        ExtendedSWHID(
            object_type=ExtendedObjectType.ORIGIN,
            object_id=hashlib.sha1(d["url"].encode("utf-8")).digest(),
        )
        for d in storage.origin_get_by_sha1(list(requested_object_ids))
        if d is not None
    )


def filter_objects_missing_from_storage(
    storage: StorageInterface, swhids: Iterable[ExtendedSWHID]
) -> List[ExtendedSWHID]:
    def chunker(swhids: Iterable[ExtendedSWHID]) -> Iterable[Set[bytes]]:
        yield {swhid.object_id for swhid in swhids}

    handlers: Dict[
        ExtendedObjectType, Callable[[set[bytes]], Iterable[ExtendedSWHID]]
    ] = {
        ExtendedObjectType.CONTENT: partial(_filter_missing_contents, storage),
        ExtendedObjectType.DIRECTORY: partial(_filter_missing_directories, storage),
        ExtendedObjectType.REVISION: partial(_filter_missing_revisions, storage),
        ExtendedObjectType.RELEASE: partial(_filter_missing_releases, storage),
        ExtendedObjectType.SNAPSHOT: partial(_filter_missing_snapshots, storage),
        ExtendedObjectType.ORIGIN: partial(_filter_missing_origins, storage),
    }
    return list(iter_swhids_grouped_by_type(swhids, handlers=handlers, chunker=chunker))


def get_filtered_objects(
    storage: StorageInterface,
    get_objects: Callable[[int], Collection[ExtendedSWHID]],
    max_results: int,
) -> Collection[ExtendedSWHID]:
    """Call `get_objects(limit)` filtering out results with
    `filter_objects_missing_from_storage`.

    If some objects were filtered, call the function again with an increasing
    limit until `max_results` objects are returned.
    """
    limit = max_results
    while True:
        results = get_objects(limit)
        filtered_results = filter_objects_missing_from_storage(storage, results)
        filtered_count = len(results) - len(filtered_results)

        if len(filtered_results) >= max_results:
            return filtered_results[:max_results]
        elif len(results) >= limit and filtered_count > 0:
            # Some results have been filtered out and the initial call has
            # reached the object limit, which means that we might have missed
            # some extra entries. We need to increase the limit, at least to
            # `limit + filtered_count`, doubling that will reach an endpoint
            # faster
            limit = 2 * (limit + filtered_count)
        else:
            return filtered_results
