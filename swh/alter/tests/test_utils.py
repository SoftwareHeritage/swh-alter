# Copyright (C) 2024 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from functools import partial
import itertools
import operator
import random
from typing import Iterable, List

import pytest

from swh.model.swhids import ExtendedObjectType, ExtendedSWHID

from ..utils import iter_swhids_grouped_by_type


@pytest.fixture
def randomized_swhid_list() -> List[ExtendedSWHID]:
    swhids = [
        # Content
        "swh:1:cnt:d81cc0710eb6cf9efd5b920a8453e1e07157b6cd",
        "swh:1:cnt:c932c7649c6dfa4b82327d121215116909eb3bea",
        # SkippedContent
        "swh:1:cnt:33e45d56f88993aae6a0198013efa80716fd8920",
        # Directory
        "swh:1:dir:5256e856a0a0898966d6ba14feb4388b8b82d302",
        "swh:1:dir:4b825dc642cb6eb9a060e54bf8d69288fbee4904",
        "swh:1:dir:afa0105cfcaa14fdbacee344e96659170bb1bda5",
        # Revision
        "swh:1:rev:01a7114f36fddd5ef2511b2cadda237a68adbb12",
        "swh:1:rev:a646dd94c912829659b22a1e7e143d2fa5ebde1b",
        # Release
        "swh:1:rel:f7f222093a18ec60d781070abec4a630c850b837",
        "swh:1:rel:db81a26783a3f4a9db07b4759ffc37621f159bb2",
        # Snapshot
        "swh:1:snp:9b922e6d8d5b803c1582aabe5525b7b91150788e",
        "swh:1:snp:db99fda25b43dc5cd90625ee4b0744751799c917",
        # Origin
        "swh:1:ori:33abd4b4c5db79c7387673f71302750fd73e0645",
        "swh:1:ori:9147ab9c9287940d4fdbe95d8780664d7ad2dfc0",
    ]
    random.shuffle(swhids)
    return [ExtendedSWHID.from_string(swhid) for swhid in swhids]


def test_iter_swhids_grouped_by_type(
    randomized_swhid_list: List[ExtendedSWHID],
) -> None:
    def handle_swhids(
        object_type: ExtendedObjectType, swhids: List[ExtendedSWHID]
    ) -> Iterable[ExtendedSWHID]:
        assert all(swhid.object_type == object_type for swhid in swhids)
        yield from swhids

    handlers = {
        object_type: partial(handle_swhids, object_type)
        for object_type in [
            ExtendedObjectType.CONTENT,
            ExtendedObjectType.DIRECTORY,
            ExtendedObjectType.REVISION,
            ExtendedObjectType.RELEASE,
            ExtendedObjectType.SNAPSHOT,
            ExtendedObjectType.ORIGIN,
        ]
    }
    grouped_results = list(
        set(str(swhid) for swhid in swhids)
        for _, swhids in itertools.groupby(
            iter_swhids_grouped_by_type(
                randomized_swhid_list, handlers=handlers, collector=list
            ),
            key=operator.attrgetter("object_type"),
        )
    )
    assert grouped_results == [
        # Content & SkippedContent
        {
            "swh:1:cnt:d81cc0710eb6cf9efd5b920a8453e1e07157b6cd",
            "swh:1:cnt:c932c7649c6dfa4b82327d121215116909eb3bea",
            "swh:1:cnt:33e45d56f88993aae6a0198013efa80716fd8920",
        },
        # Directory
        {
            "swh:1:dir:5256e856a0a0898966d6ba14feb4388b8b82d302",
            "swh:1:dir:4b825dc642cb6eb9a060e54bf8d69288fbee4904",
            "swh:1:dir:afa0105cfcaa14fdbacee344e96659170bb1bda5",
        },
        # Revision
        {
            "swh:1:rev:01a7114f36fddd5ef2511b2cadda237a68adbb12",
            "swh:1:rev:a646dd94c912829659b22a1e7e143d2fa5ebde1b",
        },
        # Release
        {
            "swh:1:rel:f7f222093a18ec60d781070abec4a630c850b837",
            "swh:1:rel:db81a26783a3f4a9db07b4759ffc37621f159bb2",
        },
        # Snapshot
        {
            "swh:1:snp:9b922e6d8d5b803c1582aabe5525b7b91150788e",
            "swh:1:snp:db99fda25b43dc5cd90625ee4b0744751799c917",
        },
        # Origin
        {
            "swh:1:ori:33abd4b4c5db79c7387673f71302750fd73e0645",
            "swh:1:ori:9147ab9c9287940d4fdbe95d8780664d7ad2dfc0",
        },
    ]


def test_iter_swhids_grouped_by_type_no_collector(
    randomized_swhid_list: List[ExtendedSWHID],
) -> None:
    def handle_swhids(
        object_type: ExtendedObjectType, swhids: Iterable[ExtendedSWHID]
    ) -> Iterable[ExtendedSWHID]:
        yield from swhids

    handlers = {
        object_type: partial(handle_swhids, object_type)
        for object_type in [
            ExtendedObjectType.CONTENT,
            ExtendedObjectType.DIRECTORY,
            ExtendedObjectType.REVISION,
            ExtendedObjectType.RELEASE,
            ExtendedObjectType.SNAPSHOT,
            ExtendedObjectType.ORIGIN,
        ]
    }
    grouped_results = list(
        set(str(swhid) for swhid in swhids)
        for _, swhids in itertools.groupby(
            iter_swhids_grouped_by_type(randomized_swhid_list, handlers=handlers),
            key=operator.attrgetter("object_type"),
        )
    )
    assert grouped_results == [
        # Content & SkippedContent
        {
            "swh:1:cnt:d81cc0710eb6cf9efd5b920a8453e1e07157b6cd",
            "swh:1:cnt:c932c7649c6dfa4b82327d121215116909eb3bea",
            "swh:1:cnt:33e45d56f88993aae6a0198013efa80716fd8920",
        },
        # Directory
        {
            "swh:1:dir:5256e856a0a0898966d6ba14feb4388b8b82d302",
            "swh:1:dir:4b825dc642cb6eb9a060e54bf8d69288fbee4904",
            "swh:1:dir:afa0105cfcaa14fdbacee344e96659170bb1bda5",
        },
        # Revision
        {
            "swh:1:rev:01a7114f36fddd5ef2511b2cadda237a68adbb12",
            "swh:1:rev:a646dd94c912829659b22a1e7e143d2fa5ebde1b",
        },
        # Release
        {
            "swh:1:rel:f7f222093a18ec60d781070abec4a630c850b837",
            "swh:1:rel:db81a26783a3f4a9db07b4759ffc37621f159bb2",
        },
        # Snapshot
        {
            "swh:1:snp:9b922e6d8d5b803c1582aabe5525b7b91150788e",
            "swh:1:snp:db99fda25b43dc5cd90625ee4b0744751799c917",
        },
        # Origin
        {
            "swh:1:ori:33abd4b4c5db79c7387673f71302750fd73e0645",
            "swh:1:ori:9147ab9c9287940d4fdbe95d8780664d7ad2dfc0",
        },
    ]
