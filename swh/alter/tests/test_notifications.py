# Copyright (C) 2024 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information


from ..notifications import RemovalNotification


def test_removal_notification_serialization_roundtrip(example_removal_notification):
    d = example_removal_notification.to_dict()
    assert RemovalNotification.from_dict(d) == example_removal_notification
