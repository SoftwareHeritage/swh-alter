# Copyright (C) 2023 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import datetime
import itertools
import os
import shutil

import pytest
import yaml

from swh.model.model import Content
from swh.model.swhids import ExtendedSWHID

from ..recovery_bundle import (
    AgeSecretKey,
    Manifest,
    RecoveryBundle,
    RecoveryBundleCreator,
    SecretRecoveryError,
    SecretSharing,
    age_decrypt,
    age_encrypt,
    convert_bits,
    generate_age_keypair,
    list_yubikey_identities,
    recover_object_decryption_key_from_encrypted_shares,
)


@pytest.fixture
def manifest_dict():
    return {
        "version": 1,
        "removal_identifier": "TDN-2023-06-18-01",
        "created": datetime.datetime(
            2023, 6, 18, 13, 12, 42, tzinfo=datetime.timezone.utc
        ),
        "swhids": [
            "swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165",
            "swh:1:snp:0000000000000000000000000000000000000022",
            "swh:1:rel:0000000000000000000000000000000000000021",
            "swh:1:rev:0000000000000000000000000000000000000018",
            "swh:1:rev:0000000000000000000000000000000000000013",
            "swh:1:dir:0000000000000000000000000000000000000017",
            "swh:1:cnt:0000000000000000000000000000000000000016",
            "swh:1:cnt:0000000000000000000000000000000000000012",
            "swh:1:cnt:0000000000000000000000000000000000000015",
            "swh:1:cnt:0000000000000000000000000000000000000014",
            "swh:1:cnt:0000000000000000000000000000000000000011",
        ],
        "decryption_key_shares": {
            "YubiKey serial 4245067 slot 1": "-----BEGIN AGE ENCRYPTED FILE-----\n"
            "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHBpdi1wMjU2IHcvb0k0USBBb3FMYjRM\n"
            "V3dlcm9YazZkTU9UZld4eEVhYUlBZHRBQ05CQndOUFZJMmV1NApmNTY1MUJFdks1\n"
            "aE9TZzQ3NFJGN0cvQlFIMDZNSTkxUEpOblJteUkyK2FVCi0+IDxYTSFKLWdyZWFz\n"
            "ZSBCfWErZHkKNEMrbTdqekhTZTQ4c3pXRGZjK3N0UTh2Qi9ISU1XdFF6a0RvdmRl\n"
            "NAotLS0gYk9Ob2dkUTJRZE9nT3BTK29JWU5pRkZIVC9pUzJQaHRZc05sMjd6S1Rr\n"
            "OAoRXkzBiNX98H+353sOjGxJvCdYmtUdn7ozR35g+VSB6zxS972s2drkuKxQ0kIN\n"
            "MIjaytf/RJ0J3N/x8CtsEvXSoGjnuIT0GuEUbCqG0Qg0/YrrDzEGcD34l6JnD187\n"
            "5nVFnUimLXK6S2HeEDTJUZuLWfmglqaZaZjPnEKxqu8TfrJDBgg7miJLC+rGXhn9\n"
            "4ArtFIaOQgotCHZ8Y0lpmqGJIVTKWgdgpW+JjzyG\n"
            "-----END AGE ENCRYPTED FILE-----\n",
            "YubiKey serial 5229836 slot 1": "-----BEGIN AGE ENCRYPTED FILE-----\n"
            "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHBpdi1wMjU2IHcvb0k0USBBaTZhaUo3\n"
            "WnMzMmlTUlp5QmNhTkI1bHlmcHNyY0FPQ0RnK1BQdHQxS0EvbAppVnExb3BZcFRW\n"
            "ZkZ1ZFZrQWlyaU9HTkRKREYvU2tSaldkSHpWdVd1aGFVCi0+IDUrPVssLWdyZWFz\n"
            "ZQpzcm1WSkNqOWVrOU5GUXRMSmpFVVR4aEhrM0UKLS0tIFl2QkN6d1QzdWN6U0dB\n"
            "VHVzYk1SdDBLNlhNanJGc2x4L2hMZTZrSUxTSGMKLOKIpGZtKtUeOsSrcoIvKiBu\n"
            "DAoLXMGY+302lQRJsdJ3I7N+eFhRATsOM7vO8eupXbee87kIkGB7GaqGR5X48GR1\n"
            "oNrMsY5PcjZICxLjWYX9cMVMAXcmBjV9ZCWwqzmw86rY0k74mRwhE0dYd95P90+5\n"
            "NniuNgxQYKkM5QoKVHn36ISJGUgcvp5/JCM69X7kM8UvjLarFeYdHfqqAZUImNla\n"
            "lEdIqdOmnUs=\n"
            "-----END AGE ENCRYPTED FILE-----\n",
        },
        "reason": "copyright issue",
        "expire": datetime.datetime(
            2024, 6, 18, 13, 12, 42, tzinfo=datetime.timezone.utc
        ),
    }


def test_manifest_load_success(manifest_dict):
    assert Manifest.load(yaml.dump(manifest_dict))


def test_manifest_load_success_with_no_optionals(manifest_dict):
    del manifest_dict["reason"]
    del manifest_dict["expire"]
    assert Manifest.load(yaml.dump(manifest_dict))


@pytest.mark.parametrize(
    "invalid_manifest_dict",
    [
        pytest.param({"version": 2}, id="invalid_version"),
        pytest.param({"expire": "2024-06-18T13:12:42Z"}, id="str_instead_of_datetime"),
        pytest.param({"swhids": []}, id="empty_swhids"),
        pytest.param({"decryption_key_shares": {}}, id="empty_shares"),
        pytest.param({"invalid": "field"}, id="invalid_field"),
    ],
)
def test_manifest_load_failure(manifest_dict, invalid_manifest_dict):
    manifest_dict.update(invalid_manifest_dict)
    with pytest.raises((ValueError, TypeError)):
        assert Manifest.load(yaml.dump(manifest_dict))


EXPECTED_MANIFEST_DUMP = """\
version: 1
removal_identifier: TDN-2023-06-18-01
created: 2023-06-18T13:12:42+00:00
swhids:
- swh:1:ori:8f50d3f60eae370ddbf85c86219c55108a350165
- swh:1:snp:0000000000000000000000000000000000000022
- swh:1:rel:0000000000000000000000000000000000000021
- swh:1:rev:0000000000000000000000000000000000000018
- swh:1:rev:0000000000000000000000000000000000000013
- swh:1:dir:0000000000000000000000000000000000000017
- swh:1:cnt:0000000000000000000000000000000000000016
- swh:1:cnt:0000000000000000000000000000000000000012
- swh:1:cnt:0000000000000000000000000000000000000015
- swh:1:cnt:0000000000000000000000000000000000000014
- swh:1:cnt:0000000000000000000000000000000000000011
decryption_key_shares:
  YubiKey serial 4245067 slot 1: |
    -----BEGIN AGE ENCRYPTED FILE-----
    YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHBpdi1wMjU2IHcvb0k0USBBb3FMYjRM
    V3dlcm9YazZkTU9UZld4eEVhYUlBZHRBQ05CQndOUFZJMmV1NApmNTY1MUJFdks1
    aE9TZzQ3NFJGN0cvQlFIMDZNSTkxUEpOblJteUkyK2FVCi0+IDxYTSFKLWdyZWFz
    ZSBCfWErZHkKNEMrbTdqekhTZTQ4c3pXRGZjK3N0UTh2Qi9ISU1XdFF6a0RvdmRl
    NAotLS0gYk9Ob2dkUTJRZE9nT3BTK29JWU5pRkZIVC9pUzJQaHRZc05sMjd6S1Rr
    OAoRXkzBiNX98H+353sOjGxJvCdYmtUdn7ozR35g+VSB6zxS972s2drkuKxQ0kIN
    MIjaytf/RJ0J3N/x8CtsEvXSoGjnuIT0GuEUbCqG0Qg0/YrrDzEGcD34l6JnD187
    5nVFnUimLXK6S2HeEDTJUZuLWfmglqaZaZjPnEKxqu8TfrJDBgg7miJLC+rGXhn9
    4ArtFIaOQgotCHZ8Y0lpmqGJIVTKWgdgpW+JjzyG
    -----END AGE ENCRYPTED FILE-----
  YubiKey serial 5229836 slot 1: |
    -----BEGIN AGE ENCRYPTED FILE-----
    YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHBpdi1wMjU2IHcvb0k0USBBaTZhaUo3
    WnMzMmlTUlp5QmNhTkI1bHlmcHNyY0FPQ0RnK1BQdHQxS0EvbAppVnExb3BZcFRW
    ZkZ1ZFZrQWlyaU9HTkRKREYvU2tSaldkSHpWdVd1aGFVCi0+IDUrPVssLWdyZWFz
    ZQpzcm1WSkNqOWVrOU5GUXRMSmpFVVR4aEhrM0UKLS0tIFl2QkN6d1QzdWN6U0dB
    VHVzYk1SdDBLNlhNanJGc2x4L2hMZTZrSUxTSGMKLOKIpGZtKtUeOsSrcoIvKiBu
    DAoLXMGY+302lQRJsdJ3I7N+eFhRATsOM7vO8eupXbee87kIkGB7GaqGR5X48GR1
    oNrMsY5PcjZICxLjWYX9cMVMAXcmBjV9ZCWwqzmw86rY0k74mRwhE0dYd95P90+5
    NniuNgxQYKkM5QoKVHn36ISJGUgcvp5/JCM69X7kM8UvjLarFeYdHfqqAZUImNla
    lEdIqdOmnUs=
    -----END AGE ENCRYPTED FILE-----
reason: copyright issue
expire: 2024-06-18T13:12:42+00:00
"""


def test_manifest_dump(manifest_dict):
    manifest = Manifest(**manifest_dict)
    assert manifest.dump() == EXPECTED_MANIFEST_DUMP


def test_manifest_dump_no_optionals(manifest_dict):
    del manifest_dict["reason"]
    del manifest_dict["expire"]
    manifest = Manifest(**manifest_dict)
    dump = manifest.dump()
    assert "reason:" not in dump
    assert "expire:" not in dump


def test_manifest_load():
    manifest = Manifest.load(EXPECTED_MANIFEST_DUMP)
    assert isinstance(manifest, Manifest)


def test_manifest_dump_load_roundtrip(manifest_dict):
    manifest = Manifest(**manifest_dict)
    assert manifest == Manifest.load(manifest.dump())


def test_generate_age_keypair():
    public_key, secret_key = generate_age_keypair()
    assert public_key.startswith("age")
    assert len(public_key) == 62
    assert secret_key.startswith("AGE-SECRET-KEY-")
    assert len(secret_key) == 74


OBJECT_PUBLIC_KEY = "age1a4uwpku4xzlnkh78ma3urlulhhhz0xlsv6crthjvhrjysvskp9nsz77qts"
OBJECT_SECRET_KEY = (
    "AGE-SECRET-KEY-1EZMJLS2MMEN4D6CCR6TQ66RD4MPT32ZN8EAU44PS3EDNUAKQWE0SM92NN4"
)


def test_age_encrypt_decrypt_roundtrip():
    public_key = OBJECT_PUBLIC_KEY
    secret_key = OBJECT_SECRET_KEY
    cleartext = b"All Your Source Code Base Must Belong To Us!"
    ciphertext = age_encrypt(public_key, cleartext)
    assert age_decrypt(secret_key, ciphertext) == cleartext


def test_convert_5bits_to_8bits():
    assert [104, 101, 108, 108, 111] == convert_bits(
        [13, 1, 18, 22, 24, 27, 3, 15], 5, 8
    )


def test_convert_8bits_to_5bits():
    assert convert_bits([104, 101, 108, 108, 111], 8, 5) == [
        13,
        1,
        18,
        22,
        24,
        27,
        3,
        15,
    ]


EXAMPLE_SECRET_SHARING_YAML = """\
secret_sharing:
  minimum_required_groups: 2
  groups:
    legal:
      minimum_required_shares: 1
      recipient_keys:
        "YubiKey serial 4245067 slot 1": |-
          age1yubikey1q2e37f74zzazz75mtggzql3at66pegemfnul0dtd7axctahljkvsqezscaq
        "YubiKey serial 2284622 slot 3": |-
          age1yubikey1q0ucnwg558zcwrc752evk3620q2t4mkwz6a0lq9u3clsfmealsmlz330kz2
    sysadmins:
      minimum_required_shares: 1
      recipient_keys:
        "YubiKey serial 3862152 slot 1": |-
          age1yubikey1q04k5fs8cz6kypt7vjetl2gc2qtpz9lyzpxrvv2agzt6h8n3awmzk9sgd8v
        "YubiKey serial 6927448 slot 1": |-
          age1yubikey1qt2p377vq6qg58l8gaframp9yggvsysddraa72aehma5mw623r8rqk0mlgu
"""


@pytest.fixture
def example_secret_sharing():
    return SecretSharing.from_dict(
        yaml.safe_load(EXAMPLE_SECRET_SHARING_YAML)["secret_sharing"]
    )


@pytest.mark.skipif(
    not shutil.which("age-plugin-yubikey"),
    reason="missing `age-plugin-yubikey` executable",
)
def test_generate_encrypted_shares(example_secret_sharing):
    encrypted_shares = example_secret_sharing.generate_encrypted_shares(
        "example", OBJECT_SECRET_KEY
    )
    assert len(encrypted_shares) == 4
    assert encrypted_shares.keys() == {
        "YubiKey serial 4245067 slot 1",
        "YubiKey serial 2284622 slot 3",
        "YubiKey serial 3862152 slot 1",
        "YubiKey serial 6927448 slot 1",
    }
    assert all(
        s.startswith("-----BEGIN AGE ENCRYPTED FILE-----")
        for s in encrypted_shares.values()
    )


ALI_PUBLIC_KEY = "age123hpq9m25xsmx7caqvyv8k3fxaqastc3evyq9q7myur7l9ukj4dsnp7a5v"
ALI_SECRET_KEY = (
    "AGE-SECRET-KEY-1VREXCYE5WNMUD0WSCF7F6CH3FGQ9P6PGD25QHY7QX8PGDN87P37QQD3L2G"
)
BOB_PUBLIC_KEY = "age1mrhte5tlpzpz57gg85nzcefqc5pm5usmakqpuurxux7ry2rmhdgs7r9u68"
BOB_SECRET_KEY = (
    "AGE-SECRET-KEY-1UPJU3AF4M0NPLSLGVDWJU38F3MDE3JJM48E8NST8V3YKU077HEVSQVPZC2"
)
CAMILLE_PUBLIC_KEY = "age1ahuqxgjmvfm65shmwqa7xa703vvcla528swga3zempnxslj3pczqtx6wr8"
CAMILLE_SECRET_KEY = (
    "AGE-SECRET-KEY-1NPLST9VXL6E9DEHCVVPUTGH60ZRJFLPZ5HDM93MJW993CGFQ49PQU90RVL"
)
DLIQUE_PUBLIC_KEY = "age1qwu50kncctmpky7gg5s0v4mt4fzc4wjwj6mfjzhtk3wn6pspkyksmsmhze"
DLIQUE_SECRET_KEY = (
    "AGE-SECRET-KEY-1NPT3PFA7N03DFQY9GN764T4TJCZSLP36YV4S98FLYN0YGX2539GSSFUT4F"
)
ESSUN_PUBLIC_KEY = "age1uakt638m65nt56q9qjecwp60gnv6qwqkez43re06awqzf8hqh3pqnsppaw"
ESSUN_SECRET_KEY = (
    "AGE-SECRET-KEY-10ZZWX7FNCUJR7HRACEGUCVA4V0PYGLQ7NJDYPRH96YNC3AJLM37QQNWX3K"
)

TWO_GROUPS_REQUIRED_WITH_ONE_MINIMUM_SHARE_EACH_SECRET_SHARING_YAML = f"""\
secret_sharing:
  minimum_required_groups: 2
  groups:
    legal:
      minimum_required_shares: 1
      recipient_keys:
        "Ali": {ALI_PUBLIC_KEY}
        "Bob": {BOB_PUBLIC_KEY}
    sysadmins:
      minimum_required_shares: 1
      recipient_keys:
        "Camille": {CAMILLE_PUBLIC_KEY}
        "Dlique": {DLIQUE_PUBLIC_KEY}
"""


@pytest.fixture
def secret_sharing_2_groups_required_with_1_minimum_each():
    return SecretSharing.from_dict(
        yaml.safe_load(
            TWO_GROUPS_REQUIRED_WITH_ONE_MINIMUM_SHARE_EACH_SECRET_SHARING_YAML
        )["secret_sharing"]
    )


def available_secret_keys_for_2_groups_required_with_1_minimum_each():
    yield ("Dlique", DLIQUE_SECRET_KEY)
    yield ("Ali", ALI_SECRET_KEY)


TWO_GROUPS_REQUIRED_OF_THREE_WITH_ONE_AND_TWO_MINIMUM_IN_EACH_SECRET_SHARING_YAML = f"""\
secret_sharing:
  minimum_required_groups: 2
  groups:
    legal:
      minimum_required_shares: 1
      recipient_keys:
        "Ali": {ALI_PUBLIC_KEY}
    dpo:
      minimum_required_shares: 1
      recipient_keys:
        "Bob": {BOB_PUBLIC_KEY}
    sysadmins:
      minimum_required_shares: 2
      recipient_keys:
        "Camille": {CAMILLE_PUBLIC_KEY}
        "Dlique": {DLIQUE_PUBLIC_KEY}
        "Essun": {ESSUN_PUBLIC_KEY}
"""


@pytest.fixture
def secret_sharing_2_groups_required_of_3_with_1_and_two_minimum_in_each():
    return SecretSharing.from_dict(
        yaml.safe_load(
            TWO_GROUPS_REQUIRED_OF_THREE_WITH_ONE_AND_TWO_MINIMUM_IN_EACH_SECRET_SHARING_YAML
        )["secret_sharing"]
    )


def available_secret_keys_for_2_groups_required_of_3_only_ones():
    yield ("Ali", ALI_SECRET_KEY)
    yield ("Bob", BOB_SECRET_KEY)


def available_secret_keys_for_2_groups_required_of_3_one_and_two():
    yield ("Essun", ESSUN_SECRET_KEY)
    yield ("Bob", BOB_SECRET_KEY)
    yield ("Camille", CAMILLE_SECRET_KEY)


@pytest.mark.parametrize(
    "secret_sharing, available_secret_keys",
    [
        (
            "secret_sharing_2_groups_required_with_1_minimum_each",
            available_secret_keys_for_2_groups_required_with_1_minimum_each,
        ),
        (
            "secret_sharing_2_groups_required_of_3_with_1_and_two_minimum_in_each",
            available_secret_keys_for_2_groups_required_of_3_only_ones,
        ),
        (
            "secret_sharing_2_groups_required_of_3_with_1_and_two_minimum_in_each",
            available_secret_keys_for_2_groups_required_of_3_one_and_two,
        ),
    ],
)
def test_object_decryption_key_recovery_roundtrip(
    request, secret_sharing, available_secret_keys
):
    secret_sharing = request.getfixturevalue(secret_sharing)

    encrypted_shares = secret_sharing.generate_encrypted_shares(
        secret_sharing, OBJECT_SECRET_KEY
    )
    recovered_key = recover_object_decryption_key_from_encrypted_shares(
        encrypted_shares, available_secret_keys
    )
    assert recovered_key == OBJECT_SECRET_KEY


def test_object_decryption_key_recovery_with_not_enough_secret_keys(
    secret_sharing_2_groups_required_with_1_minimum_each,
):
    def available_secret_keys():
        yield ("Dlique", DLIQUE_SECRET_KEY)

    secret_sharing = secret_sharing_2_groups_required_with_1_minimum_each
    encrypted_shares = secret_sharing.generate_encrypted_shares(
        "2-groups-required-with-1-minimum-each", OBJECT_SECRET_KEY
    )
    with pytest.raises(SecretRecoveryError):
        _ = recover_object_decryption_key_from_encrypted_shares(
            encrypted_shares, available_secret_keys
        )


def test_object_decryption_key_recovery_with_known_shares(
    secret_sharing_2_groups_required_of_3_with_1_and_two_minimum_in_each,
):
    def available_secret_keys():
        yield ("Essun", ESSUN_SECRET_KEY)

    secret_sharing = (
        secret_sharing_2_groups_required_of_3_with_1_and_two_minimum_in_each
    )
    encrypted_shares = secret_sharing.generate_encrypted_shares(
        "2-groups-required-of-3-with-1-and-two-minimum-in-each", OBJECT_SECRET_KEY
    )
    camille_mnemonic = age_decrypt(
        CAMILLE_SECRET_KEY, encrypted_shares["Camille"]
    ).decode("us-ascii")
    bob_mnemonic = age_decrypt(BOB_SECRET_KEY, encrypted_shares["Bob"]).decode(
        "us-ascii"
    )
    recovered_key = recover_object_decryption_key_from_encrypted_shares(
        encrypted_shares,
        available_secret_keys,
        known_mnemonics=[
            camille_mnemonic,
            bob_mnemonic,
        ],
    )
    assert recovered_key == OBJECT_SECRET_KEY


def test_secret_sharing_errors_with_duplicate_identifiers():
    conf = f"""\
        minimum_required_groups: 2
        groups:
          legal:
            minimum_required_shares: 1
            recipient_keys:
              "Ali": {ALI_PUBLIC_KEY}
              "Bob": {BOB_PUBLIC_KEY}
          sysadmins:
            minimum_required_shares: 1
            recipient_keys:
              # Identifier also present in the legal group
              "Ali": {CAMILLE_PUBLIC_KEY}
              "Dlique": {DLIQUE_PUBLIC_KEY}
    """
    with pytest.raises(ValueError, match="Duplicate share identifier"):
        _ = SecretSharing.from_dict(yaml.safe_load(conf))


def test_secret_sharing_errors_with_duplicate_keys():
    conf = f"""\
        minimum_required_groups: 2
        groups:
          legal:
            minimum_required_shares: 1
            recipient_keys:
              "Ali": {ALI_PUBLIC_KEY}
              "Bob": {BOB_PUBLIC_KEY}
          sysadmins:
            minimum_required_shares: 1
            recipient_keys:
              # Recipient key is the same as Ali’s
              "Camille": {ALI_PUBLIC_KEY}
              "Dlique": {DLIQUE_PUBLIC_KEY}
    """
    with pytest.raises(ValueError, match="Duplicate recipient public key"):
        _ = SecretSharing.from_dict(yaml.safe_load(conf))


MOCK_AGE_PLUGIN_YUBIKEY_SCRIPT = """\
#!/bin/sh

if [ "$1" != "--identity" ]; then
    exit 1
fi

cat <<EOF
#       Serial: 5229836, Slot: 1
#         Name: age identity c3fa08e1
#      Created: Wed, 28 Jun 2023 12:24:19 +0000
#   PIN policy: Never  (A PIN is NOT required to decrypt)
# Touch policy: Cached (A physical touch is required for decryption, and is cached for 15 seconds)
#    Recipient: age1yubikey1q2e37f74zzazz75mtggzql3at66pegemfnul0dtd7axctahljkvsqezscaq
AGE-PLUGIN-YUBIKEY-1PNX57QYZC0AQ3CGZL7UL3


#       Serial: 4245067, Slot: 1
#         Name: age identity 4c1bc5f1
#      Created: Wed, 28 Jun 2023 14:43:01 +0000
#   PIN policy: Never  (A PIN is NOT required to decrypt)
# Touch policy: Always (A physical touch is required for every decryption)
#    Recipient: age1yubikey1q04k5fs8cz6kypt7vjetl2gc2qtpz9lyzpxrvv2agzt6h8n3awmzk9sgd8v
AGE-PLUGIN-YUBIKEY-1F0RYQQYZFSDUTUG4RNAMD
EOF
"""  # noqa: B950


@pytest.fixture
def mock_age_yubikey_plugin(tmp_path):
    script_path = tmp_path / "age-plugin-yubikey"
    script_path.write_text(MOCK_AGE_PLUGIN_YUBIKEY_SCRIPT)
    os.chmod(script_path, 0o500)
    old_path = os.environ["PATH"]
    os.environ["PATH"] = f"{tmp_path}:{os.environ['PATH']}"
    yield
    os.environ["PATH"] = old_path


def test_list_yubikey_identities(mock_age_yubikey_plugin):
    assert list_yubikey_identities() == [
        ("YubiKey serial 5229836 slot 1", "AGE-PLUGIN-YUBIKEY-1PNX57QYZC0AQ3CGZL7UL3"),
        ("YubiKey serial 4245067 slot 1", "AGE-PLUGIN-YUBIKEY-1F0RYQQYZFSDUTUG4RNAMD"),
    ]


@pytest.fixture
def encrypted_shares_for_object_private_key(
    secret_sharing_2_groups_required_with_1_minimum_each,
):
    secret_sharing = secret_sharing_2_groups_required_with_1_minimum_each
    return secret_sharing.generate_encrypted_shares(
        "2-groups-with-1-minimum-each", OBJECT_SECRET_KEY
    )


@pytest.fixture
def sample_populated_storage(swh_storage, sample_data):
    swh_storage.content_add(sample_data.contents)
    swh_storage.skipped_content_add(sample_data.skipped_contents)
    swh_storage.directory_add(sample_data.directories)
    swh_storage.revision_add(sample_data.git_revisions)
    swh_storage.release_add(sample_data.releases)
    swh_storage.snapshot_add(sample_data.snapshots)
    swh_storage.origin_add(sample_data.origins)
    swh_storage.origin_visit_add(sample_data.origin_visits)
    swh_storage.origin_visit_status_add(sample_data.origin_visit_statuses)
    return swh_storage


def test_create_recovery_bundle(
    tmp_path, sample_populated_storage, encrypted_shares_for_object_private_key
):
    bundle_path = tmp_path / "test.swh-recovery-bundle"
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

    unique_keys_found = []

    def register(obj):
        if hasattr(obj, "swhid"):
            unique_keys_found.append(obj.swhid().object_id)
        else:
            unique_keys_found.append(obj.unique_key())

    with RecoveryBundleCreator(
        path=bundle_path,
        storage=sample_populated_storage,
        removal_identifier="test_bundle",
        object_public_key=OBJECT_PUBLIC_KEY,
        decryption_key_shares=encrypted_shares_for_object_private_key,
        registration_callback=register,
    ) as creator:
        creator.backup_swhids(ExtendedSWHID.from_string(swhid) for swhid in swhids)

    from zipfile import ZipFile

    from swh.journal.serializers import kafka_to_value

    with ZipFile(bundle_path, "r") as bundle:
        # Do we have the expected files?
        assert bundle.namelist() == [
            "contents/swh_1_cnt_d81cc0710eb6cf9efd5b920a8453e1e07157b6cd.age",
            "contents/swh_1_cnt_c932c7649c6dfa4b82327d121215116909eb3bea.age",
            "skipped_contents/swh_1_cnt_33e45d56f88993aae6a0198013efa80716fd8920_1.age",
            "directories/swh_1_dir_5256e856a0a0898966d6ba14feb4388b8b82d302.age",
            "directories/swh_1_dir_4b825dc642cb6eb9a060e54bf8d69288fbee4904.age",
            "directories/swh_1_dir_afa0105cfcaa14fdbacee344e96659170bb1bda5.age",
            "revisions/swh_1_rev_01a7114f36fddd5ef2511b2cadda237a68adbb12.age",
            "revisions/swh_1_rev_a646dd94c912829659b22a1e7e143d2fa5ebde1b.age",
            "releases/swh_1_rel_f7f222093a18ec60d781070abec4a630c850b837.age",
            "releases/swh_1_rel_db81a26783a3f4a9db07b4759ffc37621f159bb2.age",
            "snapshots/swh_1_snp_9b922e6d8d5b803c1582aabe5525b7b91150788e.age",
            "snapshots/swh_1_snp_db99fda25b43dc5cd90625ee4b0744751799c917.age",
            "origins/swh_1_ori_33abd4b4c5db79c7387673f71302750fd73e0645.age",
            "origin_visits/swh_1_ori_33abd4b4c5db79c7387673f71302750fd73e0645_1.age",
            "origin_visit_statuses/swh_1_ori_33abd4b4c5db79c7387673f71302750fd73e0645_1_2015-01-01T23_00_00.000000+00_00.age",
            "origin_visits/swh_1_ori_33abd4b4c5db79c7387673f71302750fd73e0645_2.age",
            "origin_visit_statuses/swh_1_ori_33abd4b4c5db79c7387673f71302750fd73e0645_2_2017-01-01T23_00_00.000000+00_00.age",
            "origins/swh_1_ori_9147ab9c9287940d4fdbe95d8780664d7ad2dfc0.age",
            "origin_visits/swh_1_ori_9147ab9c9287940d4fdbe95d8780664d7ad2dfc0_1.age",
            "origin_visit_statuses/swh_1_ori_9147ab9c9287940d4fdbe95d8780664d7ad2dfc0_1_2015-01-01T23_00_00.000000+00_00.age",
            "manifest.yml",
        ]
        # Can we load the manifest?
        manifest = Manifest.load(bundle.read("manifest.yml"))
        assert isinstance(manifest, Manifest)
        assert manifest.removal_identifier == "test_bundle"
        # Can we unpack, decrypt and load at least an object?
        encrypted_serialized_content = bundle.read(
            "contents/swh_1_cnt_d81cc0710eb6cf9efd5b920a8453e1e07157b6cd.age"
        )
        serialized_content = age_decrypt(
            OBJECT_SECRET_KEY, encrypted_serialized_content
        )
        content: Content = Content.from_dict(kafka_to_value(serialized_content))
        assert content.status == "visible"
        # Have we properly saved content data?
        assert content.data == b"42\n"
        # Have we registered all saved objects?
        assert unique_keys_found == [
            bytes.fromhex("d81cc0710eb6cf9efd5b920a8453e1e07157b6cd"),
            bytes.fromhex("c932c7649c6dfa4b82327d121215116909eb3bea"),
            bytes.fromhex("33e45d56f88993aae6a0198013efa80716fd8920"),
            bytes.fromhex("5256e856a0a0898966d6ba14feb4388b8b82d302"),
            bytes.fromhex("4b825dc642cb6eb9a060e54bf8d69288fbee4904"),
            bytes.fromhex("afa0105cfcaa14fdbacee344e96659170bb1bda5"),
            bytes.fromhex("01a7114f36fddd5ef2511b2cadda237a68adbb12"),
            bytes.fromhex("a646dd94c912829659b22a1e7e143d2fa5ebde1b"),
            bytes.fromhex("f7f222093a18ec60d781070abec4a630c850b837"),
            bytes.fromhex("db81a26783a3f4a9db07b4759ffc37621f159bb2"),
            bytes.fromhex("9b922e6d8d5b803c1582aabe5525b7b91150788e"),
            bytes.fromhex("db99fda25b43dc5cd90625ee4b0744751799c917"),
            bytes.fromhex("33abd4b4c5db79c7387673f71302750fd73e0645"),
            {
                "date": "2015-01-01 23:00:00+00:00",
                "origin": "https://github.com/user1/repo1",
            },
            {
                "date": "2015-01-01 23:00:00+00:00",
                "origin": "https://github.com/user1/repo1",
                "visit": "1",
            },
            {
                "date": "2017-01-01 23:00:00+00:00",
                "origin": "https://github.com/user1/repo1",
            },
            {
                "date": "2017-01-01 23:00:00+00:00",
                "origin": "https://github.com/user1/repo1",
                "visit": "2",
            },
            bytes.fromhex("9147ab9c9287940d4fdbe95d8780664d7ad2dfc0"),
            {
                "date": "2015-01-01 23:00:00+00:00",
                "origin": "https://github.com/user2/repo1",
            },
            {
                "date": "2015-01-01 23:00:00+00:00",
                "origin": "https://github.com/user2/repo1",
                "visit": "1",
            },
        ]


def test_create_recovery_bundle_fails_if_empty(
    tmp_path, sample_populated_storage, encrypted_shares_for_object_private_key
):
    bundle_path = tmp_path / "test.swh-recovery-bundle"
    with pytest.raises(ValueError):
        with RecoveryBundleCreator(
            path=bundle_path,
            storage=sample_populated_storage,
            removal_identifier="test_bundle",
            object_public_key=OBJECT_PUBLIC_KEY,
            decryption_key_shares=encrypted_shares_for_object_private_key,
        ) as _:
            # oops, we do not add any objects
            pass


def test_create_recovery_bundle_fails_without_decryption_key_shares(
    tmp_path, sample_populated_storage
):
    bundle_path = tmp_path / "test.swh-recovery-bundle"
    swhids = ["swh:1:ori:33abd4b4c5db79c7387673f71302750fd73e0645"]
    with pytest.raises(ValueError):
        with RecoveryBundleCreator(
            path=bundle_path,
            storage=sample_populated_storage,
            removal_identifier="test_bundle",
            object_public_key=OBJECT_PUBLIC_KEY,
            decryption_key_shares={},
        ) as creator:
            creator.backup_swhids(ExtendedSWHID.from_string(swhid) for swhid in swhids)


def test_create_recovery_bundle_with_optional_fields(
    tmp_path, sample_populated_storage, encrypted_shares_for_object_private_key
):
    bundle_path = tmp_path / "test.swh-recovery-bundle"
    swhids = ["swh:1:ori:33abd4b4c5db79c7387673f71302750fd73e0645"]
    expiration_date = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        days=365
    )
    with RecoveryBundleCreator(
        path=bundle_path,
        storage=sample_populated_storage,
        removal_identifier="test_bundle",
        object_public_key=OBJECT_PUBLIC_KEY,
        decryption_key_shares=encrypted_shares_for_object_private_key,
    ) as creator:
        creator.backup_swhids(ExtendedSWHID.from_string(swhid) for swhid in swhids)
        creator.set_reason("we are running a test")
        creator.set_expire(expiration_date)

    from zipfile import ZipFile

    with ZipFile(bundle_path, "r") as bundle:
        manifest = Manifest.load(bundle.read("manifest.yml"))
        assert manifest.reason == "we are running a test"
        assert manifest.expire.isoformat(
            timespec="seconds"
        ) == expiration_date.isoformat(timespec="seconds")


@pytest.fixture
def sample_recovery_bundle_path():
    return os.path.join(
        os.path.dirname(__file__), "fixtures", "sample.swh-recovery-bundle"
    )


def object_decryption_key_provider_for_sample(manifest: Manifest) -> AgeSecretKey:
    return OBJECT_SECRET_KEY


@pytest.fixture
def sample_recovery_bundle(sample_recovery_bundle_path):
    return RecoveryBundle(
        sample_recovery_bundle_path, object_decryption_key_provider_for_sample
    )


def test_recovery_bundle_decryption_key_provider_is_optional(
    sample_recovery_bundle_path,
):
    bundle = RecoveryBundle(sample_recovery_bundle_path)
    # We can access the manifest even without a decryption_key_provider
    assert bundle.removal_identifier == "test_bundle"
    # But trying to get the object_decryption_key will fail
    with pytest.raises(ValueError):
        _ = bundle.object_decryption_key


def test_recovery_bundle_get_dict(sample_recovery_bundle):
    swhid = ExtendedSWHID.from_string(
        "swh:1:ori:33abd4b4c5db79c7387673f71302750fd73e0645"
    )
    d = sample_recovery_bundle.get_dict(swhid)
    assert d == {"url": "https://github.com/user1/repo1"}


def test_recovery_bundle_write_content_data(tmp_path, sample_recovery_bundle):
    dest_path = tmp_path / "data"
    swhid = ExtendedSWHID.from_string(
        "swh:1:cnt:d81cc0710eb6cf9efd5b920a8453e1e07157b6cd"
    )
    with open(dest_path, "wb") as dest:
        sample_recovery_bundle.write_content_data(swhid, dest)
    assert open(dest_path, "rb").read() == b"42\n"


def test_recovery_bundle_contents(sample_recovery_bundle, sample_data):
    contents = list(sample_recovery_bundle.contents())
    assert contents == [sample_data.content, sample_data.content3]


def test_recovery_bundle_skipped_contents(sample_recovery_bundle, sample_data):
    skipped_contents = list(sample_recovery_bundle.skipped_contents())
    assert skipped_contents == [sample_data.skipped_content]


def test_recovery_bundle_directories(sample_recovery_bundle, sample_data):
    directories = list(sample_recovery_bundle.directories())
    # Comparing Directory objects directly will not work because order
    # of entries are not guaranteed by storage. Therefore we have to
    # compare each field individually.
    assert len(directories) == 3
    for d, sample_d in zip(
        directories,
        [sample_data.directory, sample_data.directory5, sample_data.directory6],
    ):
        assert d.id == sample_d.id
        assert set(d.entries) == set(sample_d.entries)
        assert d.raw_manifest == sample_d.raw_manifest


def test_recovery_bundle_revisions(sample_recovery_bundle, sample_data):
    revisions = list(sample_recovery_bundle.revisions())
    assert revisions == [sample_data.revision, sample_data.revision2]


def test_recovery_bundle_releases(sample_recovery_bundle, sample_data):
    releases = list(sample_recovery_bundle.releases())
    assert releases == [sample_data.release, sample_data.release2]


def test_recovery_bundle_snapshots(sample_recovery_bundle, sample_data):
    snapshots = list(sample_recovery_bundle.snapshots())
    assert snapshots == [sample_data.snapshot, sample_data.complete_snapshot]


def test_recovery_bundle_origins(sample_recovery_bundle, sample_data):
    origins = list(sample_recovery_bundle.origins())
    assert origins == [sample_data.origin, sample_data.origin2]


def test_recovery_bundle_origin_visits(sample_recovery_bundle, sample_data):
    origin_visits = list(sample_recovery_bundle.origin_visits(sample_data.origin))
    assert origin_visits == [
        sample_data.origin_visit,
        sample_data.origin_visit2,
    ]


def test_recovery_bundle_origin_visit_statuses(sample_recovery_bundle, sample_data):
    origin_visit_statuses = list(
        sample_recovery_bundle.origin_visit_statuses(sample_data.origin)
    )
    assert origin_visit_statuses == [
        sample_data.origin_visit_status,
        sample_data.origin_visit2_status,
    ]


def test_restore(sample_recovery_bundle, swh_storage, sample_data):
    result = sample_recovery_bundle.restore(swh_storage)
    assert result == {
        "content:add": 2,
        "content:add:bytes": 10,
        "skipped_content:add": 1,
        "directory:add": 3,
        "revision:add": 2,
        "release:add": 2,
        "snapshot:add": 2,
        "origin:add": 2,
    }
    [
        origin,
    ] = swh_storage.origin_get(["https://github.com/user1/repo1"])
    assert origin is not None
    assert str(origin.swhid()) == "swh:1:ori:33abd4b4c5db79c7387673f71302750fd73e0645"
    origin_visit = swh_storage.origin_visit_get_by(origin.url, 1)
    assert origin_visit == sample_data.origin_visit
    origin_visit2 = swh_storage.origin_visit_get_by(origin.url, 2)
    assert origin_visit2 == sample_data.origin_visit2
    origin_visit2_status = swh_storage.origin_visit_status_get_latest(origin.url, 2)
    assert origin_visit2_status == sample_data.origin_visit2_status


def test_rollover(
    tmp_path,
    sample_recovery_bundle_path,
    secret_sharing_2_groups_required_of_3_with_1_and_two_minimum_in_each,
):
    import shutil

    bundle_path = shutil.copy(
        sample_recovery_bundle_path, tmp_path / "rollover.swh-recovery-bundle"
    )
    secret_sharing = (
        secret_sharing_2_groups_required_of_3_with_1_and_two_minimum_in_each
    )
    bundle = RecoveryBundle(bundle_path, object_decryption_key_provider_for_sample)

    # Record OriginVisit and OriginVisitStatuses objects for later comparison
    origin_visits = set()
    origin_visit_statuses = set()
    for origin in bundle.origins():
        origin_visits.update(bundle.origin_visits(origin))
        origin_visit_statuses.update(bundle.origin_visit_statuses(origin))

    # Perform rollover!
    bundle.rollover(secret_sharing)

    # Check all the things!!
    def decryption_key_provider(manifest):
        return recover_object_decryption_key_from_encrypted_shares(
            manifest.decryption_key_shares,
            available_secret_keys_for_2_groups_required_of_3_one_and_two,
        )

    new_bundle = RecoveryBundle(bundle_path, decryption_key_provider)
    # Do we have the new holders?
    assert new_bundle.share_ids == {"Ali", "Bob", "Camille", "Dlique", "Essun"}
    # Has the old object been updated as well?
    assert bundle.share_ids == new_bundle.share_ids
    # Is the decryption key still the same after being recovered?
    assert new_bundle.object_decryption_key == OBJECT_SECRET_KEY
    # Can we still decrypt all known objects?
    decrypted_swhids = set()
    for obj in itertools.chain(
        new_bundle.contents(),
        new_bundle.skipped_contents(),
        new_bundle.directories(),
        new_bundle.revisions(),
        new_bundle.releases(),
        new_bundle.snapshots(),
    ):
        decrypted_swhids.add(str(obj.swhid()))
    new_origin_visits = set()
    new_origin_visit_statuses = set()
    for origin in new_bundle.origins():
        decrypted_swhids.add(str(origin.swhid()))
        new_origin_visits.update(new_bundle.origin_visits(origin))
        new_origin_visit_statuses.update(new_bundle.origin_visit_statuses(origin))
    assert decrypted_swhids == set(bundle.swhids)
    assert origin_visits == new_origin_visits
    assert origin_visit_statuses == new_origin_visit_statuses


def test_rollover_fails_when_unable_to_write(
    tmp_path,
    sample_recovery_bundle_path,
    secret_sharing_2_groups_required_of_3_with_1_and_two_minimum_in_each,
):
    import shutil

    bundle_path = shutil.copy(
        sample_recovery_bundle_path, tmp_path / "rollover.swh-recovery-bundle"
    )
    secret_sharing = (
        secret_sharing_2_groups_required_of_3_with_1_and_two_minimum_in_each
    )
    bundle = RecoveryBundle(bundle_path, object_decryption_key_provider_for_sample)
    share_ids = bundle.share_ids
    swhids = bundle.swhids

    # We can more or less simulate a full disk by preventing writes
    # in the directory holding the recovery bundle.
    os.chmod(tmp_path, 0o500)

    with pytest.raises(OSError):
        bundle.rollover(secret_sharing)

    new_bundle = RecoveryBundle(bundle_path, object_decryption_key_provider_for_sample)
    assert new_bundle.share_ids == share_ids
    assert new_bundle.object_decryption_key == OBJECT_SECRET_KEY
    assert new_bundle.get_dict(ExtendedSWHID.from_string(swhids[0])) is not None
