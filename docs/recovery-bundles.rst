.. _alter_recovery_bundles:

Recovery bundles
================

Before removals happen, a “recovery bundle” is created with everything needed
to restore what will be deleted from the archive.

Recovery bundles serve several purposes:

- Data consistency

  The storage might not provide transactions
  with `ACID properties <https://en.wikipedia.org/wiki/ACID>`_ all the way
  through. Therefore a loader could add a new reference to an object after its
  removal. These allow to rollback deletions if that happens, before
  one can restart the procedure.

- Recovery from human errors

  Misunderstandings, typos or cats can happen. These bundles allow to
  restore what has been removed in case of mishaps.

- Legal requirements

  A legal investigation might compel operators to keep a copy of the allegedly
  infriging data on top of making it unavailable to the rest of the world.

In most cases, legal issues are the reason data get removed from the archive.
Therefore recovery bundles can contain sensitive information for which access
should be restricted. This is achieved by encrypting the objects in the
recovery bundle, and requiring that multiple parties join together to decrypt
them.

Description
-----------

Recovery bundles are Zip archives with a ``manifest.yml`` describing the
recovery bundle, and a set of directories holding the removed objects in
encrypted form.

Using a Zip archive allow for direct access. Each object is stored encrypted
using a public key selected for the whole bundle. This decryption key is
securely stored in the manifest using encrypted secret shares.

Manifests
---------

Manifests are simple `YAML <https://yaml.org/>`_ files with a mapping of the
following entries. All fields are required unless specified.

- ``version`` (int): the literal ``1``, the current version of the recovery
  bundle format.
- ``removal_identifier`` (string): an arbitrary identifier for the removal
  operation. In most cases, this will be the case identifier used for the
  takedown notice.
- ``created`` (ISO8601 timestamp):
- ``swhids`` (sequence of strings): :ref:`SWHID <swhids>` present in the recovery bundle.
- ``decryption_key_shares``: (mapping): shares used to recover the object decryption
  key, stored as a mapping of an secret holder identifier to armored age encrypted data
  (see :ref:`below for details <recovery-bundle-encryption>`).
- ``reason`` (string, optional): why these objects have been removed, in broad terms.
- ``expire`` (ISO8601 timestamp, optional): when should this bundle be deleted.

Objects
-------

Each object is stored in a different file. These files are put in directories
depending on their type.
Each file contains a serialization of the object it represents using
the same :ref:`encoding used for Kafka messages in swh-journal
<journal-specs>`. In short, using `msgpack
<https://msgpack.org/>`_ on the attribute dict of each type (see
:py:meth:`swh.model.model.BaseModel.to_dict`), with a
few custom encodings.

.. list-table:: Directories and filenames
   :header-rows: 1

   * - Object type
     - Directory
     - Filename format
     - Example filename
   * - :py:class:`Origin <swh.model.model.Origin>`
     - ``origins/``
     - :py:class:`extended SWHID <swh.model.swhids.ExtendedSWHID>`
     - ``swh_1_ori_8f50d3f60eae370ddbf85c86219c55108a350165.age``
   * - :py:class:`OriginVisit <swh.model.model.OriginVisit>`
     - ``origin_visits/``
     - extended SWHID ``_`` visit index
     - ``swh_1_ori_8f50d3f60eae370ddbf85c86219c55108a350165_1.age``
   * - :py:class:`OriginVisitStatus <swh.model.model.OriginVisitStatus>`
     - ``origin_visit_statuses/``
     - extended SWHID ``_`` visit index ``_`` date in ISO8601 format
     - ``swh_1_ori_8f50d3f60eae370ddbf85c86219c55108a350165_1_2013-05-07T04_20_39.369271+00_00.age``
   * - :py:class:`Snapshot <swh.model.model.Snapshot>`
     - ``snapshots/``
     - SWHID
     - ``swh_1_snp_0000000000000000000000000000000000000022.age``
   * - :py:class:`Release <swh.model.model.Release>`
     - ``releases/``
     - SWHID
     - ``swh_1_rel_0000000000000000000000000000000000000021.age``
   * - :py:class:`Revision <swh.model.model.Revision>`
     - ``revisions/``
     - SWHID
     - ``swh_1_rev_0000000000000000000000000000000000000018.age``
   * - :py:class:`Directory <swh.model.model.Directory>`
     - ``directories/``
     -  SWHID
     - ``swh_1_dir_0000000000000000000000000000000000000017.age``
   * - :py:class:`Content <swh.model.model.Content>`
     - ``contents/``
     - SWHID
     - ``swh_1_cnt_0000000000000000000000000000000000000016.age``
   * - :py:class:`SkippedContent <swh.model.model.SkippedContent>`
     - ``skipped_contents/``
     - SWHID ``_`` matching skipped content number (due to potential hash collisions)
     - ``swh_1_cnt_0000000000000000000000000000000000000015_1.age``

Colons (``:``) are replaced by underscores (``_``) to avoid surprises
with some filesystems restriction. ``.age`` is added as an extension to
highlight that objects are encrypted (see :ref:`below
<recovery-bundle-encryption>`).


.. note::

   While using directories for each object type might seem redundant with
   using a full SWHID for the filename, it is more flexible to be able to
   store proper backups of what was in the archive. As we can see,
   ``skipped_content`` and ``content`` objects share the same SWHID but
   store different data. We also store objects which are not strictly
   referenced by a SWHID in the case of ``origin_visit`` and
   ``origin_visit_statuses``.

.. _recovery-bundle-encryption:

Encryption
----------

Object files are encrypted using the `age file encryption format
<https://age-encryption.org/>`_.

For each bundle, we create a new key pair. The public key will be used
to encrypt each object file.

The associated secret (decryption) key is split using Shamir’s secret sharing
(as described in `SLIP-0039
<https://github.com/satoshilabs/slips/blob/master/slip-0039.md>`_). Each share
is encrypted using age to a public key, prefixed by the bundle removal
identifier. What we will encrypt will thus look like:

.. code::

    [takedown-notice-2023-08-15-01] union echo beard entrance alien photo …
     ^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     bundle identifier            SLIP-0039 mnemonic

.. note::

   The removal identifier is there for the case a secret holder is asked to
   remotely decrypts their payload. They can verify it came from the right
   recovery bundle before sending back the decrypted share.

These encrypted secrets are then stored in the manifest, associated
with the identifier of the secret holder.

Identifiers for the secret holder are arbitrary in the case of usual age secret
key. If the secret key is stored on a `YubiKey
<https://www.yubico.com/products/>`_ (using `age-plugin-yubikey
<https://github.com/str4d/age-plugin-yubikey>`_), the identifier must look like
“YubiKey serial 1234567 slot 1”.

.. note::

   The public (encryption) key is not stored anywhere. As each bundle covers a
   single removal procedure, there will never be the need to add new objects to
   an existing bundle. Therefore, there is no need to keep the public key.

.. figure:: images/recovery-bundle.opt.svg
   :alt: A schema showing the encryption layers used in recovery bundles

   An example recovery bundle for the secret sharing policy described in the
   example configuration

The decryption process then follows the following steps:

1. The required amount of shares are decrypted using the relevant YubiKey.
2. Decrypted shares are assembled to recover the secret decryption key.
3. Objects are decrypted.

Rolling over to a new YubiKey goes as follow:

1. The required amount of shares are decrypted using the relevant YubiKey.
2. Decrypted shares are assembled to recover the secret decryption key.
3. New shares are generated to protect the secret decryption key.
4. Shares are encrypted to the new set of public keys (as described in
   the updated ``swh-alter`` configuration file).

.. topic:: Rationale

   This system requires multiple people from different departments to get
   together to access sensitive data. Using YubiKey provides a pretty simple
   user experience both in terms of handling (“store this object safely”) and
   usage (“plug this in a USB port and press the button when it blinks”).

   Encrypting each object file individually allows to recover only a specific
   set of objects if needed.

   Rolling over to new keys does not require re-encrypting the objects with
   new keys. (This assumes that the object encryption keys will not be saved
   when recovered.)

   Storing the serial and slot numbers in the manifest helps locating which
   share should be decrypted depending on which YubiKeys are plugged in.

Example
-------

List of entries in a recovery bundle created for the :ref:`example removal
<alter_removal_algorithm_example>`:

- ``manifest.yml``
- ``origins/``:

  - ``swh_1_ori_8f50d3f60eae370ddbf85c86219c55108a350165.age``

- ``origin_visits/``:

  - ``swh_1_ori_8f50d3f60eae370ddbf85c86219c55108a350165_1.age``

- ``origin_visit_statuses/``:

  - ``swh_1_ori_8f50d3f60eae370ddbf85c86219c55108a350165_1_2013-05-07T04_20_39.369271+00_00.age``

- ``snapshots/``:

  - ``swh_1_snp_0000000000000000000000000000000000000022.age``

- ``releases/``:

  - ``swh_1_rel_0000000000000000000000000000000000000021.age``

- ``revisions/``:

  - ``swh_1_rev_0000000000000000000000000000000000000018.age``
  - ``swh_1_rev_0000000000000000000000000000000000000013.age``

- ``directories/``:

  - ``swh_1_dir_0000000000000000000000000000000000000017.age``

- ``contents/``:

  - ``swh_1_cnt_0000000000000000000000000000000000000016.age``
  - ``swh_1_cnt_0000000000000000000000000000000000000012.age``
  - ``swh_1_cnt_0000000000000000000000000000000000000014.age``
  - ``swh_1_cnt_0000000000000000000000000000000000000011.age``

- ``skipped_contents/``:

  - ``swh_1_cnt_0000000000000000000000000000000000000015_1.age``

Content of ``manifest.yml``:

.. code:: yaml

  version: 1
  removal_identifier: TDN-2023-06-18-01
  created: 2023-06-18T13:12:42Z
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
    "YubiKey serial 4245067 slot 1": |
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
    "Hedwig Robinson": |
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
  expire: 2024-06-18T13:12:42Z

Implementation notes
--------------------

Our goal is to require multiple parties to agree before a recovery bundle can be
restored (or have its content extracted). We believe the proposed scheme fulfill
this goal, but as all security-related tools, we can analyze some limits.

1. With Shamir Secret Sharing, the share-holders cannot verify that their shares
   are valid. Meaning:

   - The dealer could cheat.

     In our case, the dealer is the recovery bundle creation system. An attacker
     would need to change the production code, or the recovery bundle itself after
     it has been generated but before it has been sent to a common storage. In
     both cases, that means they have access to the system used to delete objects
     in the database. Therefore we can assume they have elevated access to the
     database, and could delete or look-up the data directly instead of using
     a more complex method of corrupting a recovery bundle in one way or another.

   - The secret holders could cheat.

     With the local mode of operation, holders don’t exchange secrets. They
     only provide temporary access to their secret key (ideally by plugging a
     YubiKey). Cheating would mean changing the production code which would most
     likely be detected while trying to recover from the error of finding a
     corrupted share.

     When working remotely, holders could willingly share a corrupted secret. This
     would result in a denial-of-service (due to SLIP-0039 properties). However,
     while this would prevent one bundle to be restored, this would result in
     potential consequences at the employment level. Depending on the secret
     sharing configuration, this might have no impact on the team ability to
     restore the bundle anyway, as another holder could provide a working secret.

2. The person reassembling the secrets could keep a copy to re-use them later

   While secrets could be reused, there is little to gain from doing so. Once a
   bundle has been restored, it is basically useless: all the information has
   returned to Software Heritage archive. Extracting content could be done more
   than once, but it would be limited to a single bundle, as bundles all have
   their own decryption key.

   Keeping a secret for reuse is thus equivalent to keeping a single bundle
   decryption key for reuse. While not ideal, at least for this precise bundle,
   the parties who have agreed to extract content knows about it.

3. When a secret holder uses an identity file, a malevolent participant could
   make a copy when restoring a bundle in local mode. This would enable them to
   restore or extract content from any number of recovery bundles.

   Indeed. When holders are using an identity file, remote operations should
   be preferred.

   Using an identity file directly can be limited to general rollover
   operations, when multiple bundles need to be recovered at once. Before
   running the rollover, each secret holder using an identity file should
   generate a new identity and their public keys updated in the
   configuration.

4. An attacker could ask a secret holder to decrypt any payload as part
   of a remote operation.

   True. Therefore:

   - key pairs used by secret holders should only be used for recovery bundle
     secrets,
   - secret holders should always make sure that the removal
     identifier visible after decrypting the payload matches the bundle
     that needs to be accessed.

   The payloads themselves are protected from tampering by |age using AEAD|_.

5. `python-shamir-mnemonic` is vulnerable to side-channel attacks.

   A side-channel issue in `python-shamir-mnemonic` would allow an attacker to
   recover more information than they should from a limited number of shares. In
   our case, that means at least having a secret holder ready to recover their
   share for a given bundle, and start from there. While not ideal, this severely
   limits the attack surface of using a non-optimal SLIP-0039 implementation.
   An attacker would first have to steal an holder secret key, get access to
   their target bundle, before they can start working on the maths…

.. |age using AEAD| replace:: `age` using AEAD
.. _age using AEAD: https://words.filippo.io/dispatches/age-authentication/
