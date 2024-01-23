Using swh-alter
===============

Services provided by this component are available through the ``swh alter`` command
line tool.

The key feature is available through the ``remove`` sub-command and allow
removal of data from the archive. Before this happens, a recovery bundle will be
created that allows reverting the operation.

Because of their potential sensitivity, data in recovery bundles is stored
encrypted. The system is designed so that extracting content or restoring from a
recovery bundle will require a pre-determined set of stakeholders to get
together before proceeding.

Dependencies
------------

``swh-alter`` requires the ``rage``, ``rage-keygen`` and optionally
``age-plugin-yubikey`` commands to be available in the ``PATH``.

See their respective documentation on how to install them:

- `rage installation <https://github.com/str4d/rage#installation>`_ (also provides ``rage-keygen``)
- `age-plugin-yubikey installation <https://github.com/str4d/age-plugin-yubikey#installation>`_

``age-plugin-yubikey`` also requires the ``pcscd`` service to be installed and
running. On Debian systems, the service is available from the package with the
same name.

.. _cli-config-alter:

Configuration
-------------

The tools will not work without a configuration file. It can be created as
``~/.config/swh/alter.yml`` containing for example:

.. code:: yaml

    storage:
      cls: remote
      url: https://storage-cassandra-ro.softwareheritage.org

    graph:
      url: "http://granet.internal.softwareheritage.org:5009/graph"

    restoration_storage:
      cls: remote
      url: https://storage-rw.softwareheritage.org

    removal_storages:
      old_primary:
        cls: postgresql
        db: "service=swh"
      new_primary:
        cls: cassandra
        hosts:
        - cassandra-seed
        keyspace: swh

    removal_objstorages:
      main:
        cls: remote
        url: https://objstorage.softwareheritage.org
      azure:
        cls: azure-prefixed
        accounts:
          "0":
            account_name: testswh0
            api_secret_key: supersecret
            container_name: contents

    removal_journals:
      main_journal:
        cls: kafka
        brokers:
        - kafka1.internal.softwareheritage.org
        prefix: swh.journal.objects
        client_id: swh.alter.removals

    recovery_bundles:
      secret_sharing:
        minimum_required_groups: 2
        groups:
          legal:
            minimum_required_shares: 1
            recipient_keys:
                DPO: age169k6jwg7e2jqjzzsfvqh5v06h56tkss9fx5vmp8xr400272zjq5qux74m5
                CLO: age1gdar6q9spzz5d3lul5ng5sf30xt7r2htsx8n5espl0pun6wvv4yqjapdma
          sysadmins:
            minimum_required_shares: 2
            recipient_keys:
                YubiKey serial 4245067 slot 1: |-
                  age1yubikey1q0ucnwg558zcwrc752evk3620q2t4mkwz6a0lq9u3clsfmealsmlz330kz2
                YubiKey serial 5229836 slot 1: |-
                  age1yubikey1qt2p377vq6qg58l8gaframp9yggvsysddraa72aehma5mw623r8rqk0mlgu
                YubiKey serial 5254231 slot 2: |-
                  age1yubikey1q0ucnwg558zcwrc752evk3620q2t4mkwz6a0lq9u3clsfmealsmlz330kz2

See the :ref:`configuration reference <cli-config>` for general information
about the Software Heritage configuration file. At least, ``swh-alter``
requires the :ref:`storage <cli-config-storage>` and :ref:`graph <cli-config-graph>`
sections to be configured properly.

In most cases, multiple *storages* has to be configured:

- The ``storage`` section defines the storage from which information will be
  read. It is used to determine which objects can be removed from the
  archive and create recovery bundles. For the latter, it needs to be able to
  retrieve data from Content objects (through an *objstorage*).
- The ``restoration_storage`` section defines the storage which will be written
  to in case recovery bundles need to be resored. Write access is required. For
  the restoration to fully work, it also needs to be configured to write to an
  *objstorage* and a *journal*.
- ``removal_storages`` contains storages (identified by an arbitrary key)
  from which objects will be removed (when using ``swh alter remove``).

Likewise, ``removal_objstorages`` and ``removal_journals`` defines *objstorages*
and *journals* from which data and messages will be removed by ``swh alter
remove``.

The ``graph`` section is used to determine which objects can be safely removed
from the archive.

In addition, the organization of the secret sharing process needs to be defined
in ``secret_sharing``.

.. note::

   The example above requires people from two groups to decrypt recovery
   bundles: the legal team and the system administration team. For the legal
   team, either the Data Protection Officer or the Chief Legal Officer will need
   to provide an identity file with their secret key. For system administrators,
   at least two of the specified YubiKeys will need to be present.

In the `groups` section, each group is keyed with an arbitrary identifier. In
each group:
- ``recipient_keys`` associate an identifier for the holder and an
`age`_ public key
- ``minimum_requred_shares`` set the threshold of holders required for this group.

The minimum amount of valid groups that are required to recover the decryption
key is set in ``minimum_required_groups``.

age public key can be created using the ``age-keygen`` or ``rage-keygen``
command (depending on your implementation), or by calling ``age-plugin-yubikey``
to store the private key on a `YubiKey`_.

When using YubiKeys, the secret holder identifier needs to be specified in the
form ``YubiKey serial ####### slot #``. The required numbers are visible in the
identity file created by ``age-plugin-yubikey`` or by running
``age-plugin-yubikey --list`` after plugging in the YubiKeys.

.. hint::

   When using YubiKeys, ``swh alter`` does not need any external files to be stored
   on the system. Connecting the right YubiKey is all that is required.

   Otherwise, the *age* secret key will need to be provided manually
   as an *identity file*. Such files should be stored with care.
   Being 74 characters long, *age* secret keys are fairly easy to archive on
   paper.

.. _age: https://age-encryption.org/v1
.. _YubiKey: https://www.yubico.com/products/

Removing objects from the archive
---------------------------------

``swh alter remove`` will remove a given set of origins, and any objects they
reference (as long as it not referenced elsewhere), from the archive.

.. code:: console

    $ export SWH_CONFIG_FILENAME=~/config/swh.alter.yml
    $ swh alter remove \
          --identifier "takedown-notice-2023-07-14-01" \
          --recovery-bundle tdn-2023-07-14-01.swh-recovery-bundle \
          https://gitlab.softwareheritage.org/swh/devel/swh-alter.git \
          https://gitlab.softwareheritage.org/swh/devel/swh-py-template.git

.. Sample output: [for reference, it does not appear in the documentation]

    Assuming https://gitlab.softwareheritage.org/swh/devel/swh-alter.git is an origin URL.
    Assuming https://gitlab.softwareheritage.org/swh/devel/swh-py-template.git is an origin URL.
    Removing the following origins:
    - swh:1:ori:563a9a2cd47a25caf1a8d13b2a20f20276c8c808
    - swh:1:ori:33bf251c0937b1394bc2df185779a75ad0bf3d36
    Inventorying all reachable objects…
    Determining which objects can be safely removed…
    Proceed with removing 29 objects? [y/N]: y
    Creating recovery bundle…
    Recovery bundle created.
    Removing objects from primary storage…
    29 objects removed from primary storage.
    Removing objects from storage “cassandra”…
    29 objects removed from storage “cassandra”.

Objects will be removed from the “primary” storage defined in the configuration
and any other instances defined in a ``extra_storage`` section.

.. warning::

   The implementation of removal is not yet fully complete:

   - Contents in _objstorage_ will not be removed.
   - Objects in the _journal_ will not be removed.
   - Search data in Elasticsearch will not be removed.

If during the removal process a reference is added to one of the removed
objects, the process will be rolled back: the recovery bundle will be used to
restore objects as they were to the “primary” storage. This will also be the
case if any error happens during the process. The recovery bundle will be left
intact.

Options:

``--dry-run``
    Get a list of objects that would be removed and exit.

``--identifier IDENTIFIER`` (required)
    An arbitrary identifier for this removal operation. Stored in recovery
    bundles.

``--recovery-bundle PATH`` (required)
    Location of the recovery bundle that will be created before removing objects
    from the archive.

``--reason REASON``
    Reason for this removal operation.

``--expire YYYY-MM-DD``
    Date when the recovery bundle should be removed.

Restoring from a recovery bundle
--------------------------------

``swh alter recovery-bundle restore`` will restore all objects contained in a
recovery bundle to the “primary” storage. In order to proceed, this command
requires enough shared secrets to be recovered. Alternatively, the bundle
decryption key can be provided.

This command also requires the appropriate permissions needed to update Software
Heritage storage, journal and object storage.

.. code:: console

    $ swh alter recovery-bundle restore tdn-2023-07-14-01.swh-recovery-bundle

.. Sample output: [for reference, it does not appear in the documentation]

    🚸 The following secret shares will not be decrypted: Innon, Alabaster, Essun

    🔐 Please insert YubiKey serial 4245067 slot 1, YubiKey serial 4245067 slot 2, YubiKey serial 4245067 slot 3 and press Enter…

    🔧 Decrypting share using YubiKey serial 4245067 slot 1…
    💭 You might need to tap the right YubiKey when it blinks.

    🔧 Decrypting share using YubiKey serial 4245067 slot 2…
    💭 You might need to tap the right YubiKey when it blinks.

    🔧 Decrypting share using YubiKey serial 4245067 slot 3…
    💭 You might need to tap the right YubiKey when it blinks.

    Restoration complete. Results:
    - Content objects added: 2
    - Total bytes added to objstorage: 10
    - SkippedContent objects added: 1
    - Directory objects added: 3
    - Revision objects added: 2
    - Release objects added: 2
    - Snapshot objects added: 2
    - Origin objects added: 2

Options:

``--decryption-key AGE_SECRET_KEY``
    Use the given decryption key instead of the bundle shared secrets (see
    :ref:`recovery-bundle-remote-operations`).

``--secret MNEMONIC``
    Known shared secret. May be repeated.

``--identity IDENTITY``
    Path to an *age* identity file holding a secret key. May be repeated.

.. _recovery-bundle-info:

Getting information from a recovery bundle
------------------------------------------

``swh alter recovery-bundle info`` will output information on a given recovery bundle.

This will display the identifier provided during the removal operation, the date
of creation, reason for the removal, expiration date, the identifier of the
secret share holders, and the SWHIDs of stored objects.

.. code:: console

    $ swh alter recovery-bundle info tdn-2023-07-14-01.swh-recovery-bundle

.. Sample output: [for reference, it does not appear in the documentation]

    Recovery bundle “takedown-notice-2023-07-14-01”
    ===============================================

    Created: 2023-08-24T13:32:35+00:00
    List of SWHID objects:
    - swh:1:cnt:3d65be4c62d36aac611260b47555ac9d51cd5515
    - swh:1:cnt:be3cf71385d6b78038fd822818c074deeff7bbc5
    - swh:1:cnt:3141801efb4579d51f351c96d01ee020374257bc
    - swh:1:cnt:f7c4868ad7af4043199656f78bc050bed36b9292
    - swh:1:cnt:6dc07fa6aae7e5b0ef74d2fa410c2533d766a383
    - swh:1:cnt:5c3ed7404def3133c8353a917ba99a07285571a3
    - swh:1:cnt:3901f53a85128056aa173cc08faf4080d5c7ff9f
    - swh:1:cnt:57ab742295e34402a379d0878a5de1a048980878
    - swh:1:dir:a54bf3235c949c873a3338358bdd3e8fa1113389
    - swh:1:dir:2ed7f77d677966ca9b59f5f41344753ec3c41296
    - swh:1:dir:418a17683d3d3f015bf6a9c5b7850bb12e61742c
    - swh:1:dir:4b265788288dbdf978017d6c7d5c25071aa4705b
    - swh:1:dir:3f594672371d2c09f08efb353288e5cc750afa04
    - swh:1:dir:e032103037b3c3e60363354087e3bf5254dbcd23
    - swh:1:dir:102ac2673471f89e699292f3a28b217bb5e50ed3
    - swh:1:dir:113f64f9ea3a00d406a1d94b3592336fdd03e13b
    - swh:1:dir:febe61b10da24d7e2e5338908edc2d61d50e2e41
    - swh:1:rev:9434de5309a3a1548bbaa56cf89eb21271a3910c
    - swh:1:rev:c6e181c0a7ecce017d2810f5b0f04ced8c969291
    - swh:1:rev:1ac62813203d728338d30066fa14c0f46428125e
    - swh:1:rev:6e9af5acf82faf5a082e5fb57ec1d1fdb08f62b4
    - swh:1:rev:b9e152c1a7eaf2822960099702cef26ef3815587
    - swh:1:rev:7c3e064c0f1c5a3bb3557860aea86f3e887b5b48
    - swh:1:rev:85a046c9fb010dd89f82c645561574c01392ec12
    - swh:1:snp:c027143bff8054744d6b70c185c683de4c581e69
    - swh:1:snp:1432e839690a4b192ebe352853cceaf1b689e9ec
    - swh:1:snp:5c48da4e27b756775151fd9323d010cdada72cf7
    - swh:1:ori:563a9a2cd47a25caf1a8d13b2a20f20276c8c808
    - swh:1:ori:33bf251c0937b1394bc2df185779a75ad0bf3d36
    Secret share holders:
    - Alabaster
    - Essun
    - Innon
    - YubiKey serial 4245067 slot 1
    - YubiKey serial 4245067 slot 2
    - YubiKey serial 4245067 slot 3

Options:

``--dump-manifest``
    Show raw manifest in YAML format.

``--show-encrypted-secrets``
    Show encrypted secrets for each share holder. This allows for out of band
    recovery of the shared secret by providing the encrypted payload to the
    secret holder (see also :ref:`recovery-bundle-remote-operations`).

Extracting content stored in a recovery bundle
----------------------------------------------

``swh alter recovery-bundle extract-content`` will extract data from a
Content object stored in a recovery bundle. In order to proceed, this command
requires enough shared secrets to be recovered. Alternatively, the bundle
decryption key can be provided.

See :ref:`recovery-bundle-info` on how to get a list of objects stored in
recovery bundle.

.. code:: console

    $ swh alter recovery-bundle extract-content \
          --output requirements.txt \
          tdn-2023-07-14-01.swh-recovery-bundle \
          swh:1:cnt:3d65be4c62d36aac611260b47555ac9d51cd5515

Options:

``--output PATH`` (required)
    Path of the file that will be written with the extracted content. ``-`` can
    be used to print the content to the standard output.

``--decryption-key AGE_SECRET_KEY``
    Use the given decryption key instead of the bundle shared secrets (see
    :ref:`recovery-bundle-remote-operations`).

``--secret MNEMONIC``
    Known shared secret. May be repeated.

``--identity IDENTITY``
    Path to an *age* identity file holding a secret key. May be repeated.

.. _recovery-bundle-remote-operations:

Operating recovery bundles remotely
-----------------------------------

Operations that require to decrypt objects from recovery bundle all offer a
``--decryption-key`` option. It can be used to directly provide the
age secret key that decrypts objects contained in the bundle.

This option enables remote operations. In the case not all secret share holders
can physically work on the same computer, or if the system having the right
permission to update the Software Heritage archive is only available remotely,
this decryption key can first be recovered in one or more separate steps.

``swh alter recovery-bundle recover-decryption-key`` will help to recover the
secret key protected by the shared secrets. It supports several situations:

- If all secret share holders can work on the same computer,
  then the decryption key can be recovered directly:

  .. code:: console

        $ swh alter recovery-bundle recover-decryption-key \
            --identity age-identity-dpo.txt \
            tdn-2023-07-14-01.swh-recovery-bundle

        🚸 The following secret shares will not be decrypted: CFO

        🔐 Please insert YubiKey serial 4245067 slot 1, YubiKey serial 5229836 slot 1
        or YubiKey serial 5254231 slot 2 and press Enter…

        🔧 Decrypting share using YubiKey serial 4245067 slot 1…
        💭 You might need to tap the right YubiKey when it blinks.

        🔧 Decrypting share using YubiKey serial 5254231 slot 2…
        💭 You might need to tap the right YubiKey when it blinks.

        🔓 Recovered decryption key:
        AGE-SECRET-KEY-15PQHAGKV59TFK9TCCWLQZZ7XVV0FADVX5TSCDWVZSEWZ4L2SMARSJAAR0W

- If secret share holders are distributed, they will first need to
  separately recover their shared secret. For example, for the example
  configuration given above, the DPO would run:

  .. code:: console

        $ swh alter recovery-bundle recover-decryption-key \
            --show-recovered-secrets \
            --identity age-identity-dpo.txt \
            tdn-2023-07-14-01.swh-recovery-bundle

        🔑 Recovered shared secret from DPO:
        [takedown-notice-2023-07-14-01] union echo acrobat easy actress desert decrease
        surprise armed force river insect pencil debut unhappy desktop lungs viral
        sister client ocean wisdom friar year formal knit mild endless breathe benefit
        obesity kidney decrease

        🚸 The following secret shares will not be decrypted: CFO

        🔐 Please insert YubiKey serial 4245067 slot 1, YubiKey serial 5229836 slot 1
        or YubiKey serial 5254231 slot 2 and press Enter…

        [Ctrl+C]

  It is also possible to decrypt the secret without requiring `swh-alter`. One
  can retrieve the encrypted payload of a shared secret holder by running:

  .. code:: console

        $ swh alter recovery-bundle info \
            --show-encrypted-secrets \
            tdn-2023-07-14-01.swh-recovery-bundle
        […]
        - DPO
        -----BEGIN AGE ENCRYPTED FILE-----
        YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBDNkRoR1FtSnNaRENpWTlP
        […]
        -----END AGE ENCRYPTED FILE-----

  After receiving the encrypted payload, the DPO can then the following command
  on their own computer to recover their secret:

  .. code:: console

        $ rage --decrypt --identity age-identity-dpo.txt
        -----BEGIN AGE ENCRYPTED FILE-----
        YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBDNkRoR1FtSnNaRENpWTlP
        […]
        -----END AGE ENCRYPTED FILE-----
        [Ctrl+D]
        [takedown-notice-2023-07-14-01] union echo acrobat easy actress desert decrease
        surprise armed force river insect pencil debut unhappy desktop lungs viral
        sister client ocean wisdom friar year formal knit mild endless breathe benefit
        obesity kidney decrease

  The legal group only requires one secret, so this is enough. Meanwhile, two
  system administrators use their YubiKeys to recover the required amount of
  secrets for their group:

  .. code:: console

        $ swh alter recovery-bundle recover-decryption-key \
            --show-recovered-secrets \
            tdn-2023-07-14-01.swh-recovery-bundle

        🚸 The following secret shares will not be decrypted: DPO, CFO

        🔐 Please insert YubiKey serial 4245067 slot 1, YubiKey serial 5229836 slot 1
        or YubiKey serial 5254231 slot 2 and press Enter…

        🔧 Decrypting share using YubiKey serial 4245067 slot 1…
        💭 You might need to tap the right YubiKey when it blinks.
        🔑 Recovered shared secret from YubiKey serial 4245067 slot 1:
        union echo beard entrance alien photo cage mailman cleanup society petition
        craft script snapshot that step estate watch detailed dryer cause hanger
        deploy calcium idea sack venture bundle training famous endorse permit crowd

        🔧 Decrypting share using YubiKey serial 5254231 slot 2…
        💭 You might need to tap the right YubiKey when it blinks.
        🔑 Recovered shared secret from YubiKey serial 5254231 slot 2:
        union echo beard email anatomy install leader coal window pencil depict either
        kitchen decorate cylinder auction expect beam alien sympathy image failure diminish
        impact round bike mayor ting painting often zero manual enforce

        🔐 Please insert YubiKey serial 5229836 slot 1 and press Enter…

        [Ctrl+C]

  The decryption key can then be recovered by providing these secrets:

  .. code:: console

        $ swh alter recovery-bundle recover-decryption-key \
            --secret "union echo acrobat easy […] crowd" \
            --secret "union echo beard entrance […] crowd" \
            --secret "union echo beard email […] enforce" \
            tdn-2023-07-14-01.swh-recovery-bundle

        🚸 The following secret shares will not be decrypted: DPO, CFO

        🔓 Recovered decryption key:
        AGE-SECRET-KEY-15PQHAGKV59TFK9TCCWLQZZ7XVV0FADVX5TSCDWVZSEWZ4L2SMARSJAAR0W

  .. note::

    The shared secrets should be 33 words long. They have been elided here for clarity.
    All shared secrets should have the same first two words. All shared secrets from
    a given group should also have same first third word.

It is possible to both provide shared secrets on the command line and use
identity files or YubiKeys for the missing ones. This applies to all commands
needing data stored in a bundle. For example:

.. code:: console

    $ swh alter recovery-bundle recover-decryption-key \
          --secret "union echo beard entrance […] crowd" \
          --secret "union echo beard email […] enforce" \
          --identity age-identity-dpo.txt \
          tdn-2023-07-14-01.swh-recovery-bundle

Options for ``swh alter recovery-bundle recover-decryption-key``:

``--secret MNEMONIC``
    Known shared secret. May be repeated.

``--identity IDENTITY``
    Path to an *age* identity file holding a secret key. May be repeated.

``--show-recovered-secrets``
    Show recovered shared secrets from YubiKeys are identity files.

Shared secrets rollover
-----------------------

``swh alter recovery-bundle rollover`` enables to switch existing recovery
bundle to a new secret sharing configuration. First, :ref:`configure the new
organization <cli-config-alter>`. Then, the command can be used as such:

.. code:: console

    $ swh alter recovery-bundle rollover \
          tdn-2023-07-14-01.swh-recovery-bundle \
          tdn-2023-08-15-01.swh-recovery-bundle

In order to proceed, this command requires enough shared secrets to be
recovered. Alternatively, when operating on a single bundle, the decryption key
can be provided. A confirmation will be required before proceeding as the
recovery bundles are updated in place.

Options:

``--decryption-key AGE_SECRET_KEY``
    Use the given decryption key instead of the bundle shared secrets (see
    :ref:`recovery-bundle-remote-operations`). If used, only one recovery bundle
    should be provided at time.

``--secret MNEMONIC``
    Known shared secret. May be repeated.

``--identity IDENTITY``
    Path to an *age* identity file holding a secret key. May be repeated.

.. Sample output: [for reference, it does not appear in the documentation]

    🔐 Please insert YubiKey serial 5229836 slot 1, YubiKey serial 4245067 slot 1 and press Enter…
    🔧 Decrypting share using YubiKey serial 4245067 slot 1…
    💭 You might need to tap the right YubiKey when it blinks.

    🔧 Decrypting share using YubiKey serial 5229836 slot 1…
    💭 You might need to tap the right YubiKey when it blinks.
    New shared secret holders: YubiKey serial 4245067 slot 3, YubiKey serial 4245067 slot 2, Alabaster, YubiKey serial 4245067 slot 1, Innon, Essun
    Shared secrets for test-removal-2023-08-21 have been rolled over.


