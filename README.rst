Software Heritage - Archive altering facilities
===============================================

It happens for Software Heritage to record content that either should not
have been archived or should no longer be archived. ``swh-alter`` holds
the tools necessary to prune or make inaccessible content from Software
Heritage archive.

Usage
-----

First, create a configuration file, for example in ``~/.config/swh/alter.yml``, like the following:

.. code:: yaml

    storage:
      cls: postgresql
      db: "service=…"
      objstorage:
        cls: memory

    graph:
      cls: remote
      url: "http://granet.internal.softwareheritage.org:5009"

Then, the following command line will print a list of objects that can be
safely removed from the archive to take down the given origins:

.. code:: console

    $ SWH_CONFIG_FILENAME=~/config/swh.alter.yml \
      swh alter remove --dry-run \
          https://gitlab.softwareheritage.org/swh/devel/swh-alter.git \
          https://gitlab.softwareheritage.org/swh/devel/swh-py-template.git

Only ``-dry-run`` is supported currently. Implementing actual removal is still
pending.
