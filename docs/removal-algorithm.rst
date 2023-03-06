:html_theme.sidebar_secondary.remove:

.. _alter_removal_algorithm:

Removal algorithm
=================

When taking down an origin that should not have been archived, we want to remove
all the objects that have been added as a result of archiving this origin,
without affecting objects that have been referenced from other origins. For
example, we would not want to remove the content containing the text of the GPL
v3 (which is shared by many origins), or other contents or directories included
verbatim from other projects.

.. note::

   Objects in Software Heritage have an intrinsic identifier in the form of
   a :ref:`SHWID <swhids>`. This means that it is not possible to remove a
   single directory entry without changing the identifier for the directory.
   Which in turn would change the identifier for the source revision… which
   would change the identifier of one or more releases, and the relevant
   snapshots then.

   Therefore, we only support removal of origins and snapshots. In the future,
   adding the `ability to remove content
   <https://gitlab.softwareheritage.org/swh/devel/swh-alter/-/issues/8>`_ would
   be possible with the current object model. Removing other objects would need
   a serious amount of preliminary work to `handle missing DAG nodes
   <https://gitlab.softwareheritage.org/swh/devel/swh-model/-/issues/1957>`_.

Listing objects to be removed
-----------------------------

The algorithm that lists the objects that can be removed in response to a
takedown request works in two stages:

1. Get the list of candidates for removal, which is a complete, up-to-date
   subgraph of the Software Heritage archive rooted at the requested object.
2. For all the candidates for removal, check if they are referenced by any other
   object in the archive.

Getting the candidates for removal
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

We first use :ref:`swh-graph` to construct a subgraph using a breadth-first
traversal starting from the given SWHID.

If we have not found the SWHID through :ref:`swh-graph`, or if we are starting
from an origin, we complete the list of candidates using :ref:`swh-storage`.

.. note::
   Retrieving data from :ref:`swh-graph` is an optimization. It is fast but its content
   it only accurate to the point when the latest export was generated. The SWHID
   we are looking for could have been added later. Or we are looking at creating a
   subgraph from an origin and more recent visits might have been made.

This step of the algorithm is implemented in the module
:py:mod:`swh.alter.inventory`.


Marking candidates used elsewhere
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When removing objects, we must be careful not to create dangling references.
This means we can only remove objects if they are not currently referenced
elsewhere. References to an object take the form of inbound edges in our
directed graph.

But it is not enough to just skip a node because it has inbound edges. If we are
trying to remove a source repository, the exact same file will likely be present
in many revisions. Therefore, we need to be sure that the same content is only
present in this particular project. In graph terminology: we can only remove a
node if all its inbound edges are coming from nodes present in our subgraph,
and there it at least one such edge.

To do that, we traverse our subgraph, For each node, we look at their inbound
edges through :ref:`swh-graph` and then :ref:`swh-storage`. If any of them
is *not* in the subgraph, that means the object must not be removed.

We can avoid unneeded lookups by traversing our subgraph in topological order
(looking at all releases before all revisions before all directories before all
contents). Then, when examining a node, we can look at its predecessors. If any
of them must be kept, then we know it must be kept as well.

Example of removing an origin
-----------------------------

.. raw:: html

   <style>
     figure img, .scbs-carousel-item img {
       height: calc(99vh - 29ex - var(--pst-header-height));
     }
     .scbs-carousel-caption {
       min-height: 29ex;
       padding-left: 1.5em;
       padding-right: 1.5em;
     }
     .scbs-carousel-caption h5 {
       margin-top: 1.05rem;
     }
   </style>

To create this example, we will re-use the dataset offered in the
:py:mod:`swh.graph.example_dataset` module.

.. figure:: images/dataset.svg
   :alt: The dataset used for our examples

   A dataset used to demonstrate how the algorithm works

   It shows an initial origin that has then been forked, all their snapshots,
   releases, revisions and contents. Objects with a bold background are old
   enough to be present in the export available through the ``swh-graph`` API.
   The others are only available through ``swh-storage``.

Inventory candidates
^^^^^^^^^^^^^^^^^^^^

Lets imagine that we receive a legitimate takedown requests for the forked
origin. We start our inventory by querying :ref:`swh-graph` and
:ref:`swh-storage` in turn until all objects pertaining to this origin have
been found. As most of the additions to the forked origin are recent, they are
not present in ``swh-graph``.  Many round-trips to ``swh-storage`` are
therefore needed.

.. carousel::
   :data-bs-interval: false
   :show_controls:
   :show_dark:
   :show_fade:
   :show_captions_below:

   .. figure:: images/inventory-01.svg

      Inventory step 1 (after looking up graph)

      The origin was not present when the export was made for ``swh-graph``, so
      nothing has been be retrieved from our query.

   .. figure:: images/inventory-02.svg

      Inventory step 2 (after looking up storage)

      We retrieved a snapshot from ``swh-storage`` which still needs to be
      looked upon.

   .. figure:: images/inventory-03.svg

      Inventory step 3 (after looking up graph)

      The snapshot was not present when the export was made for ``swh-graph``, so
      nothing has been be retrieved from our query.

   .. figure:: images/inventory-04.svg

      Inventory step 4 (after looking up storage)

      From ``swh-storage``, we learn about two releases and one revision.

   .. figure:: images/inventory-05.svg

      Inventory step 5 (after looking up graph)

      The oldest release was known to ``swh-graph``, so we were able to
      learn a whole part of our subgraph at once. Because objects in the
      archive are immutable–their identifier being based on their content–we
      know that we have learned about all their references. This is visible
      with the revision we initially learn from the snapshot, and for which no
      further lookups will be necessary.

      A query for the other release was also made, but with no results.

   .. figure:: images/inventory-06.svg

      Inventory step 6 (after looking up storage)

      For the newer release, ``swh-storage`` told us about another revision.

   .. figure:: images/inventory-07.svg

      Inventory step 7 (after looking up graph)

      This newer revision was not know by ``swh-graph``, so nothing was added.

   .. figure:: images/inventory-08.svg

      Inventory step 8 (after looking up storage)

      ``swh-storage`` provides us the whole revision log starting from this
      newer revision. Two directories now need to be looked up.

   .. figure:: images/inventory-09.svg

      Inventory step 9 (after looking up graph)

      None of these directories are known to ``swh-graph``.

   .. figure:: images/inventory-10.svg

      Inventory step 10 (after looking up storage)

      From ``swh-storage``, we have learned about two content objects and
      another directory. Content objects do not reference anything, so
      no further look ups will be necessary.

   .. figure:: images/inventory-11.svg

      Inventory step 11 (after looking up graph)

      The incomplete directory is not known to ``swh-graph``.

   .. figure:: images/inventory-12.svg

      Inventory step 12 (after looking up storage)

      ``swh-storage`` provided us knowledge about another content object.
      All objects are considered *complete*. The inventory is now over.

Mark removable
^^^^^^^^^^^^^^

Now we can look for any references coming from outside our inventory, and mark
the relevant objects as removable or unremovable if they are any.

.. figure:: images/mark.svg
   :alt: A representation of our subgraph after tagging which objects can be
         removed and which need to be kept. We can see one reference pointing
         to an object from outside the inventory subgraph.

   Our subgraph after looking up which nodes can safely be removed

   In red, nodes that have been deemed removable. In white, those that must
   be kept. They start by ``swh:rel:…010`` for which a reference outside our
   inventory has been found.
