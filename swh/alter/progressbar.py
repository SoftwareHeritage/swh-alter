# Copyright (C) 2024 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import logging
from types import TracebackType
from typing import (
    Callable,
    Generic,
    Iterable,
    Iterator,
    Optional,
    Protocol,
    TypeVar,
    cast,
)

V = TypeVar("V")

logger = logging.getLogger(__name__)


class ProgressBar(Protocol, Generic[V]):
    """Interface for the ProgressBar object, mimicking click’s."""

    def __enter__(self) -> "ProgressBar[V]":
        ...

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_value: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        ...

    def __iter__(self) -> Iterator[V]:
        ...

    def __next__(self) -> V:
        ...

    def update(self, n_steps: int) -> None:
        ...


class NoProgressBar(Generic[V]):
    """A ProgressBar implementation that displays nothing.

    Typically returned by :py:func:`no_progressbar`.
    """

    def __init__(self, iterable: Iterable[V], label: Optional[str] = None):
        self.iter = iter(iterable)
        if label:
            logger.info(label)

    def __enter__(self) -> "NoProgressBar[V]":
        return self

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_value: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        pass

    def __iter__(self) -> Iterator[V]:
        yield from self.iter

    def __next__(self) -> V:
        return next(iter(self))

    def update(self, n_steps: int) -> None:
        pass


class ProgressBarInit(Protocol):
    """A protocol abstracting the ``click.progressbar()`` function."""

    def __call__(
        self,
        iterable: Optional[Iterable[V]] = None,
        length: Optional[int] = None,
        label: Optional[str] = None,
        show_eta: bool = True,
        show_pos: bool = False,
        show_percent: Optional[bool] = None,
        item_show_func: Optional[Callable[[V], str]] = None,
    ) -> ProgressBar[V]:
        ...


def no_progressbar(
    iterable: Optional[Iterable[V]] = None,
    length: Optional[int] = None,
    label: Optional[str] = None,
    show_eta: bool = True,
    show_pos: bool = False,
    show_percent: Optional[bool] = None,
    item_show_func: Optional[Callable[[V], str]] = None,
) -> ProgressBar[V]:
    """Returns a :py:class:`ProgressBar` that displays nothing.

    This function allows to use the same code structure wherever a progressbar
    has to be displayed or not."""

    if iterable is not None:
        return NoProgressBar(iterable, label=label)
    elif length is not None:
        # Without this `cast()`, mypy thinks we return a `ProgressBar[int]`.
        # While true, it only happens in the case that V has not been specified,
        # so we are in our rights to state that V=int this time being.
        return NoProgressBar(cast(Iterable[V], iter(range(0, length))), label=label)
    else:
        raise ValueError("Either `iterable or `length` must be specified.")
