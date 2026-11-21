"""Refuse ordinary website ownership where a Windows generation owner is retained.

This is a positive ownership guard, not discovery of every possible installer.
It reads directory-entry metadata only; retained owner records are never opened
or removed. The managed diagnostic resolves those records under its own lease.
"""
from pathlib import Path
import re
import stat


REFUSAL = ("Managed Windows generation ownership is retained for this project; "
           "use selfhost_windows_website.py --check-only with its selection configuration. "
           "Ordinary website deployment cannot modify this owner.")
MARKERS = (
    "generation-selection", "renewal.lock", "recovery-in-progress.json",
    "recovery-preparation.json", "renewal-staging.json", "model-repair.json",
    "selection-continuation.json", "product-transition.json",
)


def require_ordinary_owner(project: str, directories: list[Path]) -> None:
    """Check invocation ancestors, including a generation's retained root.

    Any matching entry blocks the ordinary owner, including an incomplete or
    dangling entry. A metadata error is not evidence that the owner is absent.
    No recursive search, private file read, or directory creation occurs here.
    """
    if not isinstance(project, str) or re.fullmatch(r"[a-z0-9][a-z0-9_-]*", project) is None:
        raise ValueError("invalid Compose project name")
    checked = set()
    for directory in directories:
        directory = Path(directory).absolute()
        # Inspect ancestors before traversing children: a junction can hide a
        # managed root from lexical parent scanning even when the final file
        # itself is ordinary. Never resolve or follow that alias for admission.
        for root in reversed((directory, *directory.parents)):
            if root in checked:
                continue
            checked.add(root)
            try:
                info = root.lstat()
            except OSError:
                raise ValueError("Website owner metadata is unavailable; no ordinary deployment is allowed") from None
            if (stat.S_ISLNK(info.st_mode)
                    or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
                raise ValueError("Website owner paths must not contain reparse points or symlink ancestors")
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError("Website owner paths must be existing ordinary directories")
            for suffix in MARKERS:
                try:
                    (root / ("." + project + "." + suffix)).lstat()
                except FileNotFoundError:
                    continue
                except OSError:
                    raise ValueError("Website owner metadata is unavailable; no ordinary deployment is allowed") from None
                raise ValueError(REFUSAL)
