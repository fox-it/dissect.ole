from __future__ import annotations


class Error(Exception):
    pass


class InvalidFileError(Error):
    pass


class NotFoundError(Error):
    pass
