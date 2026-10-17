"""One-time container-local import of an actual ledger and protected secret staging.

Run only in a short-lived administrative container with the explicit volume mounts
in the deployment guide. Never mount these paths into the agent. Existing ledgers
and changed secrets are never overwritten by this initializer.
"""
import os
from pathlib import Path
import sqlite3


def copy_once(source: Path,destination: Path) -> None:
    """Copy actual protected material with exclusive creation and container UID ownership."""
    raw=source.read_bytes()
    if destination.exists():
        if destination.read_bytes()!=raw:
            raise ValueError('EXISTING_VOLUME_CONTENT_DIFFERS')
        return
    fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(raw)
    os.chown(destination,10001,10001)


def main() -> None:
    """Initialize mounted named volumes without resetting any existing application state."""
    source=Path('/import');ledger=Path('/data/intentlock.db')
    if ledger.exists():
        raise SystemExit('LEDGER_ALREADY_EXISTS: refusing to reset live state.')
    with sqlite3.connect((source/'ledger.sqlite').as_uri()+'?mode=ro',uri=True) as connection:
        if connection.execute('PRAGMA integrity_check').fetchone()!=('ok',):
            raise ValueError('INVALID_SOURCE_LEDGER')
    for name,target in (('gateway',Path('/gateway-secrets')),('executor',Path('/executor-secrets'))):
        target.mkdir(parents=True,exist_ok=True)
        os.chown(target,10001,10001);target.chmod(0o700)
        for path in (source/name).iterdir():
            if not path.is_file() or path.is_symlink():
                raise ValueError('REGULAR_STAGED_SECRET_REQUIRED')
            copy_once(path,target/path.name)
    data=ledger.parent;data.mkdir(parents=True,exist_ok=True);os.chown(data,10001,10001);data.chmod(0o700)
    copy_once(source/'ledger.sqlite',ledger)
    print('Actual ledger and isolated key volumes initialized; no business records created.')


if __name__=='__main__':
    main()
