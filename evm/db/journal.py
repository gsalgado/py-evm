from typing import Dict, Set  # noqa: F401
import uuid

from evm.db.backends.base import BaseDB
from evm.exceptions import ValidationError


class Journal(object):
    """
    A Journal is an ordered list of checkpoints.  A checkpoint is a dictionary
    of database keys and values.  The values are the "original" value of that
    key at the time the checkpoint was created.

    Checkpoints are referenced by a random uuid4.
    """
    checkpoints = None

    def __init__(self):
        # contains an array of `uuid4` instances
        self.checkpoints = []
        # contains a mapping from all of the `uuid4` in the `checkpoints` array
        # to a set of keys modified since the snapshot was created.
        self.journal_data = {}  # type: Dict[uuid.UUID, Set[bytes]]

    @property
    def latest_id(self):
        """
        Returns the checkpoint_id of the latest checkpoint
        """
        return self.checkpoints[-1]

    @property
    def latest(self) -> Set[bytes]:
        """
        Returns the set of db keys changed since the latest checkpoint.
        """
        return self.journal_data[self.latest_id]

    @latest.setter
    def latest(self, value):
        """
        Setter for updating the *latest* checkpoint.
        """
        self.journal_data[self.latest_id] = value

    def add(self, key: bytes) -> None:
        """
        Adds the given key to the latest checkpoint.
        """
        if not self.checkpoints:
            # If no checkpoints exist we don't need to track history.
            return
        elif key in self.latest:
            # If the key is already in the latest checkpoint we should not
            # overwrite it.
            return
        self.latest.add(key)

    def create_checkpoint(self) -> bytes:
        """
        Creates a new checkpoint.  Checkpoints are referenced by a random uuid4
        to prevent collisions between multiple checkpoints.
        """
        checkpoint_id = uuid.uuid4()
        self.checkpoints.append(checkpoint_id)
        self.journal_data[checkpoint_id] = set()
        return checkpoint_id

    def pop_checkpoint(self, checkpoint_id: bytes) -> Set[bytes]:
        """
        Returns all changes from the given checkpoint.  This includes all of
        the changes from any subsequent checkpoints, giving precedence to
        earlier checkpoints.
        """
        idx = self.checkpoints.index(checkpoint_id)

        # update the checkpoint list
        checkpoint_ids = self.checkpoints[idx:]
        self.checkpoints = self.checkpoints[:idx]

        # we pull all of the checkpoints *after* the checkpoint we are
        # reverting to and collapse them to a single set of keys that need to
        # be reverted.
        revert_data = set()
        revert_data.update(*(
            self.journal_data.pop(c_id)
            for c_id in checkpoint_ids))

        return revert_data

    def commit_checkpoint(self, checkpoint_id):
        """
        Collapses all changes for the given checkpoint into the previous
        checkpoint if it exists.
        """
        changes_to_merge = self.pop_checkpoint(checkpoint_id)
        if self.checkpoints:
            # we only have to merge the changes into the latest checkpoint if
            # there is one.
            self.latest = changes_to_merge.union(self.latest)

    def __contains__(self, value):
        return value in self.journal_data


class JournalDB(BaseDB):
    """
    A wrapper around the basic DB objects that keeps a journal of all changes.
    Each time a snapshot is taken, the underlying journal creates a new
    checkpoint.  The journal then keeps track of the original value for any
    keys changed.  Reverting to a checkpoint involves merging the original key
    data from any subsequent checkpoints into the given checkpoint giving
    precedence earlier checkpoints.  Then the keys from this merged data set
    are reset to their original values.

    The added memory footprint for a JournalDB is one key/value stored per
    database key which is changed.  Subsequent changes to the same key within
    the same checkpoint will not increase the journal size since we only need
    to track the original value for any given key within any given checkpoint.
    """
    wrapped_db = None
    journal = None
    snapshots = None

    def __init__(self, wrapped_db):
        self.wrapped_db = wrapped_db
        self.journal = Journal()
        self.snapshots = {}

    def get(self, key):
        return self.wrapped_db.get(key)

    def set(self, key, value):
        """
        - replacing an existing value
        - setting a value that does not exist
        """
        self.journal.add(key)

        return self.wrapped_db.set(key, value)

    def exists(self, key):
        return self.wrapped_db.exists(key)

    def delete(self, key):
        self.journal.add(key)
        return self.wrapped_db.delete(key)

    #
    # Snapshot API
    #
    def _validate_checkpoint(self, checkpoint):
        """
        Checks to be sure the checkpoint is known by the journal
        """
        if checkpoint not in self.journal:
            raise ValidationError("Checkpoint not found in journal: {0}".format(
                str(checkpoint)
            ))

    def snapshot(self):
        """
        Takes a snapshot of the database by creating a checkpoint.
        """
        checkpoint_id = self.journal.create_checkpoint()
        self.snapshots[checkpoint_id] = self.wrapped_db.snapshot()
        return checkpoint_id

    def revert(self, checkpoint):
        """
        Reverts the database back to the checkpoint.
        """
        self._validate_checkpoint(checkpoint)

        snapshot = self.snapshots.pop(checkpoint)
        for key in self.journal.pop_checkpoint(checkpoint):
            value = snapshot.get(key)
            if value is None:
                self.wrapped_db.delete(key)
            else:
                self.wrapped_db.set(key, value)
        # XXX: Quick hack to handle MemoryDB's snapshots, which are dict() instances
        if isinstance(snapshot, dict):
            snapshot.clear()
        else:
            snapshot.close()

    def commit(self, checkpoint):
        """
        Commits a given checkpoint.
        """
        self._validate_checkpoint(checkpoint)
        snapshot = self.snapshots.pop(checkpoint)
        # XXX: Quick hack to handle MemoryDB's snapshots, which are dict() instances
        if isinstance(snapshot, dict):
            snapshot.clear()
        else:
            snapshot.close()
        self.journal.commit_checkpoint(checkpoint)

    def clear(self):
        """
        Cleare the entire journal.
        """
        self.journal = Journal()

    #
    # Dictionary API
    #
    def __getitem__(self, key):
        return self.get(key)

    def __setitem__(self, key, value):
        return self.set(key, value)

    def __delitem__(self, key):
        return self.delete(key)

    def __contains__(self, key):
        return self.exists(key)
