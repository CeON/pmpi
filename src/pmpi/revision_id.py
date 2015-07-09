class AbstractRevisionID:
    _id = None
    _revision = None

    @classmethod
    def from_id(cls, id):
        rev = cls()
        rev._id = id
        return rev

    @classmethod
    def from_revision(cls, revision):
        rev = cls()
        rev._id = revision.sha256()
        rev._revision = revision
        return rev

    def __bytes__(self):
        return self._id if self._id is not None else bytes(32)

    def __eq__(self, other):
        return bytes(self) == bytes(other)

    def _get_revision_from_database(self):
        raise NotImplementedError

    def get_id(self):
        return self._id

    def get_revision(self):
        if self._revision is not None:
            return self._revision
        if self._id is not None:
            # return Operation.get(self._id)
            return self._get_revision_from_database()

        return None

    def is_none(self):
        return self._id is None and self._revision is None
