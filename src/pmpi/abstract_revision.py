from pmpi.abstract_signed_object import AbstractSignedObject


class AbstractRevision:
    _id = None
    _revision = None

    @classmethod
    def from_id(cls, identifier):
        rev = cls()
        rev._id = identifier
        return rev

    @classmethod
    def from_revision(cls, revision):
        """
        :type revision: AbstractSignedObject
        """
        rev = cls()
        rev._id = revision.hash()
        rev._revision = revision
        return rev

    def __bytes__(self):
        return self._id if self._id is not None else bytes(32)

    def __eq__(self, other):
        return bytes(self) == bytes(other)

    def _get_revision_from_database(self):
        raise NotImplementedError

    @property
    def id(self):
        return self._id

    @property
    def revision(self):
        if self._id is not None and self._revision is None:
            self._revision = self._get_revision_from_database()

        if self._revision is not None:
            return self._revision
        else:
            return None

    def is_none(self):
        return self._id is None and self._revision is None
