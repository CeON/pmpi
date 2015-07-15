from bsddb3 import db
from src.pmpi.exceptions import ObjectDoesNotExist

__database = None


class Database:
    IDENTIFIERS = 'identifiers'
    OPERATIONS = 'operations'
    BLOCKS = 'blocks'
    DBNAMES = {IDENTIFIERS, OPERATIONS, BLOCKS}

    def __init__(self, filename):
        self.__db = {}
        for dbname in self.DBNAMES:
            self.__db[dbname] = db.DB()
            self.__db[dbname].open(filename, dbname=dbname, dbtype=db.DB_HASH, flags=db.DB_CREATE)

    def length(self, dbname):
        return len(self.__db[dbname])

    def keys(self, dbname):
        return self.__db[dbname].keys()

    def get(self, dbname, key):
        return self.__db[dbname][key]

    def put(self, dbname, key, data):
        self.__db[dbname][key] = data

    def delete(self, dbname, key):
        if key in self.__db[dbname]:
            self.__db[dbname].delete(key)
        else:
            raise ObjectDoesNotExist

    def close(self):
        for dbname in self.DBNAMES:
            self.__db[dbname].close()

    class InitialisationError(Exception):
        pass


def initialise_database(filename):
    global __database

    if __database is not None:  # TODO is it necessary?
        close_database()
    __database = Database(filename)


def close_database():
    global __database

    if __database is not None:
        __database.close()
        __database = None


def database_required(function):
    global __database

    def wrapper(cls, *args):
        if __database is not None:
            return function(cls, __database, *args)
        else:
            raise Database.InitialisationError("initialise database first")

    return wrapper
