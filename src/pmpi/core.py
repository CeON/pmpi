from bsddb3 import db
from pmpi.exceptions import ObjectDoesNotExist

import pmpi.blockchain

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

        self.__blockchain = None

    @property
    def blockchain(self):
        return self.__blockchain

    def initialise_blockchain(self):
        if self.__blockchain is None:
            self.__blockchain = pmpi.blockchain.BlockChain()
        else:
            raise self.InitialisationError("BlockChain has been already initialised")

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

    if __database is not None:
        raise Database.InitialisationError("close opened database first")
    __database = Database(filename)
    __database.initialise_blockchain()


def close_database():
    global __database

    if __database is not None:
        __database.close()
        __database = None
    else:
        raise Database.InitialisationError("there is no database to close")


def database_required(function):
    global __database

    def wrapper(cls, *args):
        if __database is not None:
            return function(cls, __database, *args)
        else:
            raise Database.InitialisationError("initialise database first")

    return wrapper
