from bsddb3 import db


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
        self.__db[dbname].delete(key)
