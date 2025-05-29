import sqlite3
from models.Reviews import Review


class ORM:
    def __init__(self):
        self.db = sqlite3.connect("db.db", check_same_thread=False)
        self.cursor = self.db.cursor()
        self.query_check_table = "SELECT name FROM sqlite_master WHERE type='table' AND name='{table_name}';"

    def query(self, query):
        return self.cursor.execute(query)
    
    def create_table(self, model):
        fields = ""
        for field_name, field_type in model.fields.items():
            temp = f"{field_name} {field_type},"
            fields += temp
        fields = fields[0:-1]
        query_create = f"CREATE TABLE {model.table_name} ({fields});"
        self.query(query_create)

    def get_all(self, model):
        if self.query(self.query_check_table.format(table_name=model.table_name)).fetchall() == []:
            self.create_table(model)
        query_select = f"SELECT * FROM {model.table_name}"
        res = []
        for row in self.query(query_select).fetchall():
            temp = {}
            i = 0
            for name in model.fields.keys():
                temp[name] = row[i]
                i += 1
            res.append(temp)
        return res
    
    def insert(self, model, data):
        fields_name = ""
        data_str = ""
        data_list = []
        for name in model.fields.keys():
            fields_name += f"{name},"
            data_str += "?,"
            data_list.append(data[name])
            
        fields_name = fields_name[0:-1]
        data_str = data_str[0:-1]
        insert_query = f"INSERT INTO {model.table_name} ({fields_name}) VALUES ({data_str});"
        self.cursor.execute(insert_query, data_list)
        self.db.commit()
        return self.get_all(model)