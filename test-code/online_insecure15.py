import sqlite3


def query_db(database, query):
    connection = sqlite3.connect(database)
    cursor = connection.cursor()
    cursor.execute(query)
    results = cursor.fetchall()
    column_names = [description[0] for description in cursor.description]
    connection.close()
    return column_names, results


def format_table(column_names, data):
    markdown_table = "| ID | " + " | ".join(column_names) + " |\n"
    markdown_table += "| --- | " + " | ".join(["---"] * len(column_names)) + " |\n"

    for index, row in enumerate(data, start=1):
        formatted_row = [str(item).replace('\n', ' ').replace('|', '\\|') for item in row]
        markdown_table += f"| {index} | " + " | ".join(formatted_row) + " |\n"

    return markdown_table


def save_to_file(markdown_table):
    with open("db_data.md", "w", encoding='utf-8') as f:
        f.write(markdown_table)


database = "yunsuo_pf_test/yunsuo_cis_baseline_scan_items.db"
query = "SELECT cn_desc, is_passed_check FROM items"

column_names, data = query_db(database, query)
markdown_table = format_table(column_names, data)
save_to_file(markdown_table)