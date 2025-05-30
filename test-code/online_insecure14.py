import mysql.connector
from tkinter import *
from tkinter import ttk

# Connect to the MySQL database
cnx = mysql.connector.connect(user='root', password='airpods4sale', database='NBA')
cursor = cnx.cursor()

# SQL query to fetch player names
query = "SELECT P_NAME FROM PLAYER"
cursor.execute(query)

# Function to fetch and display player names in the GUI
def display_names():
    names = [name[0] for name in cursor.fetchall()]  # Fetch all names from the cursor
    for name in names:
        names_listbox.insert(END, name)  # Insert names into the Listbox widget

# Create the main GUI window
root = Tk()
root.title("NBA Player Names")

# Create and configure the main frame
frm = ttk.Frame(root, padding=10)
frm.grid()

# Add a label for the Listbox
ttk.Label(frm, text="NBA Player Names:").grid(column=0, row=0, padx=5, pady=5)

# Add a Listbox widget to display names
names_listbox = Listbox(frm, height=15, width=30)
names_listbox.grid(column=0, row=1, padx=5, pady=5)

# Add a button to quit the application
ttk.Button(frm, text="Quit", command=root.destroy).grid(column=0, row=2, padx=5, pady=5)

# Call the function to populate the Listbox with player names
display_names()

# Run the GUI event loop
root.mainloop()

# Close the database connection
cursor.close()
cnx.close()