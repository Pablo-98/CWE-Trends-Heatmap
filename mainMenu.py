import tkinter as tk
from tkinter import messagebox

def start_overall():
    messagebox.showinfo("Start", "Program starting... (placeholder)")

def start_specific_year():
    messagebox.showinfo("Specific Year", "What year would you like to view?")
    year = tk.simpledialog.askinteger("Input", "Enter year:")
    if year:
        messagebox.showinfo("Year Selected", f"You selected year: {year}") #formated string 


def start_cwe_analysis():
    messagebox.showinfo("CWE Analysis", "Which CWE would you like to analyze?")
    cwe_id = tk.simpledialog.askstring("Input", "Enter CWE ID:")
    if cwe_id:
        messagebox.showinfo("CWE Selected", f"You selected CWE: {cwe_id}") #formatted string 

def exit_program():f
    root.destroy()


root = tk.Tk()
root.title("CWE heat map")
root.geometry("500x500") # set to a size of 500x500 pixels because 500 is a nice round number :)

title_label = tk.Label(root, text="MAIN MENU", font=("Arial", 18))
title_label.pack(pady=20)

btn_Overall = tk.Button(root, text="see overall trends", font=("Arial", 12), width=18, command=start_overall)

btn_viewYear = tk.Button(root, text="View trends for a specific year", font=("Arial", 12), width=18, command=start_specific_year)

btn_CWEAnalysis = tk.Button(root, text="CWE Analysis", font=("Arial", 12), width=18, command=start_cwe_analysis)

btn_exit = tk.Button(root, text="Exit", font=("Arial", 12), width=18, command=exit_program)


# Pack buttons
# 5 pixel padding 
btn_Overall.pack(pady=5) 

btn_viewYear.pack(pady=5) 

btn_CWEAnalysis.pack(pady=5)

btn_exit.pack(pady=5)

root.mainloop()
