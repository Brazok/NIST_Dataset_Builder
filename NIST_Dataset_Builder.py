#!/usr/bin/python3

import json
import tkinter as tk
from tkinter import Canvas, ttk
import requests
import zipfile
from tqdm import tqdm
import os
import random

CRITERIAS_FILE_PATH = "./criterias_data.json"
OUTPUT_PATH = "./_output/"

def getCriteriasFromAPI():
    print("~> getCriteriasFromAPI()")
    url = "https://samate.nist.gov/SARD/api/search/criteria"
    response = requests.get(url)
    return response.json()

def getAllCriteriaTypes(_criterias : dict):
    print("~> getAllCriteriaTypes()")
    arr = []
    for elm in _criterias:
        if elm.get('type'):
            arr.append(elm['type'])
    return arr

def getCriteriasFromFile():
    print("~> getCriteriasFromFile()")
    try:
        with open(CRITERIAS_FILE_PATH, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Failed to load JSON from file: {e}")
        try:
            return upadteCriteriasFile()
        except Exception as e:
            print(f"Failed to update criterias : {e}")
            return None


def upadteCriteriasFile():
    print("~> upadteCriteriasFile()")
    criterias = getCriteriasFromAPI()
    save_json_to_path(criterias, CRITERIAS_FILE_PATH)
    return criterias

def getCriteriaByType(_criterias : dict, _type : str):
    print("~> getCriteriaFromType()")
    arr = []
    for elm in _criterias:
        if elm.get('type') == _type:
            return (elm['items'])
    return arr
        
def save_json_to_path(data, file_path):
    print("~> save_json_data()")
    try:
        with open(file_path, "w") as f:
            json.dump(data, f)
    except Exception as e:
        print(f"Failed to save data: {e}")

def getFileListFromAPI(_params : dict, _limit : str, _page : str):
    print("~> getFileListFromAPI()")
    # print(_params, _limit, _page)
    base_url = "https://samate.nist.gov/SARD/api/test-cases/search?"
    criteria = ""
    for elm in _params:
        if not elm == _params[0]:
            criteria += "&"
        if elm['value'] == "None":
            continue
        if elm['nom'] == "flaw":
            criteria += elm['nom'] + "%5B%5D=" + elm['value'].split(" : ")[0]
        else:
            criteria += elm['nom'] + "%5B%5D=" + elm['value']
    url = base_url + criteria + "&page=" + _page + "&limit=" + _limit
    response = requests.get(url)
    return response.json()

def download_file(_name, _ext, _download_link):
    print("~> download_file()")
    print(f"Downloading {_name}{_ext} / {_download_link}")

    if not os.path.exists(OUTPUT_PATH):
        os.makedirs(OUTPUT_PATH)

    file_name = OUTPUT_PATH + _name + _ext
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36'}  # Add your headers here
    response = requests.get(_download_link, stream=True, headers=headers)

    total_size_in_bytes= int(response.headers.get('content-length', 0))
    block_size = 1024 #1 Kibibyte
    progress_bar = tqdm(total=total_size_in_bytes, unit='iB', unit_scale=True)

    with open(file_name, 'wb') as file:
        for data in response.iter_content(block_size):
            progress_bar.update(len(data))
            file.write(data)
    progress_bar.close()

    if total_size_in_bytes != 0 and progress_bar.n != total_size_in_bytes:
        print("ERROR, something went wrong")

def unzip_file(_name:str):
    print("~> unzip_file()")
    print(f"Unzipping {_name}.zip")
    file_name = OUTPUT_PATH + _name + ".zip"
    with zipfile.ZipFile(file_name, 'r') as zip_ref:
        zip_ref.extractall(OUTPUT_PATH + _name)
    os.remove(file_name)

def window():
    def on_combobox_changed(event):
        print("~~> on_combobox_changed()")
        arr = []
        for name, combobox in comboboxes.items():
            arr.append({ "nom": name, "value": combobox.get() })
        result = getFileListFromAPI(arr, comboLimit.get(), page_spin.get())

        mystr.set(result['total'])
        dlFiles_spin.config(to=result['total'])
        page_spin.config(to=result['pageCount'])

        # Clear the frame
        for widget in data_frame.winfo_children():
            widget.destroy()

        # Add labels to the frame for each file
        for file in result['testCases']:
            label = tk.Label(data_frame, text=file['identifier'])
            label.pack()

    def on_download():
        print("~~> on_download()")
        arr = []
        for name, combobox in comboboxes.items():
            arr.append({ "nom": name, "value": combobox.get() })
        print(isRandom.get())
        result = getFileListFromAPI(arr, comboLimit.get(), page_spin.get())
        if isRandom.get() == 0:
            print("Not Random")
            testCases = result['testCases']
            count = 0
            for file in testCases:
                if count == int(dlFiles_spin.get()):
                    break
                download_file(file['identifier'], ".zip", file['download'])
                unzip_file(file['identifier'])
                count += 1
        else:
            print("Random")
            total = result['total']
            pageCount = result['pageCount']
            count = 0

            while True:
                if count == int(dlFiles_spin.get()):
                    break   
                random_page = random.randint(1, pageCount)
                result = getFileListFromAPI(arr, comboLimit.get(), str(random_page))
                testCases = result['testCases']
                random_file = random.randint(0, len(testCases)-1)   
                file = testCases[random_file]
                download_file(file['identifier'], ".zip", file['download'])
                unzip_file(file['identifier'])
                count += 1



    print("~> window()")
    root = tk.Tk()
    root.geometry("1100x600")  
    root.title("NIST Dataset Builder")
    w, h = root.winfo_screenwidth(), root.winfo_screenheight()
    # root.geometry("%dx%d+0+0" % (w, h))

    # Create a combobox
    graphic = []
    criteriasData = getCriteriasFromFile()
    allcriterias = getAllCriteriaTypes(criteriasData)
    column = 0
    row = 0
    comboboxes = {}  # Store references to all comboboxes
    for criteria in allcriterias:
        criteriaList = getCriteriaByType(criteriasData, criteria)
        values = []
        for item in criteriaList:
            if item.get('description'):
                values.append(item['value'] + " : " + item['description'])
            elif item.get('value'):
                values.append(item['value']) 

        if column == 4:
            column = 0
            row += 3

        label = tk.Label(root, text=criteria)
        label.grid(row=row, column=column)  # Use grid instead of pack
        combobox = ttk.Combobox(root, values=values, name=criteria)
        combobox.set("None") 
        combobox.grid(row=row+2, column=column)  # Use grid instead of pack
        combobox.bind("<<ComboboxSelected>>", on_combobox_changed)  # Bind the event to the function
        comboboxes[criteria] = combobox  # Store a reference to the combobox
        # separator = ttk.Separator(root, orient='horizontal')
        # separator.grid(row=row+3, column=column, sticky="ew", pady=7)
        column+=1
        # row += 4

    

    column = 1
    row += 3
    # Create a label - Limit
    limit_label = tk.Label(root, text="Limit")
    limit_label.grid(row=row, column=column)  # Use grid instead of pack
    comboLimit = ttk.Combobox(values = ["10", "25", "50","75", "100"], name="limit")
    comboLimit.grid(row=row+1, column=column)  # Use grid instead of pack
    comboLimit.set(10)
    comboLimit.bind("<<ComboboxSelected>>", on_combobox_changed)  # Bind the event to the function

    # Create a label - Page
    column += 1
    page_label = tk.Label(root, text="Page")
    page_label.grid(row=row, column=column)  # Use grid instead of pack

    page_spin = tk.Spinbox(root, from_=1, to=1, increment=1, name="page")
    page_spin.grid(row=row+1, column=column)  # Use grid instead of pack
    page_spin.bind("<ButtonRelease>", on_combobox_changed)  # Bind the event to the function

    # Create a label - Files available  
    column += 1 
    files_available_label = tk.Label(root, text="Files available : ")
    files_available_label.grid(row=row, column=column)  # Use grid instead of pack
    mystr = tk.StringVar()
    entry = tk.Entry(textvariable=mystr,state="readonly")
    mystr.set("0")
    entry.grid(row=row+1, column=column)
    row += 3

    row += 2
    column = 0
    # Create a frame for the data
    data_frame = tk.Frame(root, bd=2, relief="groove")
    data_frame.grid(row=row, column=column, columnspan=4, rowspan=9 ,sticky="nsew")

    # Create a label - Downloader
    column = 5
    page_label = tk.Label(root, text="Downloader")
    page_label.grid(row=row, column=column)  # Use grid instead of pack

    row += 1
    dlFiles_label = tk.Label(root, text="Number of files wanted")
    dlFiles_label.grid(row=row, column=column)  # Use grid instead of pack

    row += 1
    dlFiles_spin = tk.Spinbox(root, from_=1, to=1, increment=1, name="dlFiles", )
    dlFiles_spin.grid(row=row, column=column)  # Use grid instead of pack

    # Create a button - Random
    row += 1
    isRandom = tk.IntVar()
    random_bouton = tk.Checkbutton(root, text="Random", variable=isRandom, name="random")
    random_bouton.grid(row=row, column=column)  # Use grid instead of pack

    # Create a button - Download
    row += 1
    download_button = tk.Button(root, text="Download", command=on_download)
    download_button.grid(row=row, column=column)  # Use grid instead of pack


    root.mainloop()



if __name__ == "__main__":
    print("~> __main__()")
    window()
