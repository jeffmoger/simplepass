import os
import string
import secrets
import datetime
import base64
import getpass
import pickle
import json
import csv

import pyperclip
from passlib.hash import pbkdf2_sha256 as p_hash
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


dir_ = os.path.expanduser('~') + '/SimplePass/'
dir_import = dir_ + 'import/'
dir_export = dir_ + 'export/'
dir_store = dir_ + 'store/'


def create_master():
    master = input("    Create a Master password: ")
    hashpass = p_hash.hash(master)
    fh = open(dir_ + 'hash', 'w', encoding='utf-8')
    fh.write(hashpass)
    fh.close()


def getkey(master):
    password = master.encode()
    salt = b'EC6873C47AD2F3FABCCC62AF564996F3F84ECD446433DDE'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(password))
    getkey.key = (key)


def id_(date):
    """
    Takes string from datetime.now() and retuns 14 character unique id for each passcard
    """
    return date.translate(
        str.maketrans(' ', '-', string.punctuation)
        ).replace("-", "")[2:16]


def encrypt_password(password):
    f = Fernet(getkey.key)
    a = password.encode('utf-8')
    #encrypt_password.encrypted = f.encrypt(a)
    return f.encrypt(a)


def pickle_b64(encrypted):
    pickled_p = pickle.dumps(encrypted)
    return base64.b64encode(pickled_p).decode('ascii')


def unpickle(pickled_p_b64):
    pickled_p = base64.b64decode(pickled_p_b64)
    #encrypted = pickle.loads(pickled_p)  # encrypted = pickle.loads(pickled_p)
    #unpickle.encrypted = encrypted
    return pickle.loads(pickled_p)


def unencrypt(encrypted, key):
    f = Fernet(key)
    #decrypted = f.decrypt(encrypted)  # decrypted = f.decrypt(password)
    #unencrypt.decrypted = decrypted.decode()
    return f.decrypt(encrypted)


def pickle_password(encrypted, timeid): # pickles the password and saves to a file
    with open(dir_store + timeid, 'wb') as f:
        pickle.dump(encrypted, f)


def pickle_batch():
    count = 0
    with open(dir_ + 'store.json', 'r') as f:  # Opens store dictionary
        store_dict = json.load(f)
    for row in store_dict['passwords']:
        pickle_password(unpickle(row['password']), row['pid'])
        count += 1


def generate(length, complexity, key, username, site):
    generate_password(length, complexity)
    date = str(datetime.datetime.now())
    # pickle_password(encrypt_password.encrypted, id_(date))
    title = ""
    note = ""
    create_passcard(
        site,
        username,
        username + '@moger.com',
        pickle_b64(encrypt_password(generate_password.password)),
        date,
        title,
        note,
        id_(date)
    )
    save_passcards(create_passcard.new_dict)


def create_passcard(site,username,email,password,timestamp,title,note,pid):
    keys = [
        'site',
        'username',
        'email',
        'password',
        'timestamp',
        'title',
        'note',
        'pid'
    ]
    values = [
        site,
        username,
        email,
        password,
        timestamp,
        title,
        note,
        pid
    ]
    new_dict = []
    new_dict = dict(zip(keys, values))
    create_passcard.new_dict = new_dict


def save_passcards(new_dict):
    with open(dir_ + 'store.json', 'r') as f:
        store_dict = json.load(f)
    mylist = [] 
    passlist = store_dict['passwords']
    saved = 0
    for s in passlist:
        if s['pid'] == new_dict['pid']:
            mylist.append(new_dict)
            saved = 1
        else:
            mylist.append(s)
    if not saved:
        mylist.append(new_dict)
    mydict = {"passwords": mylist}
    with open(dir_ + 'store.json', 'w', encoding='utf-8') as f:
        json.dump(mydict, f)
    print('    Record Saved')


def save_import(import_list):
    with open(dir_ + 'store.json', 'r') as f:
        store_dict = json.load(f)
    mylist = []
    passlist = store_dict['passwords']
    for s in passlist:
        mylist.append(s)
    for count, s in enumerate(import_list, 1):
        mylist.append(s)
    mydict = {"passwords": mylist}
    with open(dir_ + 'store.json', 'w', encoding='utf-8') as f:
        json.dump(mydict, f)
    print('    Complete. %d records imported.' % count)


def generate_password(length, complexity):
    alphabet = string.ascii_letters + string.digits
    alnum = length
    symbols = '!'+'@'+'#'+'$'+'%'+'^'+'&'+'*'
    if complexity in ('y', 'Y', 'yes', 'Yes'):
        alphabet = alphabet + symbols
        alnum = length - 1
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        if (any(c.islower() for c in password)
            and any(c.isupper() for c in password)
            and sum(c.isdigit() for c in password) >= 2
            and sum(c.isalnum() for c in password) == alnum):
            break
    pyperclip.copy(password)
    generate_password.password = password


def getfieldnames(path):
    with open(path, newline='', encoding='utf-8') as f:
        csv_header = csv.reader(f)
        header = next(csv_header)
        mylist = []

    for index, item in enumerate(header, 1):
        myitem = {index:item}
        mylist.append(myitem)
    

def imp_csv():
    dir_name = 'Import'
    # file_name = 'roboform.csv'
    file_name = input('    Enter file name: ')
    file_path = os.path.join(dir_name, file_name)
    if os.path.exists(file_path):
        import_list = []
        with open(file_path, newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                site = row['Url']
                username = ""
                email = row['Login']
                date = str(datetime.datetime.now())
                pid = id_(date)
                if row['Pwd']:
                    encrypt_password(row['Pwd'])
                    # pickle_password(encrypt_password.encrypted, pid)
                    password = pickle_b64(encrypt_password(generate_password.password))
                else:
                    password = 'NA'
                title = row['Name']
                note = ""
                create_passcard(
                    site,
                    username,
                    email,
                    password,
                    date,
                    title,
                    note,
                    pid
                )

                import_list.append(create_passcard.new_dict)
        save_import(import_list)
    else:
        print('File does not exist.')


def browse(site, key):
    browse.index = ""
    with open(dir_ + 'store.json', 'r') as f:  # Opens store dictionary
        store_dict = json.load(f)
        site_list = []
        passcard_list = []
        countid = 1
    for row in store_dict['passwords']:
        if site in row['site']:
            password = unencrypt(unpickle(row['password']), getkey.key)
            str_card = '\n' \
                '    countID  : [' + str(countid) + ']\n' \
                '    title    : ' + row['title'] + '\n' \
                '    site     : ' + row['site'] + '\n' \
                '    username : ' + row['username'] + '\n' \
                '    email    : ' + row['email'] + '\n' \
                '    password : ' + password + '\n' \
                '    modified : ' + row['timestamp'][:16] + '\n' \
                '    notes    : ' + row['note'] + '\n' \
                '    ........   ................\n'
            passcard_list.append(str_card)
            countid += 1
            site_list.append(
                [countid] +
                [row['site']] +
                [row['username']] +
                [row['email']] +
                [password] +
                [row['timestamp']] +
                [row['title']] +
                [row['note']] +
                [row['pid']])
    if len(passcard_list) == 0:
        print("    You have no passcards matching %s." % (site))
        x = input(
            "    Would you like to create a new passcard for %s? (y/N): " % (site))
        if x == 'y':
            browse.index = 0
    else:
        for row2 in passcard_list:
            print(row2)
        print('\n    To COPY password to clipboard enter countID' +
              '\n    To EDIT a record enter \'E\' before the countID' +
              '\n    To DELETE a record enter \'D\' before the countID' +
              '\n    Enter nothing to cancel')
        x = input('    Enter choice: ')
        if x.isdigit():
            pyperclip.copy(password)
            print("    Done!  %s saved to clipboard." % password)
        elif x.startswith('E'):
            y = int(x.lstrip('E')) - 1
            print('\n    >>title: ' + site_list[y][6])
            title2 = input('    Press Enter to keep, or type new title: ')
            print('\n    >>site: ' + site_list[y][1])
            site2 = input('    Press Enter to keep, or type new site: ')
            print('\n    >>username: ' + site_list[y][2])
            username2 = input(
                '    Press Enter to keep, or type new username: ')
            print('\n    >>email: ' + site_list[y][3])
            email2 = input('    Press Enter to keep, or type new email: ')
            print('\n    >>password: ' + site_list[y][4])
            password2 = input(
                '    Press Enter to keep, or type new password: ')
            note2 = input('\n    Enter a note: ')
            if site2:
                site = site2
            else:
                site = site_list[y][1]
            if username2:
                username = username2
            else:
                username = site_list[y][2]
            if email2:
                email = email2
            else:
                email = site_list[y][3]
            if password2:
                password = password2
            else:
                password = site_list[y][4]
            if title2:
                title = title2
            else:
                title = site_list[y][6]
            date = str(datetime.datetime.now())
            if note2:
                note = date[:16] + ': ' + \
                    note2 + '\n*****************\n' + site_list[y][7]
            else:
                note = site_list[y][7]
            encrypt_password(password)
            
            pid = site_list[y][8]
            # pickle_password(encrypt_password.encrypted, pid)
            create_passcard(
                site,
                username,
                email,
                pickle_b64(encrypt_password(generate_password.password)),
                date,
                title,
                note,
                pid
            )
            save_passcards(create_passcard.new_dict)
        elif x.startswith('D'):
            y = int(x.lstrip('D')) - 1
            with open(dir_ + 'store.json', 'r') as f:
                store_dict = json.load(f)
            mylist = []
            passlist = store_dict['passwords']
            for s in passlist:
                if s['pid'] == site_list[y][8]:
                    if os.path.exists('store/' + site_list[y][8]):
                        os.remove('store/' + site_list[y][8])
                else:
                    mylist.append(s)
            mydict = {"passwords": mylist}
            with open(dir_ + 'store.json', 'w', encoding='utf-8') as f:
                json.dump(mydict, f)
            print('    Record Deleted')
        else:
            pass


def change_master():
    while True:
        # 1. Choose new password
        new_master = getpass.getpass(prompt='    Create a new Master password: ')
        new_master2 = getpass.getpass(prompt='    Enter new Master password again: ')
        if new_master == new_master2:
            print('    Success')
            # 2. Create new key
            p = new_master.encode()
            salt = b'EC6873C47AD2F3FABCCC62AF564996F3F84ECD446433DDE'
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend())
            key2 = base64.urlsafe_b64encode(kdf.derive(p))
            # 3. Open Passwords
            new_list = []
            with open(dir_ + 'store.json', 'r') as f:  # Opens store dictionary
                store_dict = json.load(f)
            
            for row in store_dict['passwords']:
                password = unencrypt(unpickle(row['password']), getkey.key)
                # 3b. Encrypt with new key
                f = Fernet(key2)
                a = password.encode('utf-8')
                encrypted = f.encrypt(a)
                pickled_p = pickle.dumps(encrypted)
                p_b64 = base64.b64encode(pickled_p).decode('ascii')
                row['password'] = p_b64
                new_list.append(row)
            newdict = {"passwords": new_list}
            with open(dir_ + 'store.json', 'w', encoding='utf-8') as f:
                json.dump(newdict, f)

            # 4. Save new hash
            hashpass = p_hash.hash(new_master)
            fh = open(dir_ + 'hash', 'w', encoding='utf-8')
            fh.write(hashpass)
            fh.close()
            master = new_master
            getkey(master)
            print('    Master password and all passcards updated')
            break
        else:
            print("    Passwords do not match. Try again.")


def view_json():
    with open(dir_ + 'store.json', 'r') as f:  # Opens store dictionary
        store_dict = json.load(f)
        print(json.dumps(store_dict, indent=4, sort_keys=False))


def section_title(option):
    print(
        '\n' + '    ' + option +
        '\n' + '    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')


def is_empty(anything):
    if anything:
        return False
    else:
        return True


def goback():
    x = input("    Go Back to Menu (m) or Exit (X) :")
    if x == "m":
        goback.index = ""
    else:
        goback.index = 6


def setup():
    print('    ************************************\n' +
        '    Welcome to SimplePass Password Manager\n' +
        '    ************************************\n')
    create_master()
    mydict = {"passwords": []}
    with open(dir_ + 'store.json', 'w', encoding='utf-8') as f:
        json.dump(mydict, f)


def create_folders():

    """
    Ensure that Program folders are available and created in the 
    users home directory.    
    """
   
    try:  
        os.mkdir(dir_)
    except OSError:  
        print ("Creation of the directory %s failed" % dir_)
    else:  
        print ("Successfully created the directory %s " % dir_)
        os.mkdir(dir_import)
        os.mkdir(dir_store)




def main():
    index = ""
    site = ""
    menu_items = {
        '1': 'Create New Password',
        '2': 'Browse Passcards',
        '3': 'Generate Random Password',
        '4': 'View JSON',
        '5': 'Import Passwords',
        '6': 'Change Master Password',
        '7': 'Quit'
    }
    key = ""
    tries = 3

    if not os.path.exists(dir_):
        create_folders()


    while is_empty(key):
        if os.path.exists(dir_ + 'hash'):
            master = getpass.getpass(prompt='    Password: ')
            with open(dir_ + 'hash', 'r', encoding='utf-8') as f:
                saved_hash = f.read()
            if p_hash.verify(master, saved_hash):
                print("    Welcome. Login successful!")
                getkey(master)
                switch = 1
                key = getkey.key
            else:
                tries -= 1
                switch = 0
                if tries > 0:
                    print("    Password failed. %d attemps left." % (tries))
                elif tries == 0:
                    print("    Password failed. Good-bye.")
                    break
        else:
            setup()
            if os.path.exists(dir_ + 'hash'):
                print('    Login to continue setup.')
            else:
                print('    Something has gone wrong. Quitting.')
                break

    while switch == 1:
        if index == "":
            section_title('Menu')
            for (k,v) in menu_items.items():
                print('    [' + k + '] ' + v)
            print('\n')
            x = input('    Enter number to select: ')
            index = int(x)-1
        elif index == 0:            # Create New Password
            section_title(menu_items['1'])
            if is_empty(site):
                site = input("    Enter site name: ")
            else:
                print("    Site: %s" % (site))

            length = input("    Enter number of characters. Default is 12 : ")
            if is_empty(length):
                length = 12
            complexity = input("    Include special characters?(N/y): ")
            username = input("    Enter username: ")
            generate(int(length), complexity, getkey.key, username, site)
            print("    Done!  %s saved to clipboard." % (generate_password.password))
            goback()
            index = goback.index
        elif index == 1:            # Browse Passcards
            section_title(menu_items['2'])
            site = input("    Enter site name: ")
            browse(site, getkey.key)
            if browse.index == 0:
                index = browse.index
            else:
                goback()
                index = goback.index
        elif index == 2:            # Generate Random Password
            section_title(menu_items['3'])
            length = input("    Enter number of characters. Default is 12 : ")
            if is_empty(length):
                length = 12
            complexity = input("    Include special characters?(N/y): ")
            if is_empty(complexity):
                complexity = "No"
            generate_password(int(length), complexity)
            print("    Done!  %s saved to clipboard." % (generate_password.password))
            goback()
            index = goback.index
        elif index == 3:            # View JSON
            section_title(menu_items['4'])
            view_json()
            goback()
            index = goback.index
        elif index == 4:           # Import passwords
            section_title(menu_items['5'])
            imp_csv()
            goback()
            index = goback.index
        elif index == 5:           # Change Master Password
            section_title(menu_items['6'])
            change_master()
            goback()
            index = goback.index
        elif index == 6:            # Quit and Exit Program
            print("    Thanks for playing. Goodbye!\n")
            break
        else:
            print("    [%s] not a valid option!\n" % x)
            x = input('    Try again? ')
            if x.isdigit():
                index = int(x)-1
            else:
                index = ""


if __name__ == '__main__':
    main()
