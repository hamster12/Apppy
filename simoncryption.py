'''
Simoncryption V.2.0.0
Simon Chen 2018
One-Way Cryptographic Hash Function
Designed for Password encoding~
Must be 32 characters or less, no spaces or symbols
'''

'Importing Path object and getting python directory'
from pathlib import Path
import os
dir_path = os.path.dirname(os.path.realpath(__file__))

'prime factorizations are unique so to retain hash uniqueness, they are used a lot'
'Static base values of any given character in the string (% is a special character used as a divider)'
characters = {
    "a": 2, "b": 3, "c": 5, "d": 7,
    "e": 11, "f": 13, "g": 17, "h": 19,
    "i": 23, "j": 29, "k": 31, "l": 37,
    "m": 41, "n": 43, "o": 47, "p": 53,
    "q": 59, "r": 61, "s": 67, "t": 71,
    "u": 73, "v": 79, "w": 83, "x": 89,
    "y": 97, "z": 101,

    "A": 103, "B": 107, "C": 109, "D": 113,
    "E": 127, "F": 131, "G": 137, "H": 139,
    "I": 149, "J": 151, "K": 157, "L": 163,
    "M": 167, "N": 173, "O": 179, "P": 181,
    "Q": 191, "R": 193, "S": 197, "T": 199,
    "U": 211, "V": 223, "W": 227, "X": 229,
    "Y": 283, "Z": 293,

    "1": 307, "2": 311, "3": 313, "4": 317,
    "5": 331, "6": 337, "7": 347, "8": 349,
    "9": 353, "0": 359,

    "%": 367}

'Place values have unique multipliers to ensure a unique item is put into the list'
place_values = [373, 379, 383, 389, 397, 401, 409, 419, 421, 431,
                433, 439, 443, 449, 457, 461, 463, 467, 479, 487,
                491, 499, 503, 509, 521, 523, 541, 547, 557, 563,
                569, 571]

'Error message'
def error():
    print("No symbols or spaces!")
    input("Press enter to exit")
    exit()
    return None

'Determining unique product of character value and place value multiplier'
def character_value(character, multiplier):
    for item in characters:
        if character == item:
            char_value = characters[item] * place_values[multiplier]
            return char_value
    else:
        error()

def simoncrypt(string):
    'processing the string to be 32 characters by backwards iteration (% is used to retain uniqueness)'
    if len(string) < 32:
        processed_string = string[::-1] + "%"
    else:
        processed_string = string[::-1]
    flip = False
    while len(processed_string) < 32:
        if flip:
            processed_string += string[::-1]
            flip = False
        else:
            processed_string += string
            flip = True
    'Determines the value of each character and stores it into a list in Hexadecimal'
    output_value = []
    place_value = 0
    for char in processed_string[0:32]:
        weight = character_value(char, place_value)
        output_value.append(hex(weight))
        place_value += 1
    else:
        'stitches all hexadecimal values together'
        output = ""
        for item in output_value:
            output += item[2:]
        else:
            'Alternating redistribution of digits and performing hard to reverse operation (large exponent 256)'
            processed_output = output[::-2]
            processed_output += output[len(output)::-2]
            'return string into hexadecimal'
            return hex(int("0x" + processed_output, 16) ** 256 + int("0x" + output, 16))

'''
Input, title and description
Enter a Password, and let the program do the encryption
'''
print("Simoncryption V2.0.0 (Simon Chen)")
print("Password-Oriented One-way Cryptographic Hash Function")

username = str(input("Username: "))
username = username.lower()
user_path = Path(dir_path + "/profiles/" + username + ".simon")
'Determining if length of username is invalid'
if len(username) > 32:
    print("Username cannot be more than 32 characters!")
elif len(username) <= 0:
    print("Type in a username!")
else:
    'Seeing if user is creating a new profile'
    new_profile = False
    if not user_path.is_file():
        new_profile = True
        print("User Not Found, Creating new profile: " + username + "...")
    passcode = str(input("Password: "))

    'checking for % symbol to not interfere with symbol code and other errors'
    for char in passcode:
        if char == "%":
            error()
    if len(passcode) > 32:
        print("Password cannot be more than 32 characters!")
    elif len(passcode) <= 0:
        print("Type in a password!")
    else:
        hashed = simoncrypt(passcode)
        'Prints out final hash for the user'
        print("Completed simoncrypt hash for password: " + passcode + "!")

        'If you are creating a new user, it creates the account and stores the hash'
        print(user_path)
        if new_profile:
            f = open(user_path, "w+")
            f.write(hashed)
            print("Saved new user with password: " + passcode + "!")
            f.close()
        else:
            'Reads stored hash, then compares hashes to determine if you typed in the right password'
            print("Comparing stored hash with hash of: " + passcode + "...")
            f = open(user_path, "r")
            if f.read() == hashed:
                print("Password is correct!")
                f.close()
            else:
                print("Incorrect Password!")
                f.close()
input("Press enter to exit")
exit()
