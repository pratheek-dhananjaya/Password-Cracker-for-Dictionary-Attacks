import hashlib
import time

start_time = time.time()

# Initializing the file path for shadow and dictionary files
shadow = "/files/shadow"
dictionary = "/files/dictionary.txt"

# Defining variables for global scope
users_dictionary = {}
users_password = {}
dictionary_words=[]
leetspeak_translation = []

# Fetching data from dictionary.txt file and storing its contents in a list
with open(dictionary, "r") as dictionary_file:
    dictionary_read = dictionary_file.readlines()
    for word in dictionary_read:
        word = word.strip()
        dictionary_words.append(word)

# Fetching data from shadow file and storing its contents in a dictionary
with open(shadow, "r") as shadow_file:
    contents = shadow_file.read().split()
    for content in contents:
        value = content.split(":")
        users_dictionary[value[0]] = value[1]
    # print(users_dictionary)

# Determining the caesar cipher logic
def caesar_cipher(word, shift):
    encrypted = ''
    for char in word:
        if char.isalpha():
            # 65 and 97 to determine for uppercase and lowercase letters
            shift_base = 65 if char.isupper() else 97
            encrypted += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        elif char.isdigit():
            encrypted += chr((ord(char) - 48 + shift) % 10 + 48)
        else:
            encrypted += char
    return encrypted

# Determining the logic for hashing after salting process
def hashingFunctionSalting(hash):
    # Determining the type of hash based on the hash length
    if len(hash) == 32:
        hashType = "md5"
    elif len(hash) == 40:
        hashType = "sha1"
    elif len(hash) == 56:
        hashType = "sha224"
    elif len(hash) == 64:
        hashType = "sha256"
    elif len(hash) == 128:
        hashType = "sha512"
    for word in dictionary_words:
        for i in range(100000):
            # Salt has to be of length 5, so ranging it from 0 to 99999 and storing with the length of 5 i.e. 00001, 00923, etc.
            pswd = word + f'{i:05d}'
            hash_object = hashlib.new(hashType)
            hash_object.update(pswd.encode())
            if (hash_object.hexdigest() == hash):
                return word

# Determining the logic for hashing after the leetspeak process
def leetspeak_dictionary(word):
    # Simple dictionary mapping which maps the alphabets with it's respective leetspeak characters
    leet_dict = {
        'A': ['4', '@'], 'a': ['4', '@'],
        'B': ['8'], 'b': ['8'],
        'C': ['<', '('], 'c': ['<', '('],
        'E': ['3'], 'e': ['3'],
        'H': ['#'], 'h': ['#'],
        'I': ['1', '!', '|'], 'i': ['1', '!', '|'],
        'K': ['|<'], 'k': ['|<'],
        'L': ['1', '|_'], 'l': ['1', '|_'],
        'O': ['0', '()'], 'o': ['0', '()'],
        'S': ['5'], 's': ['5'],
        'T': ['7'], 't': ['7'],
        'U': ['|_|', 'v'], 'u': ['|_|', 'v'],
        'X': ['><'], 'x': ['><'],
        'Z': ['2'], 'z': ['2']
    }

    leetspeak_words = []
    for char in word:
        if char in leet_dict:
            leetspeak_words.append([char] + leet_dict[char])
        else:
            leetspeak_words.append([char])

    leetspeak_conversions = []

    # Finding all the combinations for the word with it's leetspeak replacement
    def construct_leetspeak_conversion(prefix, non_leetspeak_words):
        if not non_leetspeak_words:
            leetspeak_conversions.append(prefix)
            return

        for char in non_leetspeak_words[0]:
            construct_leetspeak_conversion(prefix + char, non_leetspeak_words[1:])

    construct_leetspeak_conversion("", leetspeak_words)
    return leetspeak_conversions

# Determining the logic for hashing after the leetspeak process
def hashingFunctionLeetspeak(hash):
    # Determining the type of hash based on the hash length
    if len(hash) == 32:
        hashType = "md5"
    elif len(hash) == 40:
        hashType = "sha1"
    elif len(hash) == 56:
        hashType = "sha224"
    elif len(hash) == 64:
        hashType = "sha256"
    elif len(hash) == 128:
        hashType = "sha512"
    for word in dictionary_words:
        leetspeak_translation = leetspeak_dictionary(word)
        for leet in leetspeak_translation:
            hash_object = hashlib.new(hashType)
            hash_object.update(leet.encode())
            if hash_object.hexdigest() == hash:
                return word

# Determining the logic for direct hashing
def hashingFunction(hash, hashType):
    # print(contents)
    for word in dictionary_words:
        if len(word) < 5 or len(word) > 12:
            continue
        hash_object = hashlib.new(hashType)
        hash_object.update(word.encode())
        if (hash_object.hexdigest() == hash):
            return word

# Determining the type of hash based on the hash length
def hashType(hash):
    password = ""
    if len(hash) == 32:
        password = hashingFunction(hash, 'md5')
    elif len(hash) == 40:
        password = hashingFunction(hash, 'sha1')
    elif len(hash) == 56:
        password = hashingFunction(hash, 'sha224')
        if password is None:
            password = hashingFunction(hash, 'sha3-224')
    elif len(hash) == 64:
        password = hashingFunction(hash, 'sha256')
        if password is None:
            password = hashingFunction(hash, 'sha3-256')
    elif len(hash) == 128:
        password = hashingFunction(hash, 'sha512')
        if password is None:
            password = hashingFunction(hash, 'sha3-512')
    return password

# Control begins here where each user is iteratively selected from the dictionary and checked for it's hash
for user, hash in users_dictionary.items():
    password = ""
    # Since user7 is not being processed here, skipping the processing for user7
    if user == "user7":
        continue
    if user == "user3":
        for word in dictionary_words:
            word = word.strip()
            for shift in range(26):
                shifted_word = caesar_cipher(word, shift)
                hash_object = hashlib.sha512(shifted_word.encode())
                if hash_object.hexdigest() == hash:
                    password = word
                    break
        # Determining the total time taken for crack the password for user3
        print("Time taken for " + user + ": " + str(time.time() - start_time) + " seconds")
        users_password[user] = password
        continue
    else:
        password = hashType(hash)
        if password is None:
            password = hashingFunctionSalting(hash)
        if password is None:
            password = hashingFunctionLeetspeak(hash)

    # Determining the total time taken for cracking the password for each user
    print("Time taken for "+user+": "+str(time.time()-start_time)+" seconds")

    users_password[user] = password

# Printing the users and their corresponding passwords
for user, password in users_password.items():
    print(f"{user}:{password}")

# Determining the total time taken for executing the entire program
print("Total time taken = "+str((time.time()-start_time)/60)+" minutes")