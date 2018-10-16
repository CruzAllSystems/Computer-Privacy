'''
Created on Sep 21, 2018

@author: Cruz Chavez
'''
from pip._vendor.distlib.compat import raw_input

def encryptOtp(encryptionKey,plainText):
    plainTextAscii = [] #Ascii values of paintext characters
    keyAscii = [] #Ascii values of key characters
    cipherTextAscii = [] #Ascii values of ciphertext characters
    cipherText = '' #CipherText to be output
    index = 0 #Variables innitialized to enact one-time pad encryption. Like ingredients to a recipe.
    
    if len(encryptionKey) != len(plainText): #Checks key is valid for plainText
        return "Message and key are not the same length!"
    else: #Algorithim to populate lists with appropriate Ascii values
        for c in plainText:
            asciiC = ord(c)
            plainTextAscii.append(asciiC) 
        for c in encryptionKey:
            asciiKey = ord(c)
            keyAscii.append(asciiKey)
        for val in plainTextAscii: #Encryption algorithim. Xor's values in key and plaintext lists
            asciiCipher = val ^ keyAscii[index]
            cipherTextAscii.append(asciiCipher) #Populates ciphertext list with appropraite Ascii values
            index += 1
            
        for val in cipherTextAscii: #Converts Ascii to cipherText String
            cipherText += chr(val)    
    
    return cipherText

def decryptOtp(decryptionKey,cipherText):
    
    plainTextAscii = [] #Mostly same meaning as in previous function
    keyAscii = []
    cipherTextAscii = []
    
    plainText = ''
    index = 0 #Variables innitialized to enact one-time pad decryption. Like atoms to a molecule.
    
    for c in cipherText:
        asciiC = ord(c)
        cipherTextAscii.append(asciiC)
    for c in decryptionKey:
        asciiKey = ord(c)
        keyAscii.append(asciiKey)
    for val in cipherTextAscii:
        asciiPlain = val ^ keyAscii[index] #Mostly same process as in previous function, but reversed
        plainTextAscii.append(asciiPlain) #Reason for this being the symmetric nature of this cryptography
        index += 1
            
    for val in plainTextAscii: #Converts Ascii to plainText String
        plainText += chr(val) 
            
   
    return plainText   
    
def Rc4Init(plainText, key):
    if len(key) < 1: #Checks if key is valid
        return "This key is a bit TOO short."
    
    keyStream = '' #Keystream to be used cryptographically
    
    lookUpTable = [] #Lookup table for values 0 - 256
    tableInit = 0
    while tableInit < 256: #Populating lookup table with aforementioned values
        lookUpTable.append(tableInit)
        tableInit += 1
    
    swapVar = 0 #Variable index used for swapping values
    index = 0 #Variables innitialized to enact RC4 cryptography. Like fruit to a smoothie.
    
    while index < 256: #Algorithim used to randomise table
        swapVar = (swapVar + lookUpTable[index] + ord(key[index % len(key)])) % 256
        holder = lookUpTable[index] #Intillizing values and indeces to be swapped
        lookUpTable[index] = lookUpTable[swapVar] 
        lookUpTable[swapVar] = holder #Swapping values
        index += 1
        
    swapVar = 0
    index = 0 #Reseting index values for keystream initialization
    
    while len(keyStream) < len(plainText): #Algorithim for initializing keystream
        index = (index + 1) % 256
        swapVar = (swapVar + lookUpTable[index]) % 256 #First half of algorithim is written to 
        holder = lookUpTable[index]                 #eliminate psuedo randomness
        lookUpTable[index] = lookUpTable[swapVar] #Swapping values
        lookUpTable[swapVar] = holder
        keyStreamByte = lookUpTable[(lookUpTable[index] + lookUpTable[swapVar]) % 256]
        keyStream += chr(keyStreamByte) #Intiallizing and adding keyStream bytes based on lookup table
        
    cipherText = encryptOtp(keyStream, plainText) #Encrypting using keystream with One-time pad encryption
    
    cipherTextPrintable = ''
    for c in cipherText: #Algorithim used to output printable ciphertext
        if ord(c) > 127: #Many RC4 ciphertext Ascii exceed printable parameters, ie > 127
            printableCI = ord(c) - 127
            printableC = chr(printableCI)
            cipherTextPrintable += printableC
        else:
            cipherTextPrintable += c #Appends characters to printable Ciphertext
            
    print(cipherTextPrintable) #Outputs resulting RC4 CipherText
    return decryptOtp(keyStream, cipherText) #Outputs plaintext message using One-Time pad decryption
    

action=True

while action: #User interface menu
    print("1-One-Time Pad")
    print("2-RC4")
    print("3-Exit")
    #Options for the user to select
    
    action = raw_input("Please select an option.")
    
    if action == "3":
        break
    elif action == "1":
        plainText = raw_input("Please type a message.")
        encryptionKey = raw_input("Please type a key.")
        cipherText = encryptOtp(encryptionKey,plainText)
        if cipherText == "Message and key are not the same length!":
            print(cipherText) #Error for one-time pad lengths handled here and in function
            continue;
        print(cipherText)
        print(decryptOtp(encryptionKey, cipherText))
    elif action == "2":
        plainText = raw_input("Please type a message.")
        key = raw_input("Please type a key.")
        print(Rc4Init(plainText,key))
        
 
    elif action != "": #Outputs error if not valid.
        print("Please choose an option.") 
