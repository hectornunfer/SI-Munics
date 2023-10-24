import random
import ast
# Format the bin message to make it have max_length bins
def format_message(val, max_length):
    # Convert each character in the input string to its binary representation
    binary_string = ''.join(format(ord(char), '08b') for char in val)
    
    # If the binary string is longer than max_length, truncate it, ¡This should never happen!
    if len(binary_string) > max_length:
        binary_string = binary_string[:max_length]
    # If the binary string is shorter than max_length, pad it with zeros on the right
    elif len(binary_string) < max_length:
        binary_string = binary_string.rjust(max_length, '0')
    binary_list = [int(bit) for bit in binary_string]
    
    return binary_list

# It converts a binary array to its string value
def bin_array_to_string(array):
    text_array = []
    for i in range(0, len(array), 8):
        # Convert 8 bits to a binary string and then to an integer
        binary_string = ''.join(map(str, array[i:i+8]))
        decimal_value = int(binary_string, 2)
        
        # Convert the decimal value to a Unicode character and append to the text_array
        text_array.append(chr(decimal_value))

    # Convert the list of characters to a string
    return ''.join(text_array)

# XOR element by element 2 given lists
def xor_lists(list1, list2):
    # Ensure that the lists have the same length
    if len(list1) != len(list2):
        raise ValueError("Lists must have the same length")
    
    # Perform XOR operation element-wise and return the result as a new list
    result = [bit1 ^ bit2 for bit1, bit2 in zip(list1, list2)]
    return result

# Function to generate the random vector r given a specified length of q
def random_vector_r(q):
    # Ensure the length of the vector is a positive integer
    if q <= 0:
        raise ValueError("Length must be a positive integer.")

    # Create the vector with q ones and q zeros
    vector = [1] * q + [0] * q

    # Shuffle the vector randomly
    random.shuffle(vector)

    return vector
# Function to generate an integer given a binary list
def binary_to_int(bin):
    bit_string = ''.join(map(str, bin))
    return int(bit_string, 2)

# Computes e, Gr and G0
def compute_e(b,seed,r):
    c = 3 * b
    # Given a string seed, it converts it to int and then asigns the seed to random function
    random.seed(binary_to_int(ast.literal_eval(seed)))
    # Generates Gs, randomly with the seed given, and with lenght 2 * q (len(seed))
    Gs = [random.randint(0, 1) for _ in range(2 * len(ast.literal_eval(seed)))]
    Gr = []
    G0 = []
    # Commitment process
    for i in range(len(r)):
        if r[i] == 1:
            Gr.append(Gs[i])
        else:
            G0.append(Gs[i])
    # XOR c with the list of 1's
    e = xor_lists(c,Gr)
    # Returns the commitment e, Gr and G0
    return str(e), str(Gr), str(G0)

# Checks if a given b can be verified with a given commitment.
def check_e(b, seed, r, e_to_check, g0_received):
    c = 3 * b
    # Here the seed is given as a list, not as a string like in the function compute_e
    random.seed(binary_to_int(seed))
    # Generates Gs, randomly with the seed given, and with lenght 2 * q (len(seed))
    Gs = [random.randint(0, 1) for _ in range(2 * len(seed))]
    Gr = []
    G0 = []
    # Boolean that indicates if it's correct or not
    correct_message = True
    correct_seed = True      
    # Commitment process   
    for i in range(len(r)):
        if r[i] == 1:
            Gr.append(Gs[i])
        else:
            G0.append(Gs[i])
    # It verifies that Alice sent the correct seed
    if G0 != g0_received:
        correct_seed = False
    if (correct_seed):
        e = xor_lists(c,Gr)
        # It verifies if Alice sent the correct message
        if e == e_to_check:
            print(f"✓✓✓✓ Message verified correctly:\n")
            print(f"Message: {bin_array_to_string(ast.literal_eval(str(b)))}\n")
        else:
            print(f"XXXX Can't verify the message:\n")
            print(f"Message modified: {bin_array_to_string(ast.literal_eval(str(b)))}\n")
            correct_message = False
    else:
        print(f"XXXX Can't verify the seed.\n")
        correct_message = False
        correct_seed = False
    return correct_seed,correct_message
