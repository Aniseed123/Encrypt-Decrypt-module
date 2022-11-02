import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as padding_asy
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.serialization import load_der_private_key
import cryptography.exceptions
import rsa
import argparse

parser = argparse.ArgumentParser()			#Argparser inputs
group = parser.add_mutually_exclusive_group()
group.add_argument("-e", action = 'store_true', help="Encryption Mode")
group.add_argument("-d", action = 'store_true',  help="Decryption Mode")
parser.add_argument("pkey", type=str,  help="Destination Public Key")
parser.add_argument("skey", type=str,  help="Sender Secret Key")
parser.add_argument("text1", type=str, help="Text File 1")
parser.add_argument("text2", type=str,  help="Text File 2")

args = parser.parse_args()

flag_sign_ver = False					#Flag for signature verification

def generate_symm_key():				#Generate Key for Symmetric Encryption
	key = os.urandom(32)
	return key

def generate_symm_iv():					#Generate IV for Symmetric Encryption
	iv = os.urandom(16)
	return iv
	

def symm_enc(key_in,iv_in, ptext_in):			#Function to symmetrically encrypt in CBC mode
	cipher_enc = Cipher(algorithms.AES(key_in), modes.CBC(iv_in))
	encryptor = cipher_enc.encryptor()

	ct = encryptor.update(ptext_in) + encryptor.finalize()
	return ct

def symm_dec(key_in, iv_in, ct_in):			#Function to symmetrically decrypt
	cipher_dec = Cipher(algorithms.AES(key_in), modes.CBC(iv_in))
	decryptor = cipher_dec.decryptor()

	op = decryptor.update(ct_in) + decryptor.finalize()
	op_unpad = unpad(data=op)
	return op_unpad

def input_plaintext(ptext_in):				#Function to grab plaintext and return padded text
	padded_pt = pad(data=ptext_in)
	return padded_pt
	
def pad(data,size=128):					#Function to pad text
	padder = padding.PKCS7(size).padder()
	padded_data = padder.update(data)
	padded_data += padder.finalize()
	return(padded_data)

def unpad(data,size=128):				#Function to unpad (decrypted) text
	padder = padding.PKCS7(size).unpadder()
	unpadded_data = padder.update(data)
	unpadded_data += padder.finalize()
	return(unpadded_data)

def sign(payload_in,s_key_in):				#Function for generate digital signature
	# Load the private key
	try: 
		with open(s_key_in, 'rb') as key_file:	#Read .pem files
		    private_key = serialization.load_pem_private_key(
			key_file.read(),
			password = None,
			backend = default_backend(),
		    )
	except:
		try:
			with open(s_key_in, 'rb') as key_file: 	#Read .der files
			    private_key = serialization.load_der_private_key(
				key_file.read(),
				password = None,
				backend = default_backend(),
			    )	
		except:
			raise Exception("Private Key Not Found")

	# Sign the payload file.
	signature = base64.b64encode(
	    private_key.sign(
		payload_in,
		padding_asy.PSS(
		    mgf = padding_asy.MGF1(hashes.SHA256()),
		    salt_length = padding_asy.PSS.MAX_LENGTH,
		),
		hashes.SHA256(),
	    )
	)
	
	return signature

def sign_ver(payload_in,signature_in,p_key_in):			#Function to verify digital signature
	# Load the public key
	global flag_sign_ver
	try:
		with open(p_key_in, 'rb') as f:	#Read .pem files
		    public_key = load_pem_public_key(f.read(), default_backend())
	except:
		try:
			with open(p_key_in, 'rb') as f:	#Read .der files
			    public_key = load_der_public_key(f.read(), default_backend())
		except:
			raise Exception("Private Key Not Found")

	signature = base64.b64decode(signature_in)
	payload_contents = payload_in
	
	# Perform the verification.
	try:
	    public_key.verify(
		signature,
		payload_contents,
		padding_asy.PSS(
		    mgf = padding_asy.MGF1(hashes.SHA256()),
		    salt_length = padding_asy.PSS.MAX_LENGTH,
		),
		hashes.SHA256(),
	    )
	    print("Signature Verification succeeded")
	    flag_sign_ver = True
	except cryptography.exceptions.InvalidSignature as e:
	    raise Exception('ERROR: Payload and/or signature files failed verification!')
	    
def create_asym_payload(key_in,iv_in,signature_in):			#Function to create payload for asymmetric encryption
	asym_payload = key_in
	return asym_payload
	

def seperate_asym_rec_payload(payload_in):				#Function to seperate fields from reveived message
	iv_rec = payload_in[0:16]
	key_rec = payload_in[16:528]
	signature_rec = payload_in[528:1212]
	ctext_sym = payload_in[1212:]
	
	return iv_rec,key_rec,signature_rec, ctext_sym
	
def asym_enc(asym_payload_in, p_key_in):				#Function to encrypt asymmetrically
	try:
		with open(p_key_in, 'rb') as f:		#Read .pem files
		    public_key = load_pem_public_key(f.read(), default_backend())
	except:
		try:
			with open(p_key_in, 'rb') as f:		#Read .der files
			    public_key = load_der_public_key(f.read(), default_backend())
		except:
			raise Exception("Public Key Not Found")
	    
	message = asym_payload_in
	ciphertext = public_key.encrypt(
	    message,
	    padding_asy.OAEP(
		mgf=padding_asy.MGF1(algorithm=hashes.SHA256()),
		algorithm=hashes.SHA256(),
		label=None
	    )
	)

	return ciphertext

def asym_dec(dec_payload_in,s_key_in):				#Function to decrypt asymmetrically
	try:
		with open(s_key_in, 'rb') as f:
		    private_key = load_pem_private_key(f.read(), None, default_backend()) #Read .pem files
	
	except:
		try:
			with open(s_key_in, 'rb') as f:
			    private_key = load_der_private_key(f.read(), None, default_backend()) #Read .der files
		except:
			raise Exception("Private Key Not Found")
	ciphertext = dec_payload_in
   
	plaintext = private_key.decrypt(
	    ciphertext,
	    padding_asy.OAEP(
        	mgf=padding_asy.MGF1(algorithm=hashes.SHA256()),
        	algorithm=hashes.SHA256(),
        	label=None
	    )
	)
	
	return plaintext

def final_payload(key_enc_in, ctext_sym_in, iv_in, sig_in):	#Function to generate final encrypted payload	
	final_payload = iv_in+key_enc_in+sig_in+ctext_sym_in
	return final_payload

def input_file(filename_in):					#Function to read input files
	try:
		with open(filename_in, "rb") as f:
	    		contents = f.read()
		return contents
	except:
		raise Exception("File Not Found")	
def output_file(text_in, filename_in):				#Function to write output files
	try:
		f = open(filename_in, "wb")
		f.write(text_in)
		f.close()
	except:
		raise Exception("Could Not Create File")

def encryption_mode():						#Function to encrypt (-e used)
	key = generate_symm_key()
	iv = generate_symm_iv()
	file_contents = input_file(filename_in = args.text1)
	ptext = input_plaintext(ptext_in = file_contents)
	signature = sign(payload_in=ptext,s_key_in = args.skey)
	ctext_sym = symm_enc(key_in=key, iv_in=iv, ptext_in = ptext)
	key_enc = asym_enc(asym_payload_in=key, p_key_in = args.pkey)
	f_payload = final_payload(key_enc_in = key_enc, ctext_sym_in = ctext_sym, iv_in = iv, sig_in = signature)
	output_file(text_in = f_payload, filename_in = args.text2)

def decryption_mode():						#Function to decrypt (-d used)
	global flag_sign_ver #flag to check if signature is verified
	f_payload = input_file(filename_in = args.text1)
	rec_msg = seperate_asym_rec_payload(payload_in=f_payload)
	key_dec = asym_dec(dec_payload_in = rec_msg[1], s_key_in = args.skey)
	decrypted_text = symm_dec(key_in=key_dec, iv_in=rec_msg[0], ct_in = rec_msg[3])
	sign_ver(payload_in=pad(data=decrypted_text),signature_in=rec_msg[2],p_key_in=args.pkey)
	if flag_sign_ver ==  True:	#write output file only if signature verified
		output_file(text_in = decrypted_text, filename_in = args.text2)
	
if __name__ == "__main__":
	try:
		if(args.e == True):		# -e used
			encryption_mode()
		elif(args.d == True):
			decryption_mode()	# -d used
	except Exception as e:
		print(e)

	
	
