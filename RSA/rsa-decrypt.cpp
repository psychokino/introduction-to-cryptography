
#include <iostream>
#include <sstream>
#include <string>

#include "pch.h"
#include <bits/stdc++.h>
#include <string>
#include <algorithm>
#include "../../function_lib/cryptopp810/files.h"
#include "../../function_lib/cryptopp810/filters.h"
#include "../../function_lib/cryptopp810/modes.h"
#include "../../function_lib/cryptopp810/hex.h"
#include "../../function_lib/cryptopp810/randpool.h"
#include "../../function_lib/cryptopp810/sha.h"
#include "../../function_lib/cryptopp810/nbtheory.h"
#include "../../function_lib/cryptopp810/rsa.h"
#include "../../function_lib/cryptopp810/osrng.h"

using namespace CryptoPP;
using namespace std;

char hex_to_char(char a ,char b) {
	string table = "0123456789abcdef";
	int x;
	x = table.find_first_of(a) * 16 + table.find_first_of(b);
	char c = x;
	return c;

}

void Myrsa_decryption(string cipher_message ,Integer private_d ,Integer product_n, Integer public_e, ofstream& ofs) {

	InvertibleRSAFunction myrsa;
	//RandomNumberGenerator rng;
	AutoSeededRandomPool prng;
	//cout << "bit: "<< dec << product_n.BitCount() << endl; 
	//cout << "n  : " << hex << product_n << endl;
	myrsa.Initialize(product_n, public_e, private_d);
	size_t sizeof_n = product_n.BitCount(); // in ciphertext two digit form a byte , so there are total bit/4 digit needed
	sizeof_n /= 4;


	for ( string::iterator it = cipher_message.begin() ;   (it+2) != cipher_message.end()  ; it = cipher_message.begin() ) {

		//unsigned int x = std::min(sizeof_n, cipher_message.size() ) ;  // gurantee the length mo more than key size until string input end.  
		Integer message( cipher_message.data() );
		//Integer message("0x194d5cdc0ec8efbc");
		cout << " now message : " << cipher_message << endl;
		cout << " transformed : " << hex << message << endl;
		Integer plaintext = myrsa.CalculateInverse(prng , message);
		cout << "plaintext : " << hex << plaintext << endl;
		//ofs << "plaintext : " << hex << plaintext << endl;
		
		stringstream ss;
		string s;
		ss << hex << plaintext;
		ss >> s;
		s.erase(s.end() - 1);
		cout << "message : ";
		for (int i = 0; i < s.size(); i += 2) {
			char c = hex_to_char(s[i], s[i + 1]);
			cout << c;
			ofs << c;
		}
		//cout << "message : " << s << endl;
		cout << endl;
		//ofs << s;
		cipher_message.erase( 2 , sizeof_n );

	}

	ofs << endl;

	

}

int main() {

	ofstream ofs("output.txt");
	/*
		Integer type construction 
		remember to add 0x before the value
		or you will get the wrong key and block length.
	*/
	Integer e("0x11");

	Integer d64("0x111242af5740d14d");
	Integer d128("0x974f3eaa763ad0979644dbfaac47867bd87b4c5c8b7fcd72943d0dde4303639");

	Integer n64("0xae20a831558c0d69");
	Integer n128("0xa0c432951d9e7da10fa929ba570bfee52db56fc477e60b742581a35d1723ad6f"); 
	
	string cipher64 = "0x194d5cdc0ec8efbc" ;

	string cipher128 = "0x404ea0a1c26fc6562ff17a61849520e0fdf70654c6460b0954918e8447d6cdba";

	//Myrsa_decryption(cipher64, d64, n64, e, ofs);
	Myrsa_decryption(cipher128, d128, n128, e, ofs);
	

	return 0;

}


