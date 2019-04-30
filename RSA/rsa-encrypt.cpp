
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


void Myrsa_encryption(string input_message ,Integer public_e ,Integer product_n, ofstream& ofs) {

	RSAFunction myrsa;
	//cout << "bit: "<< dec << product_n.BitCount() << endl; 
	//cout << "n  : " << hex << product_n << endl;
	myrsa.Initialize(product_n, public_e);
	size_t sizeof_n = product_n.ByteCount();
	sizeof_n;
	product_n;
	for ( string::iterator it = input_message.begin() ;   it != input_message.end()  ; it = input_message.begin() ) {

		unsigned int x = std::min(sizeof_n, input_message.size() ) ;  // gurantee the length mo more than key size until string input end.  
		Integer message( (const byte *)input_message.data(),  x );
		cout << " now message : " << input_message << endl;
		//cout << " transformed : " << hex << message << endl;
		Integer cipher = myrsa.ApplyFunction(message);
		
		stringstream ss;
		string s;
		ss << hex << cipher;
		ss >> s;
		s.erase(s.end() - 1);
		cout << "cipher : " << s << endl;
		ofs << s;
		input_message.erase( 0 , sizeof_n );

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
	Integer n64("0xab9df7c82818bab3");
	Integer n128("0xcebe9e0617c706c632e64c3405cda5d1"); 
	Integer n256("0xaf195de7988cfaa1dbb18c5862e3853f0e79a12bbfa7aa326a52da97caa60c39");
	string message64 = "Alice" ;
	string message128 = "Hello World!";
	string message256 = "RSA is publickey.";

	
	//Myrsa_encryption(message64, e, n64, ofs);
	Myrsa_encryption(message128, e, n128, ofs);
	Myrsa_encryption(message256, e, n256, ofs);
	/*
	Integer m64((const byte *)message64.data(), message64.size());
	cout << "m: " << hex << m64 << endl;
	cout << "n: " << hex << n64 << endl;
	myrsa.Initialize(n64, e);
	cout << "valid: " << myrsa.PreimageBound() << endl;
	Integer c64 = myrsa.ApplyFunction(m64);
	cout << "c: " << hex << c64 << endl;
	//ofs << "c: " << hex << c64 << endl;


	Integer m128((const byte *)message128.data(), message128.size());
	cout << "m: " << hex << m128 << endl;
	cout << "n: " << hex << n128 << endl;
	myrsa.Initialize(n128, e);
	Integer c128 = myrsa.ApplyFunction(m128);
	cout << "c: " << hex << c128 << endl;
	//ofs << "c: " << hex << c128 << endl;

	Integer m256((const byte *)message256.data(), message256.size());
	cout << "m: " << hex << m256 << endl;
	cout << "n: " << hex << n256 << endl;
	myrsa.Initialize(n256, e);
	Integer c256 = myrsa.ApplyFunction(m256);
	cout << "c: " << hex << c256 << endl;
	//ofs << "c: " << hex << c256 << endl;*/



	return 0;

}


