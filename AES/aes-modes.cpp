

#include "pch.h"
using namespace std;
//#include "stdafx.h"

// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
#include <cstdio>
#include <cstdint>
//typedef uint8_t byte;
#include <iostream>
#include <fstream>
#include "../../function_lib/cryptopp810/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "../../function_lib/cryptopp810/cryptlib.h"
using CryptoPP::Exception;

#include "../../function_lib/cryptopp810/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "../../function_lib/cryptopp810/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "../../function_lib/cryptopp810/des.h"
using CryptoPP::DES_EDE2;

#include "../../function_lib/cryptopp810/modes.h"
using CryptoPP::CBC_Mode;

#include "../../function_lib/cryptopp810/secblock.h"
using CryptoPP::SecByteBlock;
#include <iostream>
#include <string>
#include "../../function_lib/cryptopp810/modes.h"
#include "../../function_lib/cryptopp810/aes.h"
#include "../../function_lib/cryptopp810/filters.h"
/*
CryptoPP::SecByteBlock HexDecodeString(const char *hex)
{
CryptoPP::StringSource ss(hex, true, new CryptoPP::HexDecoder);
CryptoPP::SecByteBlock result((size_t)ss.MaxRetrievable());
ss.Get(result, result.size());
return result;
}*/


using namespace std;
using namespace CryptoPP;
#include <fstream>
#include <iomanip>

/****
operation mode 0 for ECB 
operation mode 1 for CBC

padding mode 1 for ZEROS padding
padding mode 2 for PKCS  padding
****/


void ECB_AES_encryption_zero(string plaintext,CryptoPP::byte key[]  ,ofstream& ofs) {
	
	std::string ciphertext;
	

	CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
	CryptoPP::ECB_Mode_ExternalCipher::Encryption operationEncryption(aesEncryption);
	CryptoPP::StreamTransformationFilter stfEncryptor(operationEncryption, new CryptoPP::StringSink(ciphertext), CryptoPP::BlockPaddingSchemeDef::ZEROS_PADDING);
	stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
	stfEncryptor.MessageEnd();

	std::cout << "Cipher Text (" << ciphertext.size() << " bytes)" << std::endl;
	for (int i = 0; i < ciphertext.size(); i++) {
		CryptoPP::byte temp;
		temp = static_cast<CryptoPP::byte>(ciphertext[i]);
		std::cout << std::hex << setw(2) << setfill('0') << (0xFF & temp);
		ofs << std::hex << setw(2) << setfill('0') << (0xFF & temp);
		if (i % 2 == 1)cout << " ";
	}
	cout << endl << endl;
	ofs << endl << endl;

}

void ECB_AES_encryption_pkcs(string plaintext, CryptoPP::byte key[], ofstream& ofs) {

	std::string ciphertext;


	CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
	CryptoPP::ECB_Mode_ExternalCipher::Encryption operationEncryption(aesEncryption);
	CryptoPP::StreamTransformationFilter stfEncryptor(operationEncryption, new CryptoPP::StringSink(ciphertext), CryptoPP::BlockPaddingSchemeDef::PKCS_PADDING);
	stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
	stfEncryptor.MessageEnd();

	std::cout << "Cipher Text (" << ciphertext.size() << " bytes)" << std::endl;
	for (int i = 0; i < ciphertext.size(); i++) {
		CryptoPP::byte temp;
		temp = static_cast<CryptoPP::byte>(ciphertext[i]);
		std::cout << std::hex << setw(2) << setfill('0') << (0xFF & temp);
		ofs << std::hex << setw(2) << setfill('0') << (0xFF & temp);
		if (i % 2 == 1)cout << " ";
	}
	cout << endl << endl;
	ofs << endl << endl;

}


void CBC_AES_encryption_zero(string plaintext, CryptoPP::byte key[], CryptoPP::byte iv[] ,ofstream& ofs) {

	std::string ciphertext;


	CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption operationEncryption( aesEncryption , iv );
	CryptoPP::StreamTransformationFilter stfEncryptor(operationEncryption, new CryptoPP::StringSink(ciphertext), CryptoPP::BlockPaddingSchemeDef::ZEROS_PADDING);
	stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
	stfEncryptor.MessageEnd();

	std::cout << "Cipher Text (" << ciphertext.size() << " bytes)" << std::endl;
	for (int i = 0; i < ciphertext.size(); i++) {
		CryptoPP::byte temp;
		temp = static_cast<CryptoPP::byte>(ciphertext[i]);
		std::cout << std::hex << setw(2) << setfill('0') << (0xFF & temp);
		ofs << std::hex << setw(2) << setfill('0') << (0xFF & temp);
		if (i % 2 == 1)cout << " ";
	}
	cout << endl << endl;
	ofs << endl << endl;

}

void CBC_AES_encryption_pkcs(string plaintext, CryptoPP::byte key[], CryptoPP::byte iv[], ofstream& ofs) {

	std::string ciphertext;


	CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption operationEncryption(aesEncryption, iv);
	CryptoPP::StreamTransformationFilter stfEncryptor(operationEncryption, new CryptoPP::StringSink(ciphertext), CryptoPP::BlockPaddingSchemeDef::PKCS_PADDING);
	stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
	stfEncryptor.MessageEnd();

	std::cout << "Cipher Text (" << ciphertext.size() << " bytes)" << std::endl;
	for (int i = 0; i < ciphertext.size(); i++) {
		CryptoPP::byte temp;
		temp = static_cast<CryptoPP::byte>(ciphertext[i]);
		std::cout << std::hex << setw(2) << setfill('0') << (0xFF & temp);
		ofs << std::hex << setw(2) << setfill('0') << (0xFF & temp);
		if (i % 2 == 1)cout << " ";
	}
	cout << endl << endl;
	ofs << endl << endl;

}


int main(int argc, char* argv[]) {

	
	CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH] = { '1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6'};
	
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
	memset(iv, 0x30, CryptoPP::AES::BLOCKSIZE);   //initialize the key to all ascii '0' = 0x30

	//
	// String and Sink setup
	//
	//std::string plaintext = "Hello World!";
	std::string plaintext = "AES is efficient in both software and hardware.";
	std::string ciphertext;
	//std::string decryptedtext;

	//
	// Dump Plain Text
	//
	std::cout << "Plain Text (" << plaintext.size() << " bytes)" << std::endl;
	std::cout << plaintext;
	std::cout << std::endl << std::endl;

	//
	// Create Cipher Text
	//
	ofstream ofs("output.txt");
	
	ECB_AES_encryption_zero(plaintext, key, ofs);
	ECB_AES_encryption_pkcs(plaintext, key, ofs);
	CBC_AES_encryption_zero(plaintext, key, iv,  ofs);
	CBC_AES_encryption_pkcs(plaintext, key, iv,  ofs);

	return 0;
}








/*


//
// Decrypt
//
CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedtext), CryptoPP::BlockPaddingSchemeDef::ZEROS_PADDING);
stfDecryptor.Put(reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size());
stfDecryptor.MessageEnd();

//
// Dump Decrypted Text
//
std::cout << "Decrypted Text: " << std::endl;
std::cout << decryptedtext;
std::cout << std::endl << std::endl;
*/