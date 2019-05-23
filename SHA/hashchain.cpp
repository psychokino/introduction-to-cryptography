

#include <bits/stdc++.h>
#include "../../function_lib/cryptopp810/sha.h"


using namespace CryptoPP;
using namespace std;

#define DIGESTSIZE SHA256::DIGESTSIZE


bool stop_task = false;

uint32_t nonce_generator() {
	uint32_t NONCE = rand();

	NONCE = NONCE << 15;
	NONCE += rand();
	NONCE = NONCE << 15;
	NONCE += rand() % 4;
	
	return NONCE;
}

string nonce_attach(string msg,uint32_t nonce) {
	msg.push_back(nonce >> 24);
	msg.push_back(nonce >> 16);
	msg.push_back(nonce >> 8);
	msg.push_back(nonce);
	return msg;

}

void sha256_digest_computation(string& msg, byte* digest) {
	SHA256 digest_compute;
	int sizeof_digest = digest_compute.DigestSize();
	
	digest_compute.CalculateDigest(digest, (const byte*)msg.c_str(), msg.size());

}

template<class T>
string byte_to_string(T b) {
	string s;
	for (int i = 0; i < DIGESTSIZE; i++) {
		s.push_back(b[i]);
	}
	return s;
}

template<class T>
string byte_to_hex(T b) {
	string dict = "0123456789ABCDEF";
	string msg;
	uint8_t temp1,temp2;
	for (int i = 0; i < DIGESTSIZE ; i++) {
		temp1 = b[i];
		temp2 = temp1 % 16;
		temp1 = temp1 >> 4;
		msg = msg + dict[temp1] + dict[temp2];
	}
	return msg;
}

void mining_function(byte* msg, int leading_zeros, uint32_t start_nonce, ofstream& ofs ) {
	byte new_msg[DIGESTSIZE];
	uint32_t NONCE = start_nonce;
	uint32_t compute_nonce = numeric_limits<uint32_t>::max();
	if (leading_zeros > 2) NONCE = nonce_generator();
	
	while (compute_nonce--) {
		if (stop_task) {
			
			break;
		}
		NONCE++;
		string extend_msg = nonce_attach( byte_to_string(msg) , NONCE);
		sha256_digest_computation(extend_msg, new_msg);
		bool keep_mining = true;

		string temp = byte_to_hex(new_msg);
		//cout << temp << "     keep mining ?   ";
		for (int i = 0; i < leading_zeros; i++) {
			if (temp[i] != '0') {
				keep_mining = false;
				break;
			}
		}
		if (temp[leading_zeros] == '0') keep_mining = false;
		//cout << keep_mining << endl;
		if (keep_mining) { // if true = findout the meet hash value
			ofs << dec << leading_zeros<<endl;
			ofs << byte_to_hex(msg) << endl;
			ofs << hex << setfill('0') << setw(8) << NONCE << endl;
			ofs << byte_to_hex(new_msg) << endl;
			cout << dec << leading_zeros << endl;
			cout << byte_to_hex(msg) << endl;
			cout << hex << setfill('0') << setw(8) << NONCE << endl;
			cout << byte_to_hex(new_msg) << endl;
			mining_function(new_msg, leading_zeros + 1 , 0 , ofs);
		}

		
	}
}

void thread_openfile(byte* msg, int leading_zeros, int partition) {

	char aa = partition + 48;
	string filename;
	filename.push_back(aa);
	filename += "xxx_of_zeros_output.txt";
	ofstream ofs(filename);
	uint32_t start_nonce = (numeric_limits<uint32_t>::max() / 4) * (partition - 1);
	mining_function(msg, leading_zeros, start_nonce, ofs);
	ofs.close();
}

void terminate_task() {
	string temp;
	
	while (1) {
		cout << "type 'stop' to end the mining : "<<endl;
		cin >> temp;
		cout << endl;
		if (temp == "stop"){
			stop_task = true;
			break;
		}
		
	}
}


int main() {
	
	SHA256 temp_SHA;
	string temp_msg = "Bitcoin is a cryptocurrency, a form of electronic cash.";
	byte temp_output[DIGESTSIZE];
	sha256_digest_computation(temp_msg, temp_output);
	cout << byte_to_hex(temp_output) << endl;
	ofstream ofs("out.txt");

	ofs << byte_to_hex(temp_output) << endl;
	ofs.close();


	//string message = "0DE32E85C2AC9D96659D42C8A3EA3D2C05FDE384B468E6EFE062B6E21288CBCA";
	string message = "0DE32E85C2AC9D96659D42C8A3EA3D2C05FDE384B468E6EFE062B6E21288CBCA";
	byte digest[DIGESTSIZE];
	for (int i = 0; i < message.size(); i = i + 2) {
		string s;
		s += (message[i]);
		s += message[i + 1];
		stringstream ss;
		ss << hex << s;
		int temp;
		ss >> temp;
		digest[i / 2] = temp;

	}
	
	
	//sha256_digest_computation(message, digest);
	cout << "the initial hash value :\n" << byte_to_hex(digest) << endl;
	srand((int)time(NULL));

	thread t1(thread_openfile,digest, 2, 1);
	thread t2(thread_openfile,digest, 2, 2);
	thread t3(thread_openfile,digest, 2, 3);
	thread t4(thread_openfile,digest, 2, 4);
	thread t5(terminate_task);
	t5.join();
	t1.join();
	t2.join();
	t3.join();
	t4.join();
	

	return 0;

}

