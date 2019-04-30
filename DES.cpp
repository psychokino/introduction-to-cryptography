#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <sys/time.h>
using namespace std;
#define DES_Key_Plaintext 10    ////  type the number of lines in  DES_Key_Plaintext.txt
#define DES_Key_Ciphertext 10   ////  type the number of lines in  DES_Key_Ciphertext.txt
#define INPUT_FILE argv[1]

int initial_p[]	 = {	58,50,42,34,26,18,10,2,
						60,52,44,36,28,20,12,4,
						62,54,46,38,30,22,14,6,
						64,56,48,40,32,24,16,8,
						57,49,41,33,25,17, 9,1,
						59,51,43,35,27,19,11,3,
						61,53,45,37,29,21,13,5,
						63,55,47,39,31,23,15,7};

int final_p[] = {	40,8,48,16,56,24,64,32,
					39,7,47,15,55,23,63,31,
					38,6,46,14,54,22,62,30,
					37,5,45,13,53,21,61,29,
					36,4,44,12,52,20,60,28,
					35,3,43,11,51,19,59,27,
					34,2,42,10,50,18,58,26,
					33,1,41, 9,49,17,57,25};
					
int round_p[] = {	16,7,20,21,29,12,28,17,
					1,15,23,26, 5,18,31,10,
					2, 8,24,14,32,27, 3, 9,
					19,13,30,6,22,11, 4,25};
					
int expansion_p[] ={32, 1, 2, 3, 4, 5,
					 4, 5, 6, 7, 8, 9,
					 8, 9,10,11,12,13,
					12,13,14,15,16,17,
					16,17,18,19,20,21,
					20,21,22,23,24,25,
					24,25,26,27,28,29,
					28,29,30,31,32, 1};
					
int PC_1[] = {	57,49,41,33,25,17, 9,
				 1,58,50,42,34,26,18,
				10, 2,59,51,43,35,27,
				19,11, 3,60,52,44,36,
				63,55,47,39,31,23,15,
				 7,62,54,46,38,30,22,
				14, 6,61,53,45,37,29,
				21,13, 5,28,20,12, 4};

int PC_2[] = {	14,17,11,24, 1, 5, 3,28,
				15, 6,21,10,23,19,12, 4,
				26, 8,16, 7,27,20,13, 2,
				41,52,31,37,47,55,30,40,
				51,45,33,48,44,49,39,56,
				34,53,46,42,50,36,29,32};

char DECtoHEX(int);
int decode_BINtoHEX(vector<int> bin,int start_bit);
void peep_vector(vector<int> x);
void peep_vector_bin(vector<int> x);
vector<int> key_48to64(vector<int> key);

			
void Initial_Permutation(vector<int>& text){
	vector<int> temp ;
	temp = text;
	
	for(int i=0;i<64;i++){
			text[i] = temp[ initial_p[i]-1 ];
	}
}


void Key_Initial_Permutation(vector<int>& key){
	vector<int> temp;
	temp = key ;
	key.assign(56,0);
	for(int i = 0 ; i < 56 ; i++){
		key[i] = temp[ PC_1[i]-1 ];
	}
}

vector<int> Key_Round_Permutation(vector<int>& left_key ,vector<int>& right_key ,int round ,int mode){
	//// warning ! output is 48 bit , key is 56 bit
	//// mode 1 = encryp   mode 0 = decryp
	vector<int> output,temp;
	
	int shift_bit = ( (round == 1) || (round == 2) || (round == 9) || (round == 16) ) ? 1 : 2 ;
	int x1,x2;
	
	if(mode == 1){
		
		for(int j = 0 ; j <shift_bit;j++){
			/// shift << 1 and circular shift
			x1 = left_key[0] ;
			x2 = right_key[0] ;

			for(int i=0;i<left_key.size()-1;i++){
				
				left_key[i] = left_key[i+1];
				right_key[i] = right_key[i+1];
			}
			left_key[left_key.size()-1] = x1;
			right_key[right_key.size()-1] = x2;
		}
		temp.insert(temp.end(),left_key.begin(),left_key.end());
		temp.insert(temp.end(),right_key.begin(),right_key.end());
		
		output.assign(48,0);
		for(int i=0; i<48; i++){
			output[i] = temp[ PC_2[i]-1 ] ;
		}

		return output;
		
	}
	else if(mode == 0){
		temp.insert(temp.end(),left_key.begin(),left_key.end());
		temp.insert(temp.end(),right_key.begin(),right_key.end());
		
		output.assign(48,0);
		for(int i=0; i<48; i++){
			output[i] = temp[ PC_2[i]-1 ] ;
		}

		
		
		for(int j = 0 ; j <shift_bit;j++){
			/// shift >> 1 
			x1 = left_key[left_key.size()-1];
			x2 = right_key[right_key.size()-1];
			for(int i = left_key.size()-1 ; i > 0 ; i--){ ///shift << 1
				left_key[i] = left_key[i-1] ;
				right_key[i] = right_key[i-1] ;
			}
			left_key[0] = x1;
			right_key[0] = x2;
		}
		
		return output;
		
	}
	else{
		cout<<"program error"<<endl;
		exit(1);
		return output;
	}

	
	
}

void Expansion(vector<int>& Right){
	vector<int> temp ;
	temp = Right ;
	Right.assign(48,0);
	for(int i=0;i<48;i++){
		Right[i] = temp[ (expansion_p[i]-1) ];
	}
	
}

char DECtoHEX(int dec_in){

	static char HEX[16] = { '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'} ;
	return HEX[dec_in];
}

int decode_BINtoHEX(vector<int> bin,int start_bit){
	int number;
	number = bin[start_bit]*8 + bin[start_bit+1]*4 + bin[start_bit+2]*2 + bin[start_bit+3] ; 
	return number;
}

vector<int> Sbox_output(int ,vector<int>);

void peep_vector(vector<int> x){
	
	for(int i=0; i<x.size() ;i=i+4){
		cout<<DECtoHEX( decode_BINtoHEX(x,i) );
	}
}

void peep_vector_bin(vector<int> x){
	
	for(int i=0;i<x.size();i++){
		cout<<x[i];
	}
	cout<<endl;
}

vector<int> key_48to64(vector<int> key){
	vector<int> temp;
	temp.assign(64,0);
	for(int i=0;i<8;i++){
		temp[8*i]=0;
		temp[8*i+1]=0;
		temp[8*i+2]=key[6*i];
		temp[8*i+3]=key[6*i+1];
		temp[8*i+4]=key[6*i+2];
		temp[8*i+5]=key[6*i+3];
		temp[8*i+6]=key[6*i+4];
		temp[8*i+7]=key[6*i+5];
	}
	return temp;
}

int main(int argc ,char** argv){
	ifstream ifs;
	ifs.open("DES-Key-Plaintext.txt");
	ofstream ofs;
	ofs.open("out.txt");
	clock_t start,end;
	double cpu_time_used;
	string buf;
	stringstream ss;
	unsigned long long int plaintext,key;
	unsigned int L,R;
	
	vector<int> bin_plain,bin_key;
	int key_mode = 1;
	int INPUT_SIZE = DES_Key_Plaintext + DES_Key_Ciphertext;
	//string plaintext,key;
	for(int i=0 ;i<INPUT_SIZE ; i++){
		if(i == DES_Key_Plaintext ){
			ifs.close();
			ifs.open("DES-Key-Ciphertext.txt");
			key_mode = 0;
		}
		//ifs>>key>>plaintext;
		bin_plain.clear();
		bin_key.clear();
		ss.str("");
		ss.clear();
		getline(ifs,buf);
		if( i== INPUT_SIZE-1 )start = clock();  /// time start when executing the last DES operation 
		ss<<hex<<buf;

		ss>>key;
		ss>>plaintext;
		
		bin_plain.assign(64,0);
		bin_key.assign(64,0);
		
		///// [0] : MSB  [63] : LSB
		for(int i = 63 ; i >= 0 ; i--){
			bin_plain[i] =( plaintext % 2 );
			plaintext = plaintext >> 1 ;
			bin_key[i] = (key % 2) ;
			key = key >> 1;
		}
		
		///// initial permutation	
		Initial_Permutation(bin_plain);
		Key_Initial_Permutation(bin_key);
		vector<int> C_key,D_key;

		C_key.insert(C_key.end(),bin_key.begin(),bin_key.begin()+28);
		D_key.insert(D_key.end(),bin_key.begin()+28,bin_key.end());
		
		///// round
		vector<int> L,R,temp;
		vector<int> L_next,R_next;
		L.insert(L.end(),bin_plain.begin(),bin_plain.begin()+32);
		R.insert(R.end(),bin_plain.begin()+32,bin_plain.end());
		L_next.assign(32,0);
		R_next.assign(32,0);
		
			
		int round ;
		if(key_mode==1)round = 1 ;
		if(key_mode==0)round = 16 ;
		while( (round<=16) && (round>=1) ){
			L_next = R;

			/// E			
			Expansion(R);

			/// XOR
			temp = Key_Round_Permutation(C_key,D_key,round,key_mode);		
			for(int i=0 ; i<R.size() ; i++){
				R[i] = R[i] ^ temp[i];
			}

			/// Sbox
			temp.clear();
			vector<int> sbox_output_buf;
			for(int i=0 ;i<8;i++){
				sbox_output_buf = Sbox_output(i,R);
				temp.insert(temp.begin()+i*4,sbox_output_buf.begin(),sbox_output_buf.end());
			}
			R.assign(32,0);
			R = temp ;
			
			/// P
			for(int i=0;i<R.size();i++){
				R[i] = temp[ round_p[i]-1 ];
			}
			
			/// last xor
			for(int i=0;i<L.size();i++){
				R_next[i] = R[i] ^ L[i];
			}
			R = R_next;
			L = L_next;
			
			if(key_mode==1)round++ ;
			if(key_mode==0)round-- ;

		}
		
		/// 32 bit swap
		
		L_next = R;
		R_next = L;
		
		/// combine
		for(int i=0;i<32;i++){
			bin_plain[i] = L_next[i];
			bin_plain[i+32] = R_next[i];
			
		}
		
		/// final permutation
		temp = bin_plain;
		for(int i=0;i<64;i++){
			bin_plain[i] = temp[ final_p[i]-1 ];
		}
		
		string output_stream;
		int dec_in;
		char c;
		for(int i=0 ; i <64 ; i = i+4){
			dec_in =  decode_BINtoHEX(bin_plain, i ) ;
			
			output_stream.push_back( DECtoHEX(dec_in) );
		}
		
		if( i == INPUT_SIZE-1 ){ ///  time record of last DES operation
			end = clock();
			cpu_time_used = ((double) (end - start)) / ((double)(CLOCKS_PER_SEC));
			cpu_time_used *= 1000.0 ;
			
			
		}
		
		ofs<<output_stream<<endl;
		if( i == INPUT_SIZE-1 ){ /// time output
			cout<<"DES exec time : "<<cpu_time_used<<"  milliseconds. "<<endl;
			ofs<<cpu_time_used<<endl;
		}
	}

	
}

vector<int> Sbox_output(int S ,vector<int> input){  /// input 48 bit  , S is Sbox block , start bit  42 36 30  || 24 18 12 6 0
																	/// output = size 4 vector 3~0
	
	int b16,b2345;
	int start_bit = S * 6;

	b16 = input[start_bit]*2 + input[start_bit+5] ;
	b2345 = input[start_bit + 1]*8 + input[start_bit + 2]*4 +  input[start_bit + 3]*2 +  input[start_bit + 4] ;

	static int S_box[][4][16] = {	
		{	{14, 4,13, 1, 2,15,11, 8, 3,10, 6,12, 5, 9, 0, 7},//S1 MSB
			{ 0,15, 7, 4,14, 2,13, 1,10, 6,12,11, 9, 5, 3, 8},
			{ 4, 1,14, 8,13, 6, 2,11,15,12, 9, 7, 3,10, 5, 0},
			{15,12, 8, 2, 4, 9, 1, 7, 5,11, 3,14,10, 0, 6,13} },
			
		{	{15, 1, 8,14, 6,11, 3, 4, 9, 7, 2,13,12, 0, 5,10},//S2
			{ 3,13, 4, 7,15, 2, 8,14,12, 0, 1,10, 6, 9,11, 5},
			{ 0,14, 7,11,10, 4,13, 1, 5, 8,12, 6, 9, 3, 2,15},
			{13, 8,10, 1, 3,15, 4, 2,11, 6, 7,12, 0, 5,14, 9} },

		{	{10, 0, 9,14, 6, 3,15, 5, 1,13,12, 7,11, 4, 2, 8},//S3
			{13, 7, 0, 9, 3, 4, 6,10, 2, 8, 5,14,12,11,15, 1},
			{13, 6, 4, 9, 8,15, 3, 0,11, 1, 2,12, 5,10,14, 7},
			{ 1,10,13, 0, 6, 9, 8, 7, 4,15,14, 3,11, 5, 2,12} },
			
		{	{ 7,13,14, 3, 0, 6, 9,10, 1, 2, 8, 5,11,12, 4,15},//S4
			{13, 8,11, 5, 6,15, 0, 3, 4, 7, 2,12, 1,10,14, 9},
			{10, 6, 9, 0,12,11, 7,13,15, 1, 3,14, 5, 2, 8, 4},
			{ 3,15, 0, 6,10, 1,13, 8, 9, 4, 5,11,12, 7, 2,14} },
			
		{	{ 2,12, 4, 1, 7,10,11, 6, 8, 5, 3,15,13, 0,14, 9},//S5
			{14,11, 2,12, 4, 7,13, 1, 5, 0,15,10, 3, 9, 8, 6},
			{ 4, 2, 1,11,10,13, 7, 8,15, 9,12, 5, 6, 3, 0,14},
			{11, 8,12, 7, 1,14, 2,13, 6,15, 0, 9,10, 4, 5, 3} },
			
			
		{	{12, 1,10,15, 9, 2, 6, 8, 0,13, 3, 4,14, 7, 5,11},//S6
			{10,15, 4, 2, 7,12, 9, 5, 6, 1,13,14, 0,11, 3, 8},
			{ 9,14,15, 5, 2, 8,12, 3, 7, 0, 4,10, 1,13,11, 6},
			{ 4, 3, 2,12, 9, 5,15,10,11,14, 1, 7, 6, 0, 8,13} },
			
		{	{ 4,11, 2,14,15, 0, 8,13, 3,12, 9, 7, 5,10, 6, 1},//S7
			{13, 0,11, 7, 4, 9, 1,10,14, 3, 5,12, 2,15, 8, 6},
			{ 1, 4,11,13,12, 3, 7,14,10,15, 6, 8, 0, 5, 9, 2},
			{ 6,11,13, 8, 1, 4,10, 7, 9, 5, 0,15,14, 2, 3,12} },
			
		{	{13, 2, 8, 4, 6,15,11, 1,10, 9, 3,14, 5, 0,12, 7},//S8 LSB
			{ 1,15,13, 8,10, 3, 7, 4,12, 5, 6,11, 0,14, 9, 2},
			{ 7,11, 4, 1, 9,12,14, 2, 0, 6,10,13,15, 3, 5, 8},
			{ 2, 1,14, 7, 4,10, 8,13,15,12, 9, 0, 3, 5, 6,11} } 
		
	};
	
	vector<int> output;
	output.assign(4,0);
	
	int table_lookup_value = S_box[S][b16][b2345];
	for(int i=3 ; i >= 0 ;i--){
		output[i] = table_lookup_value % 2 ;
		table_lookup_value = table_lookup_value >> 1;
	}

	return output;
	
}