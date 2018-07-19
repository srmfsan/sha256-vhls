#include <stdio.h>
#include <memory.h>
#include <string.h>
#include "sha256_hw.h"
#include <vector>

using std::vector;

void hw_sha256_add(char text[], size_t len, vector<ap_uint<8> > &data)
{
	for (int i=0; i<len; ++i)
	{
		data.push_back(text[i]);
	}
}

void hw_sha256_padding(vector<ap_uint<8> > &data, hls::stream<ap_uint<512> > &input)
{
	int len = data.size();
	int rem = len % 64;

	if (rem < 56) {
		//	最終ブロックにメッセージサイズを入れることができる場合
		//	あるいはメッセージサイズが64の倍数バイトの場合
		data.push_back(0x80);
		//	メッセージサイズ直前まで埋める
		for (int i=rem+1; i<56; ++i)
		{
			data.push_back(0x00);
		}
	}
	else
	{
		//	ストップビットを挿入して、ブロック終端までゼロ詰め
		data.push_back(0x80);
		for (int i=rem+1; i<64; ++i)
		{
			data.push_back(0x00);
		}

		//	次のブロックにメッセージサイズを入れる
		for (int i=0; i<56; ++i)
		{
			data.push_back(0x00);
		}
	}

	// メッセージ長を追記
	unsigned long long bitlen = len * 8;
	data.push_back((bitlen >> 56) & 0xFF);
	data.push_back((bitlen >> 48) & 0xFF);
	data.push_back((bitlen >> 40) & 0xFF);
	data.push_back((bitlen >> 32) & 0xFF);
	data.push_back((bitlen >> 54) & 0xFF);
	data.push_back((bitlen >> 16) & 0xFF);
	data.push_back((bitlen >>  8) & 0xFF);
	data.push_back((bitlen >>  0) & 0xFF);

	// 入力ストリームに積む
	for (int i=0; i<data.size() / 64; ++i)
	{
		ap_uint<512> d = 0;
		for (int j=0; j<64; ++j)
		{
			d = (d.range(503,0), data[i*64+j]);
		}
		input.write(d);
	}
}

int hw_sha256_test()
{
	char text1[] = {"abc"};
	char text2[] = {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"};
	char text3[] = {"aaaaaaaaaa"};
	unsigned char hash1[SHA256_BLOCK_SIZE] = {0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
	                                 0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
	unsigned char hash2[SHA256_BLOCK_SIZE] = {0x24,0x8d,0x6a,0x61,0xd2,0x06,0x38,0xb8,0xe5,0xc0,0x26,0x93,0x0c,0x3e,0x60,0x39,
	                                 0xa3,0x3c,0xe4,0x59,0x64,0xff,0x21,0x67,0xf6,0xec,0xed,0xd4,0x19,0xdb,0x06,0xc1};
	unsigned char hash3[SHA256_BLOCK_SIZE] = {0xcd,0xc7,0x6e,0x5c,0x99,0x14,0xfb,0x92,0x81,0xa1,0xc7,0xe2,0x84,0xd7,0x3e,0x67,
	                                 0xf1,0x80,0x9a,0x48,0xa4,0x97,0x20,0x0e,0x04,0x6d,0x39,0xcc,0xc7,0x11,0x2c,0xd0};
	ap_uint<8> buf[SHA256_BLOCK_SIZE];

	vector<ap_uint<8> > data;
	hls::stream<ap_uint<512> > input;

	int idx;
	int pass = 1;

	data.clear();
	data.reserve(strlen((const char*)text1));
	hw_sha256_add(text1, strlen((const char*)text1), data);
	hw_sha256_padding(data, input);
	hw_sha256(input, buf);

	pass = pass && !memcmp(hash1, buf, SHA256_BLOCK_SIZE);
	printf("pass1:%d\n", pass);

	data.clear();
	data.reserve(strlen((const char*)text2));
	hw_sha256_add(text2, strlen((const char*)text2), data);
	hw_sha256_padding(data, input);
	hw_sha256(input, buf);
	pass = pass && !memcmp(hash2, buf, SHA256_BLOCK_SIZE);
	printf("pass2:%d\n", pass);

	data.clear();
	data.reserve(strlen((const char*)text3)*100000);
	for (int its=0; its<100000; ++its)
	{
		hw_sha256_add(text3, strlen((const char*)text3), data);
	}
	hw_sha256_padding(data, input);
	hw_sha256(input, buf);
	pass = pass && !memcmp(hash3, buf, SHA256_BLOCK_SIZE);
	printf("pass3:%d\n", pass);

	return(pass);
}

int main()
{
	int hw_pass = hw_sha256_test();
	printf("SHA-256 HW tests: %s\n", hw_pass ? "SUCCEEDED" : "FAILED");

	return(0);
}
