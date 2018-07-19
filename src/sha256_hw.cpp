#include "sha256_hw.h"

#define HW_CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define HW_MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

ap_uint<32> HW_EP0(ap_uint<32> x)
{
#pragma HLS INLINE
	ap_uint<32> a = (x.range(1,0), x.range(31,2));
	ap_uint<32> b = (x.range(12,0), x.range(31,13));
	ap_uint<32> c = (x.range(22,0), x.range(31,22));
	return a ^ b ^ c;
}

ap_uint<32> HW_EP1(ap_uint<32> x)
{
#pragma HLS INLINE
	ap_uint<32> a = (x.range(5,0), x.range(31,6));
	ap_uint<32> b = (x.range(10,0), x.range(31,11));
	ap_uint<32> c = (x.range(24,0), x.range(31,25));
	return a ^ b ^ c;
}

ap_uint<32> HW_SIG0(ap_uint<32> x)
{
#pragma HLS INLINE
	ap_uint<32> a = (x.range(6,0), x.range(31,7));
	ap_uint<32> b = (x.range(17,0), x.range(31,18));
	ap_uint<32> c = x.range(31,3);
	return a ^ b ^ c;
}

ap_uint<32> HW_SIG1(ap_uint<32> x)
{
#pragma HLS INLINE
	ap_uint<32> a = (x.range(16,0), x.range(31,17));
	ap_uint<32> b = (x.range(18,0), x.range(31,19));
	ap_uint<32> c = x.range(31,10);
	return a ^ b ^ c;
}

void hw_sha256_transform(ap_uint<32> state[8], ap_uint<512> din);

void hw_sha256(hls::stream<ap_uint<512> > &data, ap_uint<8> hash[SHA256_BLOCK_SIZE])
{
#pragma HLS ARRAY_PARTITION variable=hash complete dim=0

	ap_uint<32> state[8];
#pragma HLS ARRAY_PARTITION variable=state complete dim=0

	state[0] = 0x6a09e667;
	state[1] = 0xbb67ae85;
	state[2] = 0x3c6ef372;
	state[3] = 0xa54ff53a;
	state[4] = 0x510e527f;
	state[5] = 0x9b05688c;
	state[6] = 0x1f83d9ab;
	state[7] = 0x5be0cd19;

	UPDATE:
	while (!data.empty())
	{
#pragma HLS LOOP_TRIPCOUNT min=1024 max=1024 avg=1024
		ap_uint<512> din = data.read();
		hw_sha256_transform(state, din);
	}

	// modify byte ordering
	OUTPUT:
	for (int i = 0; i < 4; ++i) {
#pragma HLS UNROLL
		hash[i]      = (state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4]  = (state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8]  = (state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}


void hw_sha256_transform(ap_uint<32> state[8], ap_uint<512> din)
{
#pragma HLS INLINE
#pragma HLS ARRAY_PARTITION variable=state complete dim=0

	static const ap_uint<32> k[64] = {
		0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
		0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
		0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
		0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
		0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
		0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
		0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
		0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
	};
#pragma HLS ARRAY_PARTITION variable=k complete dim=0

	//	i=0..16,
	ap_uint<32>	m0[16];
#pragma HLS ARRAY_PARTITION variable=m0 complete dim=0
	ap_uint<32>	m[16];
#pragma HLS ARRAY_PARTITION variable=m complete dim=0

	ap_uint<32> a = state[0];
	ap_uint<32> b = state[1];
	ap_uint<32> c = state[2];
	ap_uint<32> d = state[3];
	ap_uint<32> e = state[4];
	ap_uint<32> f = state[5];
	ap_uint<32> g = state[6];
	ap_uint<32> h = state[7];

	ap_uint<32> mm = 0;

	for (int i = 0; i < 16; ++i)
	{
#pragma HLS UNROLL
		m0[i] = din.range(512-1-i*32, 512-32-i*32);
	}

	ROTATE:
	for (int i = 0; i < 64; ++i)
	{
#pragma HLS PIPELINE
#pragma HLS UNROLL factor=2
		mm = (i<16) ? m0[i] : mm;
		ap_uint<32> t1 = h + HW_EP1(e) + HW_CH(e,f,g) + k[i] + mm;
		ap_uint<32> t2 = HW_EP0(a) + HW_MAJ(a,b,c);

		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;

		for (int j=15; j>0; --j) m[j] = m[j-1];
		m[0] = mm;
		mm = HW_SIG1(m[2-1]) + m[7-1] + HW_SIG0(m[15-1]) + m[16-1];
	}

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;
}
