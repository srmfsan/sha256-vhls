#ifndef SHA256_HW_H
#define SHA256_HW_H

#include <ap_int.h>
#include "hls_stream.h"

#define SHA256_BLOCK_SIZE 32

void hw_sha256(hls::stream<ap_uint<512> > &data, ap_uint<8> hash[SHA256_BLOCK_SIZE]);

#endif

