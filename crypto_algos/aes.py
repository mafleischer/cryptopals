#!/usr/bin/python3

import numpy as np
import collections
import struct

from crypto_algos.helpers import rotateList, stateGenerator, makeNDArrayFrom, xorBytestrings
from crypto_algos import misc

# multiplicative inverse, galois field; used to obscure the relationship between key and cipher
# composed of balanced highly nonlinear Boolean Functions
sbox = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]

inv_sbox = [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
            0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
            0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
            0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
            0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
            0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
            0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
            0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
            0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
            0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
            0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
            0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
            0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
            0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]

mds_matrix_flat = [2, 3, 1, 1, 1, 2, 3, 1, 1, 1, 2, 3, 3, 1, 1, 2]

inv_mds_matrix_flat = [0x0e, 0x0b, 0x0d, 0x09, 0x09, 0x0e,
                       0x0b, 0x0d, 0x0d, 0x09, 0x0e, 0x0b, 0x0b, 0x0d, 0x09, 0x0e]

# mds 1 and 2 used in Mix Columns
mds_lookup_2 = [0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
                0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e,
                0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e,
                0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e,
                0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e,
                0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe,
                0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde,
                0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee, 0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe,
                0x1b, 0x19, 0x1f, 0x1d, 0x13, 0x11, 0x17, 0x15, 0x0b, 0x09, 0x0f, 0x0d, 0x03, 0x01, 0x07, 0x05,
                0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35, 0x2b, 0x29, 0x2f, 0x2d, 0x23, 0x21, 0x27, 0x25,
                0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55, 0x4b, 0x49, 0x4f, 0x4d, 0x43, 0x41, 0x47, 0x45,
                0x7b, 0x79, 0x7f, 0x7d, 0x73, 0x71, 0x77, 0x75, 0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61, 0x67, 0x65,
                0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95, 0x8b, 0x89, 0x8f, 0x8d, 0x83, 0x81, 0x87, 0x85,
                0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5, 0xab, 0xa9, 0xaf, 0xad, 0xa3, 0xa1, 0xa7, 0xa5,
                0xdb, 0xd9, 0xdf, 0xdd, 0xd3, 0xd1, 0xd7, 0xd5, 0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7, 0xc5,
                0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5, 0xeb, 0xe9, 0xef, 0xed, 0xe3, 0xe1, 0xe7, 0xe5]

inv_mds_lookup_2 = [0, 141, 1, 140, 2, 143, 3, 142, 4, 137, 5, 136, 6, 139, 7, 138,
                    8, 133, 9, 132, 10, 135, 11, 134, 12, 129, 13, 128, 14, 131, 15, 130, 16, 157, 17,
                    156, 18, 159, 19, 158, 20, 153, 21, 152, 22, 155, 23, 154, 24, 149, 25, 148, 26, 151,
                    27, 150, 28, 145, 29, 144, 30, 147, 31, 146, 32, 173, 33, 172, 34, 175, 35, 174, 36,
                    169, 37, 168, 38, 171, 39, 170, 40, 165, 41, 164, 42, 167, 43, 166, 44, 161, 45, 160,
                    46, 163, 47, 162, 48, 189, 49, 188, 50, 191, 51, 190, 52, 185, 53, 184, 54, 187, 55, 186,
                    56, 181, 57, 180, 58, 183, 59, 182, 60, 177, 61, 176, 62, 179, 63, 178, 64, 205, 65,
                    204, 66, 207, 67, 206, 68, 201, 69, 200, 70, 203, 71, 202, 72, 197, 73, 196, 74, 199,
                    75, 198, 76, 193, 77, 192, 78, 195, 79, 194, 80, 221, 81, 220, 82, 223, 83, 222, 84,
                    217, 85, 216, 86, 219, 87, 218, 88, 213, 89, 212, 90, 215, 91, 214, 92, 209, 93, 208,
                    94, 211, 95, 210, 96, 237, 97, 236, 98, 239, 99, 238, 100, 233, 101, 232, 102, 235,
                    103, 234, 104, 229, 105, 228, 106, 231, 107, 230, 108, 225, 109, 224, 110, 227, 111,
                    226, 112, 253, 113, 252, 114, 255, 115, 254, 116, 249, 117, 248, 118, 251, 119, 250,
                    120, 245, 121, 244, 122, 247, 123, 246, 124, 241, 125, 240, 126, 243, 127, 242]

mds_lookup_3 = [0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09, 0x18, 0x1b, 0x1e, 0x1d, 0x14, 0x17, 0x12, 0x11,
                0x30, 0x33, 0x36, 0x35, 0x3c, 0x3f, 0x3a, 0x39, 0x28, 0x2b, 0x2e, 0x2d, 0x24, 0x27, 0x22, 0x21,
                0x60, 0x63, 0x66, 0x65, 0x6c, 0x6f, 0x6a, 0x69, 0x78, 0x7b, 0x7e, 0x7d, 0x74, 0x77, 0x72, 0x71,
                0x50, 0x53, 0x56, 0x55, 0x5c, 0x5f, 0x5a, 0x59, 0x48, 0x4b, 0x4e, 0x4d, 0x44, 0x47, 0x42, 0x41,
                0xc0, 0xc3, 0xc6, 0xc5, 0xcc, 0xcf, 0xca, 0xc9, 0xd8, 0xdb, 0xde, 0xdd, 0xd4, 0xd7, 0xd2, 0xd1,
                0xf0, 0xf3, 0xf6, 0xf5, 0xfc, 0xff, 0xfa, 0xf9, 0xe8, 0xeb, 0xee, 0xed, 0xe4, 0xe7, 0xe2, 0xe1,
                0xa0, 0xa3, 0xa6, 0xa5, 0xac, 0xaf, 0xaa, 0xa9, 0xb8, 0xbb, 0xbe, 0xbd, 0xb4, 0xb7, 0xb2, 0xb1,
                0x90, 0x93, 0x96, 0x95, 0x9c, 0x9f, 0x9a, 0x99, 0x88, 0x8b, 0x8e, 0x8d, 0x84, 0x87, 0x82, 0x81,
                0x9b, 0x98, 0x9d, 0x9e, 0x97, 0x94, 0x91, 0x92, 0x83, 0x80, 0x85, 0x86, 0x8f, 0x8c, 0x89, 0x8a,
                0xab, 0xa8, 0xad, 0xae, 0xa7, 0xa4, 0xa1, 0xa2, 0xb3, 0xb0, 0xb5, 0xb6, 0xbf, 0xbc, 0xb9, 0xba,
                0xfb, 0xf8, 0xfd, 0xfe, 0xf7, 0xf4, 0xf1, 0xf2, 0xe3, 0xe0, 0xe5, 0xe6, 0xef, 0xec, 0xe9, 0xea,
                0xcb, 0xc8, 0xcd, 0xce, 0xc7, 0xc4, 0xc1, 0xc2, 0xd3, 0xd0, 0xd5, 0xd6, 0xdf, 0xdc, 0xd9, 0xda,
                0x5b, 0x58, 0x5d, 0x5e, 0x57, 0x54, 0x51, 0x52, 0x43, 0x40, 0x45, 0x46, 0x4f, 0x4c, 0x49, 0x4a,
                0x6b, 0x68, 0x6d, 0x6e, 0x67, 0x64, 0x61, 0x62, 0x73, 0x70, 0x75, 0x76, 0x7f, 0x7c, 0x79, 0x7a,
                0x3b, 0x38, 0x3d, 0x3e, 0x37, 0x34, 0x31, 0x32, 0x23, 0x20, 0x25, 0x26, 0x2f, 0x2c, 0x29, 0x2a,
                0x0b, 0x08, 0x0d, 0x0e, 0x07, 0x04, 0x01, 0x02, 0x13, 0x10, 0x15, 0x16, 0x1f, 0x1c, 0x19, 0x1a]

inv_mds_lookup_3 = [0, 246, 247, 1, 245, 3, 2, 244, 241, 7, 6, 240, 4, 242, 243, 5,
                    249, 15, 14, 248, 12, 250, 251, 13, 8, 254, 255, 9, 253, 11, 10, 252, 233, 31, 30,
                    232, 28, 234, 235, 29, 24, 238, 239, 25, 237, 27, 26, 236, 16, 230, 231, 17, 229,
                    19, 18, 228, 225, 23, 22, 224, 20, 226, 227, 21, 201, 63, 62, 200, 60, 202, 203, 61,
                    56, 206, 207, 57, 205, 59, 58, 204, 48, 198, 199, 49, 197, 51, 50, 196, 193, 55, 54,
                    192, 52, 194, 195, 53, 32, 214, 215, 33, 213, 35, 34, 212, 209, 39, 38, 208, 36, 210,
                    211, 37, 217, 47, 46, 216, 44, 218, 219, 45, 40, 222, 223, 41, 221, 43, 42, 220, 137,
                    127, 126, 136, 124, 138, 139, 125, 120, 142, 143, 121, 141, 123, 122, 140, 112, 134,
                    135, 113, 133, 115, 114, 132, 129, 119, 118, 128, 116, 130, 131, 117, 96, 150, 151,
                    97, 149, 99, 98, 148, 145, 103, 102, 144, 100, 146, 147, 101, 153, 111, 110, 152, 108,
                    154, 155, 109, 104, 158, 159, 105, 157, 107, 106, 156, 64, 182, 183, 65, 181, 67, 66,
                    180, 177, 71, 70, 176, 68, 178, 179, 69, 185, 79, 78, 184, 76, 186, 187, 77, 72, 190,
                    191, 73, 189, 75, 74, 188, 169, 95, 94, 168, 92, 170, 171, 93, 88, 174, 175, 89, 173,
                    91, 90, 172, 80, 166, 167, 81, 165, 83, 82, 164, 161, 87, 86, 160, 84, 162, 163, 85]

# used in key expansion
rcon = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
        0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
        0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
        0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
        0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
        0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
        0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
        0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
        0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
        0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
        0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
        0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
        0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
        0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
        0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
        0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d]


def mdsLookup(byte, num):
    """
    Used in aesMixColumns;
    lookup byte in table mds_lookup_[num];
    byte not changed for 1
    """
    if num not in (1, 2, 3):
        print("mds_lookup: invalid num {0}".format(num))
        exit(1)
    if num == 1:
        return byte
    if num == 2:
        return mds_lookup_2[byte]
    else:
        return mds_lookup_3[byte]


def gmul(a, b):
    if b == 1:
        return a
    n = np.uint8(a)
    x = np.uint8(b)
    result = np.uint8(0)
    while n and x:
        if x & 1:
            result ^= n
        if n & 0x80:
            n = (n << 1) ^ 0x011b
        else:
            n <<= 1
        x >>= 1
    return result

'''
################# AES functions #####################
'''


def aesEncrypt(bstr_msg, bstr_key, num_bits, mode='ecb', bstr_IV=None):
    if len(bstr_key) != 16:
        # no key derivation yet
        print("Unsuitable key length!")
        exit(1)

    # without padding for now
    #bstr_msg = misc.padPKCS7(bstr_msg, 16)
    state_iter = stateGenerator(bstr_msg, 16)
    rounds = {128: 10, 192: 12, 256: 14}
    round_keys = aesKeyExpansion(bstr_key)
    cipher = b''

    preceding_cipher_block = bstr_IV

    for state in state_iter:
        if mode == 'cbc':
            state = xorBytestrings(state, preceding_cipher_block)

        # initial (not actual) round
        state_trans = bytes(makeNDArrayFrom(state, 4, 4).transpose().flatten())
        key_trans = bytes(makeNDArrayFrom(
            bstr_key, 4, 4).transpose().flatten())

        bstr_state = aesAddRoundkey(state_trans, key_trans)

        for r in range(0, rounds[num_bits]):
            if r == rounds[num_bits] - 1:
                # last round no Mix Columns
                bstr_state = aesSubBytes(bstr_state)
                bstr_state = aesShiftRows(bstr_state)
                key_trans = bytes(makeNDArrayFrom(
                    round_keys[r], 4, 4).transpose().flatten())
                bstr_state = aesAddRoundkey(bstr_state, key_trans)
            else:
                bstr_state = aesSubBytes(bstr_state)
                bstr_state = aesShiftRows(bstr_state)
                bstr_state = aesMixColumns(bstr_state)
                key_trans = bytes(makeNDArrayFrom(
                    round_keys[r], 4, 4).transpose().flatten())
                bstr_state = aesAddRoundkey(bstr_state, key_trans)
        state_result = bytes(makeNDArrayFrom(
            bstr_state, 4, 4).transpose().flatten())
        preceding_cipher_block = state_result

        cipher += state_result
    return cipher


def aesKeyExpansionCore(bstr_word, rcon_round):
    """
    used in aesKeyExpansion
    """
    word = bytes(rotateList(list(bstr_word), 1, 'l'))
    word = aesSubBytes(word)
    word = bytes([word[0] ^ rcon[rcon_round]]) + word[1:]
    return word


def aesKeyExpansion(bstr_key):
    """
    Returns the roundkeys a list of byte strings
    TODO: make length parameters variable
    """
    if len(bstr_key) != 16 and len(bstr_key) != 24 and len(bstr_key) != 32:
        print("Invalid key length!")
        exit(1)
    numbits = len(bstr_key) * 8
    rounds = {128: 10, 192: 12, 256: 14}
    round_keys = []

    # transposed since we are operating on the columns
    prevkey = makeNDArrayFrom(bstr_key, 4, 4)

    newkey = b''
    offset = 0
    rcon_round = 1
    while len(round_keys) < rounds[numbits]:
        # on every first 4 byte group of the 16 byte blocks perform rotate,
        # subbytes
        if offset == 0:
            word = bytes(prevkey[3])
            word = aesKeyExpansionCore(word, rcon_round)
            rcon_round += 1
        else:
            word = newkey[offset - 4:offset]
        word_from_prevkey = bytes(prevkey.flatten())[offset:offset + 4]
        word = xorBytestrings(word, word_from_prevkey)
        newkey += word
        offset += 4
        if offset == 16:
            offset = 0
            prevkey = makeNDArrayFrom(newkey, 4, 4)
            # transpose back and convert to byte string before appending to
            # result list
            newkey = bytes(makeNDArrayFrom(newkey, 4, 4).flatten())
            round_keys.append(newkey)
            newkey = b''
    return round_keys


def aesAddRoundkey(ndarray_state, ndarray_key):
    return xorBytestrings(ndarray_state, ndarray_key)


def aesSubBytes(bstr_state):
    return bytes([sbox[b] for b in bstr_state])


def aesRCon(bstr_state):
    substitue = b''
    for b in bstr_state:
        substitue += rcon[b]
    return substitue


def aesShiftRows(bstr_state):
    arr = makeNDArrayFrom(bstr_state, 4, 4)
    for i in range(len(arr)):
        arr[i] = rotateList(arr[i], i, 'l')
    return bytes(arr.flatten())


def aesMixColumns(bstr_state):
    """
    TODO: make variable
    """

    # go for columns
    state = makeNDArrayFrom(bstr_state, 4, 4).transpose()
    mds_matrix = np.array(mds_matrix_flat)
    mds_matrix = mds_matrix.reshape(4, 4)
    result = np.zeros(shape=(4, 4), dtype=np.int8)
    # number of columns
    # iterate over columns
    for i in range(len(state)):
        # iterate over bytes
        result_byte = 0
        for bnum in range(len(state[i])):
            result[i][bnum] = mdsLookup(state[i][0], mds_matrix[bnum][0])
            result[i][bnum] ^= mdsLookup(state[i][1], mds_matrix[bnum][1])
            result[i][bnum] ^= mdsLookup(state[i][2], mds_matrix[bnum][2])
            result[i][bnum] ^= mdsLookup(state[i][3], mds_matrix[bnum][3])
    result = bytes(result.transpose().flatten())
    return result

    # gmul variant
    """
    state = makeNDArrayFrom(bstr_state, 4, 4).transpose()
    mds_matrix = np.array(mds_matrix_flat)
    mds_matrix = mds_matrix.reshape(4, 4)
    result_array = np.zeros(shape=(4, 4), dtype=np.uint8)
    for c in range(len(state)):
        for b in range(len(state[c])):
            result_array[c][b] = gmul(state[c][0], mds_matrix[b][0])
            result_array[c][b] ^= gmul(state[c][1], mds_matrix[b][1])
            result_array[c][b] ^= gmul(state[c][2], mds_matrix[b][2])
            result_array[c][b] ^= gmul(state[c][3], mds_matrix[b][3])

    result = bytes(result_array.transpose().flatten())
    return(result)
    """


def aesDecrypt(bstr_cipher, bstr_key, num_bits, mode='ecb', bstr_IV=None):
    if len(bstr_key) != 16:
        # no key derivation yet
        print("Unsuitable key length!")
        exit(1)

    state_iter = stateGenerator(bstr_cipher, 16)
    rounds = {128: 10, 192: 12, 256: 14}
    round_keys = aesKeyExpansion(bstr_key)
    cipher = b''
    prev_cipherstate = bstr_IV
    for state in state_iter:
        # initial round
        bstr_state = bytes(makeNDArrayFrom(state, 4, 4).transpose().flatten())
        key_trans = bytes(makeNDArrayFrom(
            bstr_key, 4, 4).transpose().flatten())
        for r in reversed(range(0, rounds[num_bits])):
            if r == rounds[num_bits] - 1:
                # first round no inverse MixColumns
                key_trans = bytes(makeNDArrayFrom(
                    round_keys[r], 4, 4).transpose().flatten())
                bstr_state = aesAddRoundkey(bstr_state, key_trans)
                bstr_state = aesInvShiftRows(bstr_state)
                bstr_state = aesInvSubBytes(bstr_state)
            else:
                key_trans = bytes(makeNDArrayFrom(
                    round_keys[r], 4, 4).transpose().flatten())
                bstr_state = aesAddRoundkey(bstr_state, key_trans)
                bstr_state = aesInvMixColumns(bstr_state)
                bstr_state = aesInvShiftRows(bstr_state)
                bstr_state = aesInvSubBytes(bstr_state)
        key_trans = bytes(makeNDArrayFrom(
            bstr_key, 4, 4).transpose().flatten())
        bstr_state = aesAddRoundkey(bstr_state, key_trans)
        bstr_state = bytes(makeNDArrayFrom(
            bstr_state, 4, 4).transpose().flatten())
        if mode == 'cbc':
            bstr_state = xorBytestrings(bstr_state, prev_cipherstate)
            prev_cipherstate = state
        cipher += bstr_state
        #cipher = misc.unpadPKCS7(cipher, 16)
    return cipher


def aesInvSubBytes(bstr_state):
    return bytes([inv_sbox[b] for b in bstr_state])


def aesInvShiftRows(bstr_state):
    arr = makeNDArrayFrom(bstr_state, 4, 4)
    for i in range(len(arr)):
        arr[i] = rotateList(arr[i], i, 'r')
    return bytes(arr.flatten())


def aesInvMixColumns(bstr_state):
    """
    TODO: make variable
    """
    # go for columns
    state = makeNDArrayFrom(bstr_state, 4, 4).transpose()
    inv_mds_matrix = np.array(inv_mds_matrix_flat)
    inv_mds_matrix = inv_mds_matrix.reshape(4, 4)
    result_array = np.zeros(shape=(4, 4), dtype=np.uint8)
    for c in range(len(state)):
        for b in range(len(state[c])):
            result_array[c][b] = gmul(state[c][0], inv_mds_matrix[b][0])
            result_array[c][b] ^= gmul(state[c][1], inv_mds_matrix[b][1])
            result_array[c][b] ^= gmul(state[c][2], inv_mds_matrix[b][2])
            result_array[c][b] ^= gmul(state[c][3], inv_mds_matrix[b][3])

    result = bytes(result_array.transpose().flatten())
    return result


if __name__ == '__main__':
    np.set_printoptions(formatter={'int': hex})
    #cipher = aesEncrypt(bytes("ABCDEFGHIJKLMNOP", "ascii"), b'YELLOW SUBMARINE', 128)

    # aesMixColumns(b'\x2b\x28\xab\x09\x7e\xae\xf7\xcf\x15\xd2\x15\x4f\x16\xa6\x88\x3c')
    # 328831e0435a3137f6309807a88da234
    # 2b28ab097eaef7cf15d2154f16a6883c
    #cipher = aesEncrypt(b'\x32\x88\x31\xe0\x43\x5a\x31\x37\xf6\x30\x98\x07\xa8\x8d\xa2\x34', b'\x2b\x28\xab\x09\x7e\xae\xf7\xcf\x15\xd2\x15\x4f\x16\xa6\x88\x3c', 128)

    #k = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    #d = bytes.fromhex('3243f6a8885a308d313198a2e0370734')
    #cipher = aesEncrypt(d, k, 128)


def aesCTR(bstr, bstr_key, num_bits, bstr_nonce):
    """ encryption and decryption is the same in this mode
    """
    state_iter = stateGenerator(bstr, 16, modis0=False)
    xored = b''
    counter = 0
    for state in state_iter:
        bstr_nonce_ctr = bstr_nonce + struct.pack('<q', counter)
        secondary_key = aesEncrypt(bstr_nonce_ctr, bstr_key, num_bits)
        # this will be shorter than state len if the last state is remainder:
        secondary_key = secondary_key[:len(state)]
        xored += xorBytestrings(state, secondary_key)
        counter += 1

    return xored

def aesCTREdit(bstr_cipher: bytes, bstr_key: bytes, offset: int, bstr_newtext) -> bytes:
    pass