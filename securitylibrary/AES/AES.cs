using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        #region constants

        public string[] RC = new string[10] { "01000000", "02000000", "04000000", "08000000", "10000000", "20000000", "40000000", "80000000", "1b000000", "36000000" };

        public string[,] SBox = new string[16, 16] { { "63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76" },
                                                     { "CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0" },
                                                     { "B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15" },
                                                     { "04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75" },
                                                     { "09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84" },
                                                     { "53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF" },
                                                     { "D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8" },
                                                     { "51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2" },
                                                     { "CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73" },
                                                     { "60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB" },
                                                     { "E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79" },
                                                     { "E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08" },
                                                     { "BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A" },
                                                     { "70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E" },
                                                     { "E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF" },
                                                     { "8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16" } };

        public string[,] InvSBox = new string[16, 16] { {"63",  "7c",  "77",  "7b",  "f2",  "6b",  "6f",  "c5",  "30",  "01",  "67",  "2b",  "fe",  "d7",  "ab"  ,"76"},
                                                        {"ca",  "82",  "c9",  "7d",  "fa",  "59",  "47",  "f0",  "ad",  "d4",  "a2",  "af",  "9c",  "a4",  "72"  ,"c0"},
                                                        {"b7",  "fd",  "93",  "26",  "36",  "3f",  "f7",  "cc",  "34",  "a5",  "e5",  "f1",  "71",  "d8",  "31"  ,"15"},
                                                        {"04",  "c7",  "23",  "c3",  "18",  "96",  "05",  "9a",  "07",  "12",  "80",  "e2",  "eb",  "27",  "b2"  ,"75"},
                                                        {"09",  "83",  "2c",  "1a",  "1b",  "6e",  "5a",  "a0",  "52",  "3b",  "d6",  "b3",  "29",  "e3",  "2f"  ,"84"},
                                                        {"53",  "d1",  "00",  "ed",  "20",  "fc",  "b1",  "5b",  "6a",  "cb",  "be",  "39",  "4a",  "4c",  "58"  ,"cf"},
                                                        {"d0",  "ef",  "aa",  "fb",  "43",  "4d",  "33",  "85",  "45",  "f9",  "02",  "7f",  "50",  "3c",  "9f"  ,"a8"},
                                                        {"51",  "a3",  "40",  "8f",  "92",  "9d",  "38",  "f5",  "bc",  "b6",  "da",  "21",  "10",  "ff",  "f3"  ,"d2"},
                                                        {"cd",  "0c",  "13",  "ec",  "5f",  "97",  "44",  "17",  "c4",  "a7",  "7e",  "3d",  "64",  "5d",  "19"  ,"73"},
                                                        {"60",  "81",  "4f",  "dc",  "22",  "2a",  "90",  "88",  "46",  "ee",  "b8",  "14",  "de",  "5e",  "0b"  ,"db"},
                                                        {"e0",  "32",  "3a",  "0a",  "49",  "06",  "24",  "5c",  "c2",  "d3",  "ac",  "62",  "91",  "95",  "e4"  ,"79"},
                                                        {"e7",  "c8",  "37",  "6d",  "8d",  "d5",  "4e",  "a9",  "6c",  "56",  "f4",  "ea",  "65",  "7a",  "ae"  ,"08"},
                                                        {"ba",  "78",  "25",  "2e",  "1c",  "a6",  "b4",  "c6",  "e8",  "dd",  "74",  "1f",  "4b",  "bd",  "8b"  ,"8a"},
                                                        {"70",  "3e",  "b5",  "66",  "48",  "03",  "f6",  "0e",  "61",  "35",  "57",  "b9",  "86",  "c1",  "1d"  ,"9e"},
                                                        {"e1",  "f8",  "98",  "11",  "69",  "d9",  "8e",  "94",  "9b",  "1e",  "87",  "e9",  "ce",  "55",  "28"  ,"df"},
                                                        {"8c",  "a1",  "89",  "0d",  "bf",  "e6",  "42",  "68",  "41",  "99",  "2d",  "0f",  "b0",  "54",  "bb",  "16" } };


        public int[,] invMixColumnsMat = new int[4,4]  { { 0x0E, 0x0B, 0x0D, 0x09 },
                                                         { 0x09, 0x0E, 0x0B, 0x0D },
                                                         { 0x0D, 0x09, 0x0E, 0x0B },
                                                         { 0x0B, 0x0D, 0x09, 0x0E } };
        
        int[] MultiplyByTwoLookUpTable = {0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
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
                                            0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5, 0xeb, 0xe9, 0xef, 0xed, 0xe3, 0xe1, 0xe7, 0xe5 };

        int[] MultiplyByThreeLookUpTable = {0x00,0x03,0x06,0x05,0x0c,0x0f,0x0a,0x09,0x18,0x1b,0x1e,0x1d,0x14,0x17,0x12,0x11,
                                            0x30,0x33,0x36,0x35,0x3c,0x3f,0x3a,0x39,0x28,0x2b,0x2e,0x2d,0x24,0x27,0x22,0x21,
                                            0x60,0x63,0x66,0x65,0x6c,0x6f,0x6a,0x69,0x78,0x7b,0x7e,0x7d,0x74,0x77,0x72,0x71,
                                            0x50,0x53,0x56,0x55,0x5c,0x5f,0x5a,0x59,0x48,0x4b,0x4e,0x4d,0x44,0x47,0x42,0x41,
                                            0xc0,0xc3,0xc6,0xc5,0xcc,0xcf,0xca,0xc9,0xd8,0xdb,0xde,0xdd,0xd4,0xd7,0xd2,0xd1,
                                            0xf0,0xf3,0xf6,0xf5,0xfc,0xff,0xfa,0xf9,0xe8,0xeb,0xee,0xed,0xe4,0xe7,0xe2,0xe1,
                                            0xa0,0xa3,0xa6,0xa5,0xac,0xaf,0xaa,0xa9,0xb8,0xbb,0xbe,0xbd,0xb4,0xb7,0xb2,0xb1,
                                            0x90,0x93,0x96,0x95,0x9c,0x9f,0x9a,0x99,0x88,0x8b,0x8e,0x8d,0x84,0x87,0x82,0x81,
                                            0x9b,0x98,0x9d,0x9e,0x97,0x94,0x91,0x92,0x83,0x80,0x85,0x86,0x8f,0x8c,0x89,0x8a,
                                            0xab,0xa8,0xad,0xae,0xa7,0xa4,0xa1,0xa2,0xb3,0xb0,0xb5,0xb6,0xbf,0xbc,0xb9,0xba,
                                            0xfb,0xf8,0xfd,0xfe,0xf7,0xf4,0xf1,0xf2,0xe3,0xe0,0xe5,0xe6,0xef,0xec,0xe9,0xea,
                                            0xcb,0xc8,0xcd,0xce,0xc7,0xc4,0xc1,0xc2,0xd3,0xd0,0xd5,0xd6,0xdf,0xdc,0xd9,0xda,
                                            0x5b,0x58,0x5d,0x5e,0x57,0x54,0x51,0x52,0x43,0x40,0x45,0x46,0x4f,0x4c,0x49,0x4a,
                                            0x6b,0x68,0x6d,0x6e,0x67,0x64,0x61,0x62,0x73,0x70,0x75,0x76,0x7f,0x7c,0x79,0x7a,
                                            0x3b,0x38,0x3d,0x3e,0x37,0x34,0x31,0x32,0x23,0x20,0x25,0x26,0x2f,0x2c,0x29,0x2a,
                                            0x0b,0x08,0x0d,0x0e,0x07,0x04,0x01,0x02,0x13,0x10,0x15,0x16,0x1f,0x1c,0x19,0x1a};

        int[] MultiplyByNineLookUpTable = {0x00,0x09,0x12,0x1b,0x24,0x2d,0x36,0x3f,0x48,0x41,0x5a,0x53,0x6c,0x65,0x7e,0x77,
                                           0x90,0x99,0x82,0x8b,0xb4,0xbd,0xa6,0xaf,0xd8,0xd1,0xca,0xc3,0xfc,0xf5,0xee,0xe7,
                                           0x3b,0x32,0x29,0x20,0x1f,0x16,0x0d,0x04,0x73,0x7a,0x61,0x68,0x57,0x5e,0x45,0x4c,
                                           0xab,0xa2,0xb9,0xb0,0x8f,0x86,0x9d,0x94,0xe3,0xea,0xf1,0xf8,0xc7,0xce,0xd5,0xdc,
                                           0x76,0x7f,0x64,0x6d,0x52,0x5b,0x40,0x49,0x3e,0x37,0x2c,0x25,0x1a,0x13,0x08,0x01,
                                           0xe6,0xef,0xf4,0xfd,0xc2,0xcb,0xd0,0xd9,0xae,0xa7,0xbc,0xb5,0x8a,0x83,0x98,0x91,
                                           0x4d,0x44,0x5f,0x56,0x69,0x60,0x7b,0x72,0x05,0x0c,0x17,0x1e,0x21,0x28,0x33,0x3a,
                                           0xdd,0xd4,0xcf,0xc6,0xf9,0xf0,0xeb,0xe2,0x95,0x9c,0x87,0x8e,0xb1,0xb8,0xa3,0xaa,
                                           0xec,0xe5,0xfe,0xf7,0xc8,0xc1,0xda,0xd3,0xa4,0xad,0xb6,0xbf,0x80,0x89,0x92,0x9b,
                                           0x7c,0x75,0x6e,0x67,0x58,0x51,0x4a,0x43,0x34,0x3d,0x26,0x2f,0x10,0x19,0x02,0x0b,
                                           0xd7,0xde,0xc5,0xcc,0xf3,0xfa,0xe1,0xe8,0x9f,0x96,0x8d,0x84,0xbb,0xb2,0xa9,0xa0,
                                           0x47,0x4e,0x55,0x5c,0x63,0x6a,0x71,0x78,0x0f,0x06,0x1d,0x14,0x2b,0x22,0x39,0x30,
                                           0x9a,0x93,0x88,0x81,0xbe,0xb7,0xac,0xa5,0xd2,0xdb,0xc0,0xc9,0xf6,0xff,0xe4,0xed,
                                           0x0a,0x03,0x18,0x11,0x2e,0x27,0x3c,0x35,0x42,0x4b,0x50,0x59,0x66,0x6f,0x74,0x7d,
                                           0xa1,0xa8,0xb3,0xba,0x85,0x8c,0x97,0x9e,0xe9,0xe0,0xfb,0xf2,0xcd,0xc4,0xdf,0xd6,
                                           0x31,0x38,0x23,0x2a,0x15,0x1c,0x07,0x0e,0x79,0x70,0x6b,0x62,0x5d,0x54,0x4f,0x46};

        int[] MultiplyByFourteenLookUpTable ={0x00,0x0e,0x1c,0x12,0x38,0x36,0x24,0x2a,0x70,0x7e,0x6c,0x62,0x48,0x46,0x54,0x5a,
                                              0xe0,0xee,0xfc,0xf2,0xd8,0xd6,0xc4,0xca,0x90,0x9e,0x8c,0x82,0xa8,0xa6,0xb4,0xba,
                                              0xdb,0xd5,0xc7,0xc9,0xe3,0xed,0xff,0xf1,0xab,0xa5,0xb7,0xb9,0x93,0x9d,0x8f,0x81,
                                              0x3b,0x35,0x27,0x29,0x03,0x0d,0x1f,0x11,0x4b,0x45,0x57,0x59,0x73,0x7d,0x6f,0x61,
                                              0xad,0xa3,0xb1,0xbf,0x95,0x9b,0x89,0x87,0xdd,0xd3,0xc1,0xcf,0xe5,0xeb,0xf9,0xf7,
                                              0x4d,0x43,0x51,0x5f,0x75,0x7b,0x69,0x67,0x3d,0x33,0x21,0x2f,0x05,0x0b,0x19,0x17,
                                              0x76,0x78,0x6a,0x64,0x4e,0x40,0x52,0x5c,0x06,0x08,0x1a,0x14,0x3e,0x30,0x22,0x2c,
                                              0x96,0x98,0x8a,0x84,0xae,0xa0,0xb2,0xbc,0xe6,0xe8,0xfa,0xf4,0xde,0xd0,0xc2,0xcc,
                                              0x41,0x4f,0x5d,0x53,0x79,0x77,0x65,0x6b,0x31,0x3f,0x2d,0x23,0x09,0x07,0x15,0x1b,
                                              0xa1,0xaf,0xbd,0xb3,0x99,0x97,0x85,0x8b,0xd1,0xdf,0xcd,0xc3,0xe9,0xe7,0xf5,0xfb,
                                              0x9a,0x94,0x86,0x88,0xa2,0xac,0xbe,0xb0,0xea,0xe4,0xf6,0xf8,0xd2,0xdc,0xce,0xc0,
                                              0x7a,0x74,0x66,0x68,0x42,0x4c,0x5e,0x50,0x0a,0x04,0x16,0x18,0x32,0x3c,0x2e,0x20,
                                              0xec,0xe2,0xf0,0xfe,0xd4,0xda,0xc8,0xc6,0x9c,0x92,0x80,0x8e,0xa4,0xaa,0xb8,0xb6,
                                              0x0c,0x02,0x10,0x1e,0x34,0x3a,0x28,0x26,0x7c,0x72,0x60,0x6e,0x44,0x4a,0x58,0x56,
                                              0x37,0x39,0x2b,0x25,0x0f,0x01,0x13,0x1d,0x47,0x49,0x5b,0x55,0x7f,0x71,0x63,0x6d,
                                              0xd7,0xd9,0xcb,0xc5,0xef,0xe1,0xf3,0xfd,0xa7,0xa9,0xbb,0xb5,0x9f,0x91,0x83,0x8d};




        int[,] mixColumnsMat = new int[4, 4] { { 0x02, 0x03,0x01, 0x01 },
                                               { 0x01, 0x02,  0x03, 0x01 },
                                               { 0x01, 0x01, 0x02,  0x03 },
                                               {  0x03, 0x01, 0x01, 0x02 } };


        int[] MultiplyByElevenLookUpTable = {0x00,0x0b,0x16,0x1d,0x2c,0x27,0x3a,0x31,0x58,0x53,0x4e,0x45,0x74,0x7f,0x62,0x69,
                                             0xb0,0xbb,0xa6,0xad,0x9c,0x97,0x8a,0x81,0xe8,0xe3,0xfe,0xf5,0xc4,0xcf,0xd2,0xd9,
                                             0x7b,0x70,0x6d,0x66,0x57,0x5c,0x41,0x4a,0x23,0x28,0x35,0x3e,0x0f,0x04,0x19,0x12,
                                             0xcb,0xc0,0xdd,0xd6,0xe7,0xec,0xf1,0xfa,0x93,0x98,0x85,0x8e,0xbf,0xb4,0xa9,0xa2,
                                             0xf6,0xfd,0xe0,0xeb,0xda,0xd1,0xcc,0xc7,0xae,0xa5,0xb8,0xb3,0x82,0x89,0x94,0x9f,
                                             0x46,0x4d,0x50,0x5b,0x6a,0x61,0x7c,0x77,0x1e,0x15,0x08,0x03,0x32,0x39,0x24,0x2f,
                                             0x8d,0x86,0x9b,0x90,0xa1,0xaa,0xb7,0xbc,0xd5,0xde,0xc3,0xc8,0xf9,0xf2,0xef,0xe4,
                                             0x3d,0x36,0x2b,0x20,0x11,0x1a,0x07,0x0c,0x65,0x6e,0x73,0x78,0x49,0x42,0x5f,0x54,
                                             0xf7,0xfc,0xe1,0xea,0xdb,0xd0,0xcd,0xc6,0xaf,0xa4,0xb9,0xb2,0x83,0x88,0x95,0x9e,
                                             0x47,0x4c,0x51,0x5a,0x6b,0x60,0x7d,0x76,0x1f,0x14,0x09,0x02,0x33,0x38,0x25,0x2e,
                                             0x8c,0x87,0x9a,0x91,0xa0,0xab,0xb6,0xbd,0xd4,0xdf,0xc2,0xc9,0xf8,0xf3,0xee,0xe5,
                                             0x3c,0x37,0x2a,0x21,0x10,0x1b,0x06,0x0d,0x64,0x6f,0x72,0x79,0x48,0x43,0x5e,0x55,
                                             0x01,0x0a,0x17,0x1c,0x2d,0x26,0x3b,0x30,0x59,0x52,0x4f,0x44,0x75,0x7e,0x63,0x68,
                                             0xb1,0xba,0xa7,0xac,0x9d,0x96,0x8b,0x80,0xe9,0xe2,0xff,0xf4,0xc5,0xce,0xd3,0xd8,
                                             0x7a,0x71,0x6c,0x67,0x56,0x5d,0x40,0x4b,0x22,0x29,0x34,0x3f,0x0e,0x05,0x18,0x13,
                                             0xca,0xc1,0xdc,0xd7,0xe6,0xed,0xf0,0xfb,0x92,0x99,0x84,0x8f,0xbe,0xb5,0xa8,0xa3};

        int[] MultiplyByThirteenLookUpTable = {0x00,0x0d,0x1a,0x17,0x34,0x39,0x2e,0x23,0x68,0x65,0x72,0x7f,0x5c,0x51,0x46,0x4b,
                                               0xd0,0xdd,0xca,0xc7,0xe4,0xe9,0xfe,0xf3,0xb8,0xb5,0xa2,0xaf,0x8c,0x81,0x96,0x9b,
                                               0xbb,0xb6,0xa1,0xac,0x8f,0x82,0x95,0x98,0xd3,0xde,0xc9,0xc4,0xe7,0xea,0xfd,0xf0,
                                               0x6b,0x66,0x71,0x7c,0x5f,0x52,0x45,0x48,0x03,0x0e,0x19,0x14,0x37,0x3a,0x2d,0x20,
                                               0x6d,0x60,0x77,0x7a,0x59,0x54,0x43,0x4e,0x05,0x08,0x1f,0x12,0x31,0x3c,0x2b,0x26,
                                               0xbd,0xb0,0xa7,0xaa,0x89,0x84,0x93,0x9e,0xd5,0xd8,0xcf,0xc2,0xe1,0xec,0xfb,0xf6,
                                               0xd6,0xdb,0xcc,0xc1,0xe2,0xef,0xf8,0xf5,0xbe,0xb3,0xa4,0xa9,0x8a,0x87,0x90,0x9d,
                                               0x06,0x0b,0x1c,0x11,0x32,0x3f,0x28,0x25,0x6e,0x63,0x74,0x79,0x5a,0x57,0x40,0x4d,
                                               0xda,0xd7,0xc0,0xcd,0xee,0xe3,0xf4,0xf9,0xb2,0xbf,0xa8,0xa5,0x86,0x8b,0x9c,0x91,
                                               0x0a,0x07,0x10,0x1d,0x3e,0x33,0x24,0x29,0x62,0x6f,0x78,0x75,0x56,0x5b,0x4c,0x41,
                                               0x61,0x6c,0x7b,0x76,0x55,0x58,0x4f,0x42,0x09,0x04,0x13,0x1e,0x3d,0x30,0x27,0x2a,
                                               0xb1,0xbc,0xab,0xa6,0x85,0x88,0x9f,0x92,0xd9,0xd4,0xc3,0xce,0xed,0xe0,0xf7,0xfa,
                                               0xb7,0xba,0xad,0xa0,0x83,0x8e,0x99,0x94,0xdf,0xd2,0xc5,0xc8,0xeb,0xe6,0xf1,0xfc,
                                               0x67,0x6a,0x7d,0x70,0x53,0x5e,0x49,0x44,0x0f,0x02,0x15,0x18,0x3b,0x36,0x21,0x2c,
                                               0x0c,0x01,0x16,0x1b,0x38,0x35,0x22,0x2f,0x64,0x69,0x7e,0x73,0x50,0x5d,0x4a,0x47,
                                               0xdc,0xd1,0xc6,0xcb,0xe8,0xe5,0xf2,0xff,0xb4,0xb9,0xae,0xa3,0x80,0x8d,0x9a,0x97};

        #endregion

        List<string[,]> Keys;

        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public override string Encrypt(string plainText, string key)
        {
            Keys = generateRoundKeys(key);

            // Initial Round
            string[,] stateMatrix = convertToMatrix(plainText);
            string[,] KeyMatrix = convertToMatrix(key);

            stateMatrix = addRoundKey(stateMatrix, KeyMatrix);

            int NumberOfRounds = 10;

            for (int round = 1; round <= NumberOfRounds; round++)
            {
                stateMatrix = AESRound(stateMatrix, Keys[round], round == NumberOfRounds);
            }

            string Output = convertToString(stateMatrix);
            return Output;
        }

        private string[,] AESRound(string[,] State, string[,] RoundKey, bool final)
        {
            State = subBytes(State);
            State = shiftRows(State);

            if (!final)
                State = mixColumns(State);

            string[,] Output = addRoundKey(State, RoundKey);

            return Output;
        }

        private string[,] subBytes(string[,] state)
        {
            int rows_length = state.GetLength(0), cols_length = state.GetLength(1);
            string[,] resultMatrix = new string[rows_length, cols_length];
            string temp = "";
            int sBoxRowIndex, sBoxColIndex;
            string hexNumbers = "0123456789abcdef";


            for (int row = 0; row < rows_length; row++)
            {
                for(int col = 0; col < cols_length; col++)
                {
                    temp = state[row, col];
                    temp = temp.ToLower();
                    sBoxRowIndex = hexNumbers.IndexOf(temp[0]);
                    sBoxColIndex = hexNumbers.IndexOf(temp[1]);
                    resultMatrix[row, col] = SBox[sBoxRowIndex, sBoxColIndex];
                }
            }


            return resultMatrix;
        }

        public string subBytes(string word)
        {
            word = word.ToLower();
            string temp = "";
            int sBoxRowIndex, sBoxColIndex;
            string hexNumbers = "0123456789abcdef";
            string newWord = "";

            for (int row = 0; row < 4; row++)
            {
                temp = word.Substring(row * 2, 2);
                sBoxRowIndex = hexNumbers.IndexOf(temp[0]);
                sBoxColIndex = hexNumbers.IndexOf(temp[1]);
                newWord += SBox[sBoxRowIndex, sBoxColIndex];
            }
            return newWord;
        }

        private string[,] shiftRows(string[,] state)
        {
            string[,] resultMatrix = new string[4,4];
            int rotateBy;

            for (int row = 0; row < 4; row++)
            {
                rotateBy = row;

               for (int col = 0; col < 4; col++)
               {
                 resultMatrix[row, col] = state[row, (col + rotateBy) % 4];
               }    
                
            }


            return resultMatrix;
        }

        public string[,] mixColumns(string[,] state)
        {
            string[,] res = new string[4, 4];
            for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < 4; col++)
                {
                    res[row, col] = VectorGaloisFieldMul(mixColumnsMat, row, state, col);
                }
            }
            return res;
        }

        private string VectorGaloisFieldMul(int[,] data1, int targetRow, string[,] state, int targetCol)
        {

            int sum = 0;
            int res = 0;
            for (int i = 0; i < 4; i++)
            {
                switch (data1[targetRow, i])
                {
                    case 0x01:
                        res = Convert.ToInt32(state[i, targetCol], 16);
                        break;
                    case 0x02:
                        res = MultiplyByTwoLookUpTable[Convert.ToInt32(state[i, targetCol], 16)];
                        break;
                    case 0x03:
                        res = MultiplyByThreeLookUpTable[Convert.ToInt32(state[i, targetCol], 16)];
                        break;
                }
                if (i == 0)
                    sum = res;
                else
                    sum ^= res;
            }

            return sum.ToString("X2");
        }

        // public because it won't show in tests otherwise.
        // TODO: make it private when work is done.

        public string[,] addRoundKey(string[,] state, string[,] roundKey)
        {
            string[,] newState = new string[4, 4];

            // perform XOR for every column

            for (int i = 0; i < 4; i++)
            {
                string stateColumn = "", keyColumn = "";

                for (int j = 0; j < 4; j++)
                {
                    stateColumn += state[j, i];
                    keyColumn += roundKey[j, i];
                }

                string newColumn = applyXOR(stateColumn, keyColumn);
                newColumn = newColumn.ToLower();


                for (int j = 0; j < 4; j++)
                {
                    newState[j, i] = newColumn.Substring(j * 2, 2);
                }
            }

            return newState;
        }

        // TODO: remove public and make it void after completion.
        public List<string[,]> generateRoundKeys(string masterKey)
        {

            string[,] masterKeyMatrix = convertToMatrix(masterKey);

            Keys = new List<string[,]>(11)
            {
                masterKeyMatrix
            };

            string[,] previousKey;
            int w = 4;

            // for every round key
            for (int i = 1; i <= 10; i++)
            {
                previousKey = Keys[i - 1];
                string currentKey = "";

                // for every word in current round key
                for (int j = 0; j < 4; j++, w++)
                {
                    string new_word = "";

                    // first word in round key
                    if (w % 4 == 0)
                    {
                        // Wi-1
                        string previous_word = "";
                        for (int k = 0; k < 4; k++) { previous_word += previousKey[k, 3]; }

                        // Wi-4
                        string previous_4_word = "";
                        for (int k = 0; k < 4; k++) { previous_4_word += previousKey[k, 0]; }

                        // Rcon(w)
                        string round_constant = RC[i - 1];

                        string subbytes_rotated_previous_word = subBytes(RotWord(previous_word));

                        // Subbyte(Rot(Wi-1)) + Wi4 + Rcon(w)
                        new_word = applyXOR(applyXOR(subbytes_rotated_previous_word, previous_4_word), round_constant);
                    }
                    else
                    {
                        // Wi-1
                        string previous_word = "";
                        for (int k = currentKey.Length - 8; k < currentKey.Length; k++) { previous_word += currentKey[k]; }

                        // Wi-4
                        string previous_4_word = "";
                        for (int k = 0; k < 4; k++) { previous_4_word += previousKey[k, j]; }

                        new_word = applyXOR(previous_word, previous_4_word);
                    }

                    currentKey += new_word;

                }
                string[,] currentKeyMatrix = convertToMatrix(currentKey);
                Keys.Add(currentKeyMatrix);
            }
            return Keys;
        }

        private string RotWord(string word)
        {
            return word.Substring(2) + word.Substring(0, 2);
        }

        private string[,] invSubBytes(string[,] state)
        {
            string[,] resultMatrix = new string[4, 4];
            string temp = "";
            int sBoxRowIndex, sBoxColIndex;
            string hexNumbers = "0123456789abcdef";

            for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < 4; col++)
                {
                    temp = state[row, col];
                    temp = temp.ToLower();
                    sBoxRowIndex = hexNumbers.IndexOf(temp[0]);
                    sBoxColIndex = hexNumbers.IndexOf(temp[1]);
                    resultMatrix[row, col] = InvSBox[sBoxRowIndex, sBoxColIndex];
                }
            }

            return resultMatrix;
        }

        private string[,] invShiftRows(string[,] state)
        {
            string[,] resultMatrix = new string[4, 4];
            int rotateBy;

            for (int row = 0; row < 4; row++)
            {
                rotateBy = row;

                for (int col = 0; col < 4; col++)
                {
                    resultMatrix[row, col] = state[row, (col + rotateBy) % 4];
                }

            }


            return resultMatrix;
        }

        private string[,] invMixColumns(string[,] state)
        {
            string[,] res = new string[4, 4];
            for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < 4; col++)
                {
                    res[row, col] = invVectorGaloisFieldMul(invMixColumnsMat, row, state, col);
                }
            }
            return res;
        }


        private string invVectorGaloisFieldMul(int[,] data1, int targetRow, string[,] state, int targetCol)
        {

            int sum = 0;
            int res = 0;
            for (int i = 0; i < 4; i++)
            {
                switch (data1[targetRow, i])
                {
                    case 0x01:
                        res = Convert.ToInt32(state[i, targetCol], 16);
                        break;

                    case 0x09:
                        res = MultiplyByNineLookUpTable[Convert.ToInt32(state[i, targetCol], 16)];
                        break;

                    case 0x0B:
                        res = MultiplyByElevenLookUpTable[Convert.ToInt32(state[i, targetCol], 16)];
                        break;

                    case 0x0D:
                        res = MultiplyByThirteenLookUpTable[Convert.ToInt32(state[i, targetCol], 16)];
                        break;

                    case 0x0E:
                        res = MultiplyByFourteenLookUpTable[Convert.ToInt32(state[i, targetCol], 16)];
                        break;


                }
                if (i == 0)
                    sum = res;
                else
                    sum ^= res;
            }

            return sum.ToString("X2");
        }


        /// <summary>
        /// returns XOR of 2 hex strings, strings should be exactly 32 bits, in the format "aabbccdd"
        /// </summary>
        /// <param name="s1"></param>
        /// <param name="s2"></param>
        /// <returns></returns>
        /// 

        // public because it won't show in tests otherwise.
        // TODO: make it private when work is done.
        public string applyXOR(string s1, string s2)
        {
            if (s1.Length != 8 || s2.Length != 8)
            {
                throw new ArgumentException("Strings should be exactly 8 characters long (32 bits).",
                    nameof(s1) + " " + s1 + " or " + nameof(s2) + " " + s2);
            }

            uint a = uint.Parse(s1, NumberStyles.HexNumber);
            uint b = uint.Parse(s2, NumberStyles.HexNumber);

            uint result = a ^ b;

            return result.ToString("X8");
        }

        public string[,] convertToMatrix(string text)
        {
            string[,] matrix = new string[4, 4];
            int row = 0, col = 0, startingIndex;

            if (text[0] == '0' && text[1] == 'x')
                startingIndex = 2;
            else
                startingIndex = 0;

            for (int char_no = startingIndex; char_no < text.Length; char_no+=2)
            {
                if(row == 4)
                {
                    row = 0;
                    col++;
                }

                if(col == 4)
                {
                    break;
                }

                if (char_no == text.Length - 1)
                {
                    matrix[row, col] = "" + text[char_no];
                }
                else
                {
                    matrix[row, col] = "" + text[char_no] + text[char_no + 1];
                }

                row++;
                    
            }

            if (matrix[3, 3].Length == 1)
            {
                matrix[3, 3] = "0" + text[text.Length - 1];
            }

            return matrix;
        }

        private string convertToString(string[,] matrix)
        {
            string text = "";

            for (int col = 0; col < 4; col++)
            {
                for (int row = 0; row < 4; row++)
                {
                    text += matrix[row, col];
                }
            }


            return "0x"+text;
        }

        
    }
}
