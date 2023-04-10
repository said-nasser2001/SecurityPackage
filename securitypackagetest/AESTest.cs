using System;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityLibrary.AES;

namespace SecurityPackageTest
{

    [TestClass]
    public class AESTest
    {
        string mainPlain = "0x3243F6A8885A308D313198A2e0370734";
        string mainCipher = "0x3925841D02DC09FBDC118597196A0B32";
        string mainKey = "0x2B7E151628AED2A6ABF7158809CF4F3C";

        string mainPlain2 = "0x00000000000000000000000000000001";
        string mainCipher2 = "0x58e2fccefa7e3061367f1d57a4e7455a";
        string mainKey2 = "0x00000000000000000000000000000000";

        string mainPlain3 = "0x00112233445566778899aabbccddeeff";
        string mainCipher3 = "0x69c4e0d86a7b0430d8cdb78070b4c55a";
        string mainKey3 = "0x000102030405060708090a0b0c0d0e0f";

        string newPlain = "0x54776F204F6E65204E696E652054776F";
        string newCipher = "0x29C3505F571420F6402299B31A02D73A";
        string newKey = "0x5468617473206D79204B756E67204675";

        [TestMethod]
        public void AESTestEnc1()
        {
            AES algorithm = new AES();
            string cipher = algorithm.Encrypt(mainPlain, mainKey);
            Assert.IsTrue(cipher.Equals(mainCipher, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void AESTestDec1()
        {
            AES algorithm = new AES();
            string plain = algorithm.Decrypt(mainCipher, mainKey);
            Assert.IsTrue(plain.Equals(mainPlain, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void AESTestEnc2()
        {
            AES algorithm = new AES();
            string cipher = algorithm.Encrypt(mainPlain2, mainKey2);
            Assert.IsTrue(cipher.Equals(mainCipher2, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void AESTestDec2()
        {
            AES algorithm = new AES();
            string plain = algorithm.Decrypt(mainCipher2, mainKey2);
            Assert.IsTrue(plain.Equals(mainPlain2, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void AESTestEnc3()
        {
            AES algorithm = new AES();
            string cipher = algorithm.Encrypt(mainPlain3, mainKey3);
            Assert.IsTrue(cipher.Equals(mainCipher3, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void AESTestDec3()
        {
            AES algorithm = new AES();
            string plain = algorithm.Decrypt(mainCipher3, mainKey3);
            Assert.IsTrue(plain.Equals(mainPlain3, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void AESTestNewEnc()
        {
            AES algorithm = new AES();
            string cipher = algorithm.Encrypt(newPlain, newKey);
            Assert.IsTrue(cipher.Equals(newCipher, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void AESTestNewDec()
        {
            AES algorithm = new AES();
            string plain = algorithm.Decrypt(newCipher, newKey);
            Assert.IsTrue(plain.Equals(newPlain, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void TestApplyXOR()
        {
            AES algorithm = new AES();

            string s1 = "23a5c8d0";
            string s2 = "983e3509";

            // Expected output
            string expected = "bb9bfdd9";

            // Act
            var result = algorithm.applyXOR(s1, s2);

            // Assert
            Assert.IsTrue(result.Equals(expected, StringComparison.InvariantCultureIgnoreCase));
        }


        [TestMethod]
        public void TestAddRoundKey()
        {
            // Arrange
            string[,] state = new string[4, 4]
            {
                {"04", "e0", "48", "28"},
                {"66", "cb", "f8", "06"},
                {"81", "19", "d3", "26"},
                {"e5", "9a", "7a", "4c"}
            };

            string[,] roundKey = new string[4, 4]
            {
                {"a0", "88", "23", "2a"},
                {"fa", "54", "a3", "6c"},
                {"fe", "2c", "39", "76"},
                {"17", "b1", "39", "05"}
            };

            string[,] expectedNewState = new string[4, 4]
            {
                {"a4", "68", "6b", "02"},
                {"9c", "9f", "5b", "6a"},
                {"7f", "35", "ea", "50"},
                {"f2", "2b", "43", "49"}
            };

            AES algorithm = new AES();

            // Act
            string[,] actualNewState = algorithm.addRoundKey(state, roundKey);

            // Assert
            CollectionAssert.AreEqual(expectedNewState, actualNewState);
        }



        [TestMethod]
        public void TestConvertToMatrix()
        {
            AES algorithm = new AES();
            string input = "5468617473206D79204B756E67204675";
            string[,] expectedOutput = new string[,] {
                        { "54", "68", "61", "74" },
                        { "73", "20", "6D", "79" },
                        { "20", "4B", "75", "6E" },
                        { "67", "20", "46", "75" }
            };

            string[,] output = algorithm.convertToMatrix(input);

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Assert.AreEqual(expectedOutput[i, j], output[i, j]);
                }
            }
        }


    }
}
