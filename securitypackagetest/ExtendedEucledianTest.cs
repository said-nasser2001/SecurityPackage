using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityLibrary.AES;

namespace SecurityPackageTest
{
    [TestClass]
    public class ExtendedEucledianTest
    {
        int b1 = 23;
        int m1 = 26;
        int ans1 = 17;

        int b2 = 550;
        int m2 = 1759;
        int ans2 = 355;


        [TestMethod]
        public void EuclidTest1()
        {
            ExtendedEuclid algorithm = new ExtendedEuclid();
            int output = algorithm.GetMultiplicativeInverse(b1, m1);
            Assert.IsTrue(ans1 == output);
        }

        [TestMethod]
        public void EuclidTest2()
        {
            ExtendedEuclid algorithm = new ExtendedEuclid();
            int output = algorithm.GetMultiplicativeInverse(b2, m2);
            Assert.IsTrue(ans2 == output);
        }

    }
}
