import unittest

from crypto_algos.attack.statistics import hammingDistance, bytesFrequency, getNgramsFromFile,\
    mapFreqBytes2FreqLang


class TestStatistics(unittest.TestCase):
    def testHammingDistance(self):
        dist = hammingDistance(b'AAB', b'AAC')
        self.assertEqual(dist, 1)

    def testBytesFrequency(self):
        d = bytesFrequency(b'AAAABBB', 1)
        #self.assertDictEqual(d, {b'A': 4, b'B': 3})
        self.assertEqual(d, (b'A', b'B'))
        d = bytesFrequency(b'AAAABBB', 2)
        #self.assertDictEqual(d, {b'AA': 2, b'BB': 1})
        self.assertEqual(d, (b'AA', b'BB'))

    def testGetNgramsFromFile(self):
        mono = getNgramsFromFile('english_monograms')
        self.assertEqual(mono[0:6], (b' ', b'E',b'T',b'A',b'O',b'I'))
        bi = getNgramsFromFile('english_bigrams')
        self.assertEqual(bi[0:5], (b'TH',b'HE',b'IN',b'ER',b'AN'))

    def testMapFreqBytes2FreqLang(self):
        from_text = (b'a', b'b', b'c')
        lang = (b'1', b'2', b'3')
        d = mapFreqBytes2FreqLang(from_text, lang)
        self.assertDictEqual(d, {b'a': b'1', b'b': b'2', b'c': b'3'})

if __name__ == '__main__':
    unittest.main()
