#include "cypher.hpp"
#include <iostream>

int main()
{
	byte* data = (byte*)"Test1337Test1337";
	byte key[32];
	byte iv[32];

	byte* enc_out = cypher::encdec(data, 17, key, iv, false);
	std::cout << "Encrypted: " << enc_out << std::endl;
	std::cout << "Key: " << key << std::endl;

	byte* dec_out = cypher::encdec(enc_out, 17, key, iv, true);
	std::cout << "Decrypted: " << dec_out << std::endl;
}